// Package logging provides structured-logging utilities for CSAR.
package logging

import (
	"context"
	"log/slog"
	"strings"

	"github.com/Ledatu/csar-core/secret"
)

// Secret is a type alias for secret.Secret from csar-core. This preserves
// backward compatibility: all existing code that uses logging.Secret,
// logging.NewSecret, etc. continues to compile without changes.
type Secret = secret.Secret

// NewSecret wraps a plaintext string in a Secret.
func NewSecret(plaintext string) Secret {
	return secret.NewSecret(plaintext)
}

// sensitiveKeys are attribute keys whose values should be redacted.
// Keys are compared case-insensitively.
var sensitiveKeys = map[string]struct{}{
	"authorization": {},
	"bearer":        {},
	"token":         {},
	"password":      {},
	"key":           {},
	"secret":        {},
	"api_key":       {},
	"api-key":       {},
	"iam_token":     {},
	"oauth_token":   {},
	"cookie":        {},
	"set-cookie":    {},
	"x-api-key":     {},
}

const redactedValue = "[REDACTED]"

// RedactingHandler wraps a slog.Handler and scrubs attribute values whose
// keys match common sensitive patterns (Authorization, Bearer, Token,
// Password, Key, etc.) before writing them to the underlying handler.
type RedactingHandler struct {
	inner slog.Handler
}

// NewRedactingHandler creates a handler that redacts sensitive log attributes
// before delegating to inner.
func NewRedactingHandler(inner slog.Handler) *RedactingHandler {
	return &RedactingHandler{inner: inner}
}

// Enabled delegates to the inner handler.
func (h *RedactingHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

// Handle redacts sensitive attributes before forwarding the record.
func (h *RedactingHandler) Handle(ctx context.Context, r slog.Record) error {
	var cleaned []slog.Attr
	r.Attrs(func(a slog.Attr) bool {
		cleaned = append(cleaned, redactAttr(a))
		return true
	})

	// Build a new record without the original attrs, then add cleaned ones.
	nr := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	nr.AddAttrs(cleaned...)
	return h.inner.Handle(ctx, nr)
}

// WithAttrs returns a new handler with the given pre-redacted attrs.
func (h *RedactingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	redacted := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		redacted[i] = redactAttr(a)
	}
	return &RedactingHandler{inner: h.inner.WithAttrs(redacted)}
}

// WithGroup returns a new handler with the given group.
func (h *RedactingHandler) WithGroup(name string) slog.Handler {
	return &RedactingHandler{inner: h.inner.WithGroup(name)}
}

// redactAttr scrubs a single attribute if its key matches a sensitive pattern.
// Group attributes are recursed into.
func redactAttr(a slog.Attr) slog.Attr {
	// Recurse into groups.
	if a.Value.Kind() == slog.KindGroup {
		attrs := a.Value.Group()
		cleaned := make([]slog.Attr, len(attrs))
		for i, ga := range attrs {
			cleaned[i] = redactAttr(ga)
		}
		return slog.Group(a.Key, attrsToAny(cleaned)...)
	}

	if isSensitiveKey(a.Key) {
		return slog.String(a.Key, redactedValue)
	}
	return a
}

// isSensitiveKey checks if a key matches any known sensitive pattern.
func isSensitiveKey(key string) bool {
	lower := strings.ToLower(key)
	if _, ok := sensitiveKeys[lower]; ok {
		return true
	}
	for _, substr := range []string{"token", "secret", "password", "bearer", "authorization", "api_key", "api-key"} {
		if strings.Contains(lower, substr) {
			return true
		}
	}
	return false
}

// attrsToAny converts []slog.Attr to []any for slog.Group().
func attrsToAny(attrs []slog.Attr) []any {
	result := make([]any, len(attrs))
	for i, a := range attrs {
		result[i] = a
	}
	return result
}
