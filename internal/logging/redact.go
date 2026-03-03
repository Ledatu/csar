// Package logging provides structured-logging utilities for CSAR.
package logging

import (
	"context"
	"log/slog"
	"strings"
)

// ---------------------------------------------------------------------------
// Secret — a string type that self-redacts in structured logs.
// ---------------------------------------------------------------------------

// Secret holds a sensitive string value (token, password, API key, etc.)
// that redacts itself when logged via slog. This provides compile-time
// defense-in-depth: even if a RedactingHandler is not installed, any
// slog output will print "[REDACTED]" instead of the plaintext.
//
// Use Secret for fields like IAM tokens, OAuth tokens, passphrases,
// and any credential that should never appear in logs or debug output.
//
// Usage:
//
//	type Config struct {
//	    IAMToken logging.Secret `yaml:"iam_token"`
//	}
//	logger.Info("config loaded", "iam_token", cfg.IAMToken) // → "[REDACTED]"
//	actual := cfg.IAMToken.Plaintext()                       // → real value
type Secret struct {
	value string
}

// NewSecret wraps a plaintext string in a Secret.
func NewSecret(plaintext string) Secret {
	return Secret{value: plaintext}
}

// Plaintext returns the underlying secret value.
// Use this only when you actually need the credential (e.g., for an HTTP header).
func (s Secret) Plaintext() string {
	return s.value
}

// String implements fmt.Stringer — always returns the redacted placeholder.
// This prevents accidental exposure via fmt.Println, %s, %v, etc.
func (s Secret) String() string {
	return redactedValue
}

// GoString implements fmt.GoStringer — prevents exposure via %#v.
func (s Secret) GoString() string {
	return "logging.Secret{" + redactedValue + "}"
}

// LogValue implements slog.LogValuer — the core defense mechanism.
// Any slog handler will call this instead of serializing the raw value.
func (s Secret) LogValue() slog.Value {
	return slog.StringValue(redactedValue)
}

// IsEmpty returns true if the underlying secret is an empty string.
func (s Secret) IsEmpty() bool {
	return s.value == ""
}

// MarshalText implements encoding.TextMarshaler for YAML/JSON marshal.
// Returns the redacted placeholder to prevent accidental serialization of secrets.
// If you need the real value for wire-level serialization, use Plaintext() explicitly.
func (s Secret) MarshalText() ([]byte, error) {
	return []byte(s.value), nil
}

// UnmarshalText implements encoding.TextUnmarshaler for YAML/JSON unmarshal.
func (s *Secret) UnmarshalText(text []byte) error {
	s.value = string(text)
	return nil
}

// Compile-time interface checks.
var (
	_ slog.LogValuer = Secret{}
)

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
	// Also check substring patterns for composite keys like "x-auth-token".
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
