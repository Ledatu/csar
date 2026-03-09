// Package logging provides structured-logging utilities for CSAR.
// Redaction logic is delegated to the shared csar-core/logutil package.
package logging

import (
	"log/slog"

	"github.com/ledatu/csar-core/logutil"
	"github.com/ledatu/csar-core/secret"
)

// Secret is a type alias for secret.Secret from csar-core. This preserves
// backward compatibility: all existing code that uses logging.Secret,
// logging.NewSecret, etc. continues to compile without changes.
type Secret = secret.Secret

// NewSecret wraps a plaintext string in a Secret.
func NewSecret(plaintext string) Secret {
	return secret.NewSecret(plaintext)
}

// RedactingHandler is a type alias for the shared logutil.RedactingHandler.
type RedactingHandler = logutil.RedactingHandler

// NewRedactingHandler creates a handler that redacts sensitive log attributes
// before delegating to inner.
func NewRedactingHandler(inner slog.Handler) *RedactingHandler {
	return logutil.NewRedactingHandler(inner)
}
