package logging

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestRedactingHandler_RedactsSensitiveKeys(t *testing.T) {
	var buf bytes.Buffer
	inner := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	handler := NewRedactingHandler(inner)
	logger := slog.New(handler)

	logger.Info("test message",
		"authorization", "Bearer super-secret-token",
		"password", "hunter2",
		"token", "abc123",
		"api_key", "key-456",
		"safe_field", "visible-value",
		"user", "alice",
	)

	var entry map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to parse log output: %v\nbuf: %s", err, buf.String())
	}

	// Sensitive keys must be redacted.
	for _, key := range []string{"authorization", "password", "token", "api_key"} {
		val, ok := entry[key]
		if !ok {
			t.Errorf("expected key %q in log output", key)
			continue
		}
		if val != "[REDACTED]" {
			t.Errorf("key %q should be [REDACTED], got %q", key, val)
		}
	}

	// Non-sensitive keys must be untouched.
	for _, key := range []string{"safe_field", "user"} {
		val, ok := entry[key]
		if !ok {
			t.Errorf("expected key %q in log output", key)
			continue
		}
		if val == "[REDACTED]" {
			t.Errorf("key %q should NOT be redacted", key)
		}
	}
}

func TestRedactingHandler_SubstringMatch(t *testing.T) {
	var buf bytes.Buffer
	inner := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	handler := NewRedactingHandler(inner)
	logger := slog.New(handler)

	logger.Info("composite keys",
		"x-auth-token", "should-be-redacted",
		"my_secret_value", "should-be-redacted",
		"db_password_hash", "should-be-redacted",
		"user_id", "not-redacted",
	)

	var entry map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to parse log output: %v\nbuf: %s", err, buf.String())
	}

	for _, key := range []string{"x-auth-token", "my_secret_value", "db_password_hash"} {
		val, ok := entry[key]
		if !ok {
			t.Errorf("expected key %q in log output", key)
			continue
		}
		if val != "[REDACTED]" {
			t.Errorf("key %q should be [REDACTED], got %q", key, val)
		}
	}

	if val, ok := entry["user_id"]; !ok || val == "[REDACTED]" {
		t.Errorf("user_id should NOT be redacted, got %v", val)
	}
}

func TestRedactingHandler_PassesMessage(t *testing.T) {
	var buf bytes.Buffer
	inner := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	handler := NewRedactingHandler(inner)
	logger := slog.New(handler)

	logger.Info("hello world", "safe", "value")

	if !strings.Contains(buf.String(), "hello world") {
		t.Errorf("log should contain message 'hello world', got: %s", buf.String())
	}
}

// ==========================================================================
// Secret type tests
// ==========================================================================

func TestSecret_LogValue_Redacts(t *testing.T) {
	var buf bytes.Buffer
	inner := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	logger := slog.New(inner) // no RedactingHandler — testing LogValuer alone

	s := NewSecret("super-secret-iam-token")
	logger.Info("auth configured", "iam_token", s)

	var entry map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to parse log output: %v\nbuf: %s", err, buf.String())
	}

	val, ok := entry["iam_token"]
	if !ok {
		t.Fatal("expected key iam_token in log output")
	}
	if val != "[REDACTED]" {
		t.Errorf("iam_token should be [REDACTED] via LogValuer, got %q", val)
	}
	if strings.Contains(buf.String(), "super-secret-iam-token") {
		t.Error("plaintext secret leaked into log output")
	}
}

func TestSecret_String_Redacts(t *testing.T) {
	s := NewSecret("my-password")
	str := fmt.Sprintf("%s", s)
	if str != "[REDACTED]" {
		t.Errorf("String() should return [REDACTED], got %q", str)
	}
	str = fmt.Sprintf("%v", s)
	if str != "[REDACTED]" {
		t.Errorf("%%v should return [REDACTED], got %q", str)
	}
}

func TestSecret_GoString_Redacts(t *testing.T) {
	s := NewSecret("my-password")
	str := fmt.Sprintf("%#v", s)
	if strings.Contains(str, "my-password") {
		t.Errorf("GoString() should not contain plaintext, got %q", str)
	}
}

func TestSecret_Plaintext(t *testing.T) {
	s := NewSecret("actual-value")
	if s.Plaintext() != "actual-value" {
		t.Errorf("Plaintext() = %q, want %q", s.Plaintext(), "actual-value")
	}
}

func TestSecret_IsEmpty(t *testing.T) {
	if !NewSecret("").IsEmpty() {
		t.Error("empty secret should be empty")
	}
	if NewSecret("x").IsEmpty() {
		t.Error("non-empty secret should not be empty")
	}
}

func TestSecret_UnmarshalText(t *testing.T) {
	var s Secret
	if err := s.UnmarshalText([]byte("from-yaml")); err != nil {
		t.Fatalf("UnmarshalText: %v", err)
	}
	if s.Plaintext() != "from-yaml" {
		t.Errorf("after UnmarshalText, Plaintext() = %q, want %q", s.Plaintext(), "from-yaml")
	}
	// Verify it still redacts.
	if s.String() != "[REDACTED]" {
		t.Errorf("after UnmarshalText, String() = %q, want [REDACTED]", s.String())
	}
}
