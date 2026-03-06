package config

import (
	"strings"
	"testing"
)

func TestLoad_RedactPolicyBareStringRef(t *testing.T) {
	yaml := `
listen_addr: ":8080"

redact_policies:
  pii-mask:
    fields: ["email", "phone"]
    mask: "***"

paths:
  /api/v1/users:
    get:
      x-csar-backend:
        target_url: "https://users.example.com"
      x-csar-redact: "pii-mask"
`
	path := writeTemp(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	redact := cfg.Paths["/api/v1/users"]["get"].Redact
	if redact == nil {
		t.Fatal("Redact should not be nil after policy resolution")
	}
	if len(redact.Fields) != 2 {
		t.Errorf("Fields length = %d, want 2", len(redact.Fields))
	}
	if redact.Mask != "***" {
		t.Errorf("Mask = %q, want ***", redact.Mask)
	}
	if redact.Use != "" {
		t.Errorf("Use = %q, should be empty after resolution", redact.Use)
	}
}

func TestLoad_RedactPolicyUseWithOverride(t *testing.T) {
	yaml := `
listen_addr: ":8080"

redact_policies:
  pii-mask:
    fields: ["email", "phone"]
    mask: "***"

paths:
  /api/v1/users:
    get:
      x-csar-backend:
        target_url: "https://users.example.com"
      x-csar-redact:
        use: "pii-mask"
        mask: "[REDACTED]"
`
	path := writeTemp(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	redact := cfg.Paths["/api/v1/users"]["get"].Redact
	if redact.Mask != "[REDACTED]" {
		t.Errorf("Mask = %q, want [REDACTED] (inline override)", redact.Mask)
	}
	if len(redact.Fields) != 2 {
		t.Errorf("Fields should come from policy, got %v", redact.Fields)
	}
}

func TestLoad_RedactPolicyUnknownRef(t *testing.T) {
	yaml := `
listen_addr: ":8080"

paths:
  /api/v1/users:
    get:
      x-csar-backend:
        target_url: "https://users.example.com"
      x-csar-redact: "nonexistent"
`
	path := writeTemp(t, yaml)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for unknown redact policy reference")
	}
	if !strings.Contains(err.Error(), "nonexistent") {
		t.Errorf("error should mention policy name, got: %v", err)
	}
}
