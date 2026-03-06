package config

import (
	"strings"
	"testing"
	"time"
)

func TestLoad_RetryPolicyBareStringRef(t *testing.T) {
	yaml := `
listen_addr: ":8080"

retry_policies:
  safe-retry:
    max_attempts: 3
    backoff: "1s"
    max_backoff: "10s"
    retryable_status_codes: [502, 503, 504]

paths:
  /api/v1/products:
    get:
      x-csar-backend:
        target_url: "https://api.example.com/products"
      x-csar-retry: "safe-retry"
`
	path := writeTemp(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	retry := cfg.Paths["/api/v1/products"]["get"].Retry
	if retry == nil {
		t.Fatal("Retry should not be nil after policy resolution")
	}
	if retry.MaxAttempts != 3 {
		t.Errorf("MaxAttempts = %v, want 3", retry.MaxAttempts)
	}
	if retry.Backoff.Duration != 1*time.Second {
		t.Errorf("Backoff = %v, want 1s", retry.Backoff.Duration)
	}
	if retry.Use != "" {
		t.Errorf("Use = %q, should be empty after resolution", retry.Use)
	}
}

func TestLoad_RetryPolicyUseWithOverride(t *testing.T) {
	yaml := `
listen_addr: ":8080"

retry_policies:
  base-retry:
    max_attempts: 3
    backoff: "1s"
    max_backoff: "10s"

paths:
  /api/v1/products:
    get:
      x-csar-backend:
        target_url: "https://api.example.com/products"
      x-csar-retry:
        use: "base-retry"
        max_attempts: 5
`
	path := writeTemp(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	retry := cfg.Paths["/api/v1/products"]["get"].Retry
	if retry.MaxAttempts != 5 {
		t.Errorf("MaxAttempts = %v, want 5 (inline override)", retry.MaxAttempts)
	}
	if retry.Backoff.Duration != 1*time.Second {
		t.Errorf("Backoff = %v, want 1s (from policy)", retry.Backoff.Duration)
	}
}

func TestLoad_RetryPolicyUnknownRef(t *testing.T) {
	yaml := `
listen_addr: ":8080"

paths:
  /api/v1/products:
    get:
      x-csar-backend:
        target_url: "https://api.example.com/products"
      x-csar-retry: "nonexistent"
`
	path := writeTemp(t, yaml)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for unknown retry policy reference")
	}
	if !strings.Contains(err.Error(), "nonexistent") {
		t.Errorf("error should mention policy name, got: %v", err)
	}
}
