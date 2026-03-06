package config

import (
	"strings"
	"testing"
)

func TestLoad_CORSPolicyBareStringRef(t *testing.T) {
	yaml := `
listen_addr: ":8080"

cors_policies:
  standard-cors:
    allowed_origins: ["https://example.com"]
    allowed_methods: ["GET", "POST"]
    max_age: 3600

paths:
  /api/v1/products:
    get:
      x-csar-backend:
        target_url: "https://api.example.com/products"
      x-csar-cors: "standard-cors"
`
	path := writeTemp(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	cors := cfg.Paths["/api/v1/products"]["get"].CORS
	if cors == nil {
		t.Fatal("CORS should not be nil after policy resolution")
	}
	if len(cors.AllowedOrigins) != 1 || cors.AllowedOrigins[0] != "https://example.com" {
		t.Errorf("AllowedOrigins = %v, want [https://example.com]", cors.AllowedOrigins)
	}
	if cors.MaxAge != 3600 {
		t.Errorf("MaxAge = %v, want 3600", cors.MaxAge)
	}
	if cors.Use != "" {
		t.Errorf("Use = %q, should be empty after resolution", cors.Use)
	}
}

func TestLoad_CORSPolicyUseWithOverride(t *testing.T) {
	yaml := `
listen_addr: ":8080"

cors_policies:
  base-cors:
    allowed_origins: ["https://example.com"]
    allowed_methods: ["GET"]
    max_age: 3600

paths:
  /api/v1/products:
    get:
      x-csar-backend:
        target_url: "https://api.example.com/products"
      x-csar-cors:
        use: "base-cors"
        max_age: 7200
`
	path := writeTemp(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	cors := cfg.Paths["/api/v1/products"]["get"].CORS
	if cors == nil {
		t.Fatal("CORS should not be nil")
	}
	if cors.MaxAge != 7200 {
		t.Errorf("MaxAge = %v, want 7200 (inline override)", cors.MaxAge)
	}
	if len(cors.AllowedOrigins) != 1 {
		t.Errorf("AllowedOrigins should come from policy, got %v", cors.AllowedOrigins)
	}
}

func TestLoad_CORSPolicyUnknownRef(t *testing.T) {
	yaml := `
listen_addr: ":8080"

paths:
  /api/v1/products:
    get:
      x-csar-backend:
        target_url: "https://api.example.com/products"
      x-csar-cors: "nonexistent"
`
	path := writeTemp(t, yaml)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for unknown CORS policy reference")
	}
	if !strings.Contains(err.Error(), "nonexistent") {
		t.Errorf("error should mention policy name, got: %v", err)
	}
}
