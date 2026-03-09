package config

import (
	"strings"
	"testing"
)

func TestLoad_AuthValidatePolicyBareStringRef(t *testing.T) {
	yaml := `
listen_addr: ":8080"

auth_validate_policies:
  jwt-internal:
    jwks_url: "https://auth.example.com/.well-known/jwks.json"
    issuer: "auth.example.com"

paths:
  /api/v1/products:
    get:
      x-csar-backend:
        target_url: "https://api.example.com/products"
      x-csar-authn-validate: "jwt-internal"
`
	path := writeTemp(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	av := cfg.Paths["/api/v1/products"]["get"].AuthValidate
	if av == nil {
		t.Fatal("AuthValidate should not be nil after policy resolution")
	}
	if av.JWKSURL != "https://auth.example.com/.well-known/jwks.json" {
		t.Errorf("JWKSURL = %q, want auth.example.com URL", av.JWKSURL)
	}
	if av.Issuer != "auth.example.com" {
		t.Errorf("Issuer = %q, want auth.example.com", av.Issuer)
	}
	if av.Use != "" {
		t.Errorf("Use = %q, should be empty after resolution", av.Use)
	}
}

func TestLoad_AuthValidatePolicyUseWithOverride(t *testing.T) {
	yaml := `
listen_addr: ":8080"

auth_validate_policies:
  jwt-base:
    jwks_url: "https://auth.example.com/.well-known/jwks.json"
    issuer: "auth.example.com"

paths:
  /api/v1/products:
    get:
      x-csar-backend:
        target_url: "https://api.example.com/products"
      x-csar-authn-validate:
        use: "jwt-base"
        issuer: "custom-issuer"
`
	path := writeTemp(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	av := cfg.Paths["/api/v1/products"]["get"].AuthValidate
	if av.Issuer != "custom-issuer" {
		t.Errorf("Issuer = %q, want custom-issuer (inline override)", av.Issuer)
	}
	if av.JWKSURL != "https://auth.example.com/.well-known/jwks.json" {
		t.Errorf("JWKSURL should come from policy")
	}
}

func TestLoad_AuthValidatePolicyUnknownRef(t *testing.T) {
	yaml := `
listen_addr: ":8080"

paths:
  /api/v1/products:
    get:
      x-csar-backend:
        target_url: "https://api.example.com/products"
      x-csar-authn-validate: "nonexistent"
`
	path := writeTemp(t, yaml)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for unknown auth-validate policy reference")
	}
	if !strings.Contains(err.Error(), "nonexistent") {
		t.Errorf("error should mention policy name, got: %v", err)
	}
}
