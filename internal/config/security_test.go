package config

import (
	"strings"
	"testing"

	yamlPkg "gopkg.in/yaml.v3"
)

// ==========================================================================
// Security Profiles tests (Feature A)
// ==========================================================================

func TestSecurityProfiles_StringRef(t *testing.T) {
	yamlStr := `
listen_addr: ":8080"
security_profiles:
  api_bearer:
    kms_key_id: "key-1"
    token_ref: "api_token"
    inject_header: "Authorization"
    inject_format: "Bearer {token}"
paths:
  /api/v1/products:
    get:
      x-csar-backend:
        target_url: "https://api.example.com/products"
      x-csar-security: "api_bearer"
`
	path := writeTemp(t, yamlStr)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	route := cfg.Paths["/api/v1/products"]["get"]
	if len(route.Security) != 1 {
		t.Fatalf("expected 1 security entry, got %d", len(route.Security))
	}
	sec := route.Security[0]
	if sec.Profile != "" {
		t.Errorf("Profile should be cleared after resolution, got %q", sec.Profile)
	}
	if sec.KMSKeyID != "key-1" {
		t.Errorf("KMSKeyID = %q, want %q", sec.KMSKeyID, "key-1")
	}
	if sec.TokenRef != "api_token" {
		t.Errorf("TokenRef = %q, want %q", sec.TokenRef, "api_token")
	}
	if sec.InjectHeader != "Authorization" {
		t.Errorf("InjectHeader = %q, want %q", sec.InjectHeader, "Authorization")
	}
	if sec.InjectFormat != "Bearer {token}" {
		t.Errorf("InjectFormat = %q, want %q", sec.InjectFormat, "Bearer {token}")
	}
}

func TestSecurityProfiles_ArrayMixed(t *testing.T) {
	yamlStr := `
listen_addr: ":8080"
security_profiles:
  api_bearer:
    kms_key_id: "key-1"
    token_ref: "api_token"
    inject_header: "Authorization"
    inject_format: "Bearer {token}"
paths:
  /api/v1/products:
    get:
      x-csar-backend:
        target_url: "https://api.example.com/products"
      x-csar-security:
        - "api_bearer"
        - kms_key_id: "key-2"
          token_ref: "extra_secret"
          inject_header: "X-Client-Secret"
          inject_format: "{token}"
`
	path := writeTemp(t, yamlStr)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	route := cfg.Paths["/api/v1/products"]["get"]
	if len(route.Security) != 2 {
		t.Fatalf("expected 2 security entries, got %d", len(route.Security))
	}
	// First entry should be resolved from profile
	if route.Security[0].KMSKeyID != "key-1" {
		t.Errorf("[0].KMSKeyID = %q, want %q", route.Security[0].KMSKeyID, "key-1")
	}
	if route.Security[0].InjectHeader != "Authorization" {
		t.Errorf("[0].InjectHeader = %q, want %q", route.Security[0].InjectHeader, "Authorization")
	}
	// Second entry is inline
	if route.Security[1].KMSKeyID != "key-2" {
		t.Errorf("[1].KMSKeyID = %q, want %q", route.Security[1].KMSKeyID, "key-2")
	}
	if route.Security[1].InjectHeader != "X-Client-Secret" {
		t.Errorf("[1].InjectHeader = %q, want %q", route.Security[1].InjectHeader, "X-Client-Secret")
	}
}

func TestSecurityProfiles_InlineOverride(t *testing.T) {
	yamlStr := `
listen_addr: ":8080"
security_profiles:
  api_bearer:
    kms_key_id: "key-1"
    token_ref: "api_token"
    inject_header: "Authorization"
    inject_format: "Bearer {token}"
    on_kms_error: "fail_closed"
paths:
  /api/v1/products:
    get:
      x-csar-backend:
        target_url: "https://api.example.com/products"
      x-csar-security:
        - profile: "api_bearer"
          on_kms_error: "serve_stale"
          token_ref: "overridden_token"
`
	path := writeTemp(t, yamlStr)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	sec := cfg.Paths["/api/v1/products"]["get"].Security[0]
	// Inherited from profile
	if sec.KMSKeyID != "key-1" {
		t.Errorf("KMSKeyID = %q, want inherited %q", sec.KMSKeyID, "key-1")
	}
	if sec.InjectHeader != "Authorization" {
		t.Errorf("InjectHeader = %q, want inherited %q", sec.InjectHeader, "Authorization")
	}
	// Overridden by inline
	if sec.OnKMSError != "serve_stale" {
		t.Errorf("OnKMSError = %q, want overridden %q", sec.OnKMSError, "serve_stale")
	}
	if sec.TokenRef != "overridden_token" {
		t.Errorf("TokenRef = %q, want overridden %q", sec.TokenRef, "overridden_token")
	}
}

func TestSecurityProfiles_NotFound(t *testing.T) {
	yamlStr := `
listen_addr: ":8080"
security_profiles:
  api_bearer:
    kms_key_id: "key-1"
    token_ref: "api_token"
    inject_header: "Authorization"
    inject_format: "Bearer {token}"
paths:
  /api:
    get:
      x-csar-backend:
        target_url: "https://api.example.com"
      x-csar-security: "nonexistent_profile"
`
	path := writeTemp(t, yamlStr)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for nonexistent profile, got nil")
	}
	if !strings.Contains(err.Error(), "nonexistent_profile") {
		t.Errorf("error should mention profile name, got: %v", err)
	}
}

func TestSecurityProfiles_BackwardCompat_InlineObject(t *testing.T) {
	// Existing inline syntax should still work unchanged
	yamlStr := `
listen_addr: ":8080"
paths:
  /api:
    get:
      x-csar-backend:
        target_url: "https://api.example.com"
      x-csar-security:
        kms_key_id: "key-1"
        token_ref: "tok"
        inject_header: "Authorization"
        inject_format: "Bearer {token}"
`
	path := writeTemp(t, yamlStr)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	sec := cfg.Paths["/api"]["get"].Security[0]
	if sec.KMSKeyID != "key-1" {
		t.Errorf("KMSKeyID = %q, want %q", sec.KMSKeyID, "key-1")
	}
}

func TestSecurityProfiles_NoProfilesDefined_StringRef_Error(t *testing.T) {
	// Referencing a profile when no security_profiles section exists should error
	yamlStr := `
listen_addr: ":8080"
paths:
  /api:
    get:
      x-csar-backend:
        target_url: "https://api.example.com"
      x-csar-security: "some_profile"
`
	path := writeTemp(t, yamlStr)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error when referencing profile with no security_profiles defined")
	}
	if !strings.Contains(err.Error(), "some_profile") {
		t.Errorf("error should mention profile name, got: %v", err)
	}
}

// ==========================================================================
// StripTokenParams tests (Feature B)
// ==========================================================================

func TestSecurityConfig_StripTokenParams_DefaultTrue(t *testing.T) {
	cfg := SecurityConfig{}
	if !cfg.ShouldStripTokenParams() {
		t.Error("ShouldStripTokenParams() = false, want true (default)")
	}
}

func TestSecurityConfig_StripTokenParams_ExplicitFalse(t *testing.T) {
	f := false
	cfg := SecurityConfig{StripTokenParams: &f}
	if cfg.ShouldStripTokenParams() {
		t.Error("ShouldStripTokenParams() = true, want false")
	}
}

func TestSecurityConfig_StripTokenParams_ExplicitTrue(t *testing.T) {
	tr := true
	cfg := SecurityConfig{StripTokenParams: &tr}
	if !cfg.ShouldStripTokenParams() {
		t.Error("ShouldStripTokenParams() = false, want true")
	}
}

func TestSecurityProfiles_StripTokenParams_InheritedFromProfile(t *testing.T) {
	yamlStr := `
listen_addr: ":8080"
security_profiles:
  api_bearer:
    kms_key_id: "key-1"
    token_ref: "api_token_{query.seller_id}"
    inject_header: "Authorization"
    inject_format: "Bearer {token}"
    strip_token_params: true
paths:
  /api:
    get:
      x-csar-backend:
        target_url: "https://api.example.com"
      x-csar-security: "api_bearer"
`
	path := writeTemp(t, yamlStr)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	sec := cfg.Paths["/api"]["get"].Security[0]
	if !sec.ShouldStripTokenParams() {
		t.Error("expected strip_token_params=true inherited from profile")
	}
}

func TestSecurityProfiles_StripTokenParams_OverriddenInline(t *testing.T) {
	yamlStr := `
listen_addr: ":8080"
security_profiles:
  api_bearer:
    kms_key_id: "key-1"
    token_ref: "api_token_{query.seller_id}"
    inject_header: "Authorization"
    inject_format: "Bearer {token}"
    strip_token_params: true
paths:
  /api:
    get:
      x-csar-backend:
        target_url: "https://api.example.com"
      x-csar-security:
        - profile: "api_bearer"
          strip_token_params: false
`
	path := writeTemp(t, yamlStr)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	sec := cfg.Paths["/api"]["get"].Security[0]
	if sec.ShouldStripTokenParams() {
		t.Error("expected strip_token_params=false (overridden by inline)")
	}
}

func TestValidate_UnresolvedProfileRef_Error(t *testing.T) {
	// Simulate a programmatically-built config where the caller forgot to
	// call ResolveSecurityProfiles() before Validate().
	cfg := &Config{
		ListenAddr: ":8080",
		Paths: map[string]PathConfig{
			"/api": {
				"get": RouteConfig{
					Backend: BackendConfig{TargetURL: "https://api.example.com"},
					Security: SecurityConfigs{{
						Profile: "unresolved_ref",
					}},
				},
			},
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for unresolved profile reference, got nil")
	}
	if !strings.Contains(err.Error(), "unresolved profile reference") {
		t.Errorf("error should mention 'unresolved profile reference', got: %v", err)
	}
	if !strings.Contains(err.Error(), "ResolveSecurityProfiles") {
		t.Errorf("error should mention ResolveSecurityProfiles(), got: %v", err)
	}
}

// unmarshalYAML is a helper used in security/throttle tests.
func unmarshalYAML(data []byte, v interface{}) error {
	return yamlPkg.Unmarshal(data, v)
}
