package config

import (
	"strings"
	"testing"
)

func TestLoad_BackendTLSPolicyBareStringRef(t *testing.T) {
	y := `
listen_addr: ":8080"

backend_tls_policies:
  authn-mtls:
    ca_file: "/tls/ca.pem"
    cert_file: "/tls/client.pem"
    key_file: "/tls/client-key.pem"

paths:
  /auth:
    get:
      x-csar-backend:
        target_url: "https://authn:8081"
        tls: "authn-mtls"
`
	path := writeTemp(t, y)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	bt := cfg.Paths["/auth"]["get"].Backend.TLS
	if bt == nil {
		t.Fatal("Backend.TLS should not be nil after policy resolution")
	}
	if bt.Use != "" {
		t.Errorf("Use = %q, should be empty after resolution", bt.Use)
	}
	if bt.CAFile != "/tls/ca.pem" {
		t.Errorf("CAFile = %q, want /tls/ca.pem", bt.CAFile)
	}
	if bt.CertFile != "/tls/client.pem" {
		t.Errorf("CertFile = %q, want /tls/client.pem", bt.CertFile)
	}
	if bt.KeyFile != "/tls/client-key.pem" {
		t.Errorf("KeyFile = %q, want /tls/client-key.pem", bt.KeyFile)
	}
}

func TestLoad_BackendTLSPolicyUseWithOverride(t *testing.T) {
	y := `
listen_addr: ":8080"

backend_tls_policies:
  authn-mtls:
    ca_file: "/tls/ca.pem"
    cert_file: "/tls/client.pem"
    key_file: "/tls/client-key.pem"

paths:
  /debug:
    get:
      x-csar-backend:
        target_url: "https://authn:8081"
        tls:
          use: "authn-mtls"
          insecure_skip_verify: true
`
	path := writeTemp(t, y)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	bt := cfg.Paths["/debug"]["get"].Backend.TLS
	if bt == nil {
		t.Fatal("Backend.TLS should not be nil")
	}
	if !bt.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be true (inline override)")
	}
	if bt.CAFile != "/tls/ca.pem" {
		t.Errorf("CAFile should come from policy, got %q", bt.CAFile)
	}
	if bt.CertFile != "/tls/client.pem" {
		t.Errorf("CertFile should come from policy, got %q", bt.CertFile)
	}
}

func TestLoad_BackendTLSPolicyFieldOverride(t *testing.T) {
	y := `
listen_addr: ":8080"

backend_tls_policies:
  base:
    ca_file: "/tls/ca.pem"
    cert_file: "/tls/client.pem"
    key_file: "/tls/client-key.pem"

paths:
  /api:
    get:
      x-csar-backend:
        target_url: "https://backend:443"
        tls:
          use: "base"
          ca_file: "/tls/custom-ca.pem"
`
	path := writeTemp(t, y)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	bt := cfg.Paths["/api"]["get"].Backend.TLS
	if bt.CAFile != "/tls/custom-ca.pem" {
		t.Errorf("CAFile = %q, want /tls/custom-ca.pem (inline override)", bt.CAFile)
	}
	if bt.CertFile != "/tls/client.pem" {
		t.Errorf("CertFile = %q, want /tls/client.pem (from policy)", bt.CertFile)
	}
}

func TestLoad_BackendTLSPolicyUnknownRef(t *testing.T) {
	y := `
listen_addr: ":8080"

paths:
  /auth:
    get:
      x-csar-backend:
        target_url: "https://authn:8081"
        tls: "nonexistent"
`
	path := writeTemp(t, y)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for unknown backend TLS policy reference")
	}
	if !strings.Contains(err.Error(), "nonexistent") {
		t.Errorf("error should mention policy name, got: %v", err)
	}
	if !strings.Contains(err.Error(), "no backend_tls_policies defined") {
		t.Errorf("error should mention no policies defined, got: %v", err)
	}
}

func TestLoad_BackendTLSPolicyMissingFromMap(t *testing.T) {
	y := `
listen_addr: ":8080"

backend_tls_policies:
  other-policy:
    ca_file: "/tls/ca.pem"

paths:
  /auth:
    get:
      x-csar-backend:
        target_url: "https://authn:8081"
        tls: "nonexistent"
`
	path := writeTemp(t, y)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for missing backend TLS policy")
	}
	if !strings.Contains(err.Error(), "not found in backend_tls_policies") {
		t.Errorf("error should mention 'not found', got: %v", err)
	}
}

func TestLoad_BackendTLSPolicyInlineNoRef(t *testing.T) {
	y := `
listen_addr: ":8080"

paths:
  /api:
    get:
      x-csar-backend:
        target_url: "https://backend:443"
        tls:
          ca_file: "/tls/ca.pem"
          cert_file: "/tls/client.pem"
          key_file: "/tls/client-key.pem"
`
	path := writeTemp(t, y)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	bt := cfg.Paths["/api"]["get"].Backend.TLS
	if bt == nil {
		t.Fatal("Backend.TLS should not be nil")
	}
	if bt.CAFile != "/tls/ca.pem" {
		t.Errorf("CAFile = %q", bt.CAFile)
	}
}

func TestValidate_BackendTLSPolicyPartialKeypair(t *testing.T) {
	y := `
listen_addr: ":8080"

backend_tls_policies:
  broken:
    ca_file: "/tls/ca.pem"
    cert_file: "/tls/client.pem"

paths:
  /api:
    get:
      x-csar-backend:
        target_url: "https://backend:443"
`
	path := writeTemp(t, y)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected validation error for partial mTLS keypair in policy definition")
	}
	if !strings.Contains(err.Error(), "cert_file and key_file must both be set") {
		t.Errorf("error should mention keypair requirement, got: %v", err)
	}
}

func TestParseBytes_BackendTLSPolicyResolution(t *testing.T) {
	y := `
listen_addr: ":8080"

backend_tls_policies:
  authn-mtls:
    ca_file: "/tls/ca.pem"
    cert_file: "/tls/client.pem"
    key_file: "/tls/client-key.pem"

paths:
  /auth:
    get:
      x-csar-backend:
        target_url: "https://authn:8081"
        tls: "authn-mtls"
`
	cfg, err := ParseBytes([]byte(y))
	if err != nil {
		t.Fatalf("ParseBytes() error: %v", err)
	}

	bt := cfg.Paths["/auth"]["get"].Backend.TLS
	if bt == nil {
		t.Fatal("Backend.TLS should not be nil after resolution via ParseBytes")
	}
	if bt.Use != "" {
		t.Errorf("Use = %q, should be empty after resolution", bt.Use)
	}
	if bt.CertFile != "/tls/client.pem" {
		t.Errorf("CertFile = %q", bt.CertFile)
	}
}

func TestLoad_BackendTLSPolicyAnnotatesSource(t *testing.T) {
	y := `
listen_addr: ":8080"

backend_tls_policies:
  authn-mtls:
    ca_file: "/tls/ca.pem"
    cert_file: "/tls/client.pem"
    key_file: "/tls/client-key.pem"

paths:
  /auth:
    get:
      x-csar-backend:
        target_url: "https://authn:8081"
        tls: "authn-mtls"
`
	path := writeTemp(t, y)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	route := cfg.Paths["/auth"]["get"]
	if route.SourceInfo == nil {
		t.Fatal("SourceInfo should not be nil after policy resolution")
	}
	meta, ok := route.SourceInfo["x-csar-backend.tls"]
	if !ok {
		t.Fatal("SourceInfo should contain x-csar-backend.tls entry")
	}
	if meta.Policy != "authn-mtls" {
		t.Errorf("Policy = %q, want authn-mtls", meta.Policy)
	}
}

func TestLoad_BackendTLSPolicyOverrideFalse(t *testing.T) {
	y := `
listen_addr: ":8080"

backend_tls_policies:
  permissive:
    insecure_skip_verify: true
    ca_file: "/tls/ca.pem"
    cert_file: "/tls/client.pem"
    key_file: "/tls/client-key.pem"

paths:
  /api:
    get:
      x-csar-backend:
        target_url: "https://backend:443"
        tls:
          use: "permissive"
          insecure_skip_verify: false
`
	path := writeTemp(t, y)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	bt := cfg.Paths["/api"]["get"].Backend.TLS
	if bt == nil {
		t.Fatal("Backend.TLS should not be nil")
	}
	if bt.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be false (route explicitly overrides policy true → false)")
	}
	if bt.CAFile != "/tls/ca.pem" {
		t.Errorf("CAFile = %q, want /tls/ca.pem (from policy)", bt.CAFile)
	}
}

func TestLoad_BackendTLSPolicyInheritTrue(t *testing.T) {
	y := `
listen_addr: ":8080"

backend_tls_policies:
  permissive:
    insecure_skip_verify: true
    ca_file: "/tls/ca.pem"
    cert_file: "/tls/client.pem"
    key_file: "/tls/client-key.pem"

paths:
  /debug:
    get:
      x-csar-backend:
        target_url: "https://backend:443"
        tls: "permissive"
`
	path := writeTemp(t, y)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	bt := cfg.Paths["/debug"]["get"].Backend.TLS
	if bt == nil {
		t.Fatal("Backend.TLS should not be nil")
	}
	if !bt.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be true (inherited from policy, no override)")
	}
}

func TestLoad_BackendTLSPolicyUseFieldIgnoredInPolicy(t *testing.T) {
	y := `
listen_addr: ":8080"

backend_tls_policies:
  child:
    use: "base"
    ca_file: "/tls/ca.pem"
    cert_file: "/tls/client.pem"
    key_file: "/tls/client-key.pem"

paths:
  /api:
    get:
      x-csar-backend:
        target_url: "https://backend:443"
`
	path := writeTemp(t, y)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() should succeed (unknown fields in policy are ignored by Go struct): %v", err)
	}
	_ = cfg
}
