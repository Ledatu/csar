package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ledatu/csar/internal/logging"
	yamlPkg "gopkg.in/yaml.v3"
)

func TestLoad_ValidConfig(t *testing.T) {
	yaml := `
listen_addr: ":8080"

circuit_breakers:
  standard:
    max_requests: 5
    interval: "60s"
    timeout: "30s"
    failure_threshold: 3

paths:
  /api/v1/products:
    get:
      x-csar-backend:
        target_url: "https://api.example.com/products"
      x-csar-security:
        kms_key_id: "key-123"
        token_ref: "token_main"
        inject_header: "Authorization"
        inject_format: "Bearer {token}"
      x-csar-traffic:
        rps: 5.0
        burst: 10
        max_wait: "30s"
      x-csar-resilience:
        circuit_breaker: "standard"
    post:
      x-csar-backend:
        target_url: "https://api.example.com/products"
  /health:
    get:
      x-csar-backend:
        target_url: "http://localhost:8080"
`
	path := writeTemp(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.ListenAddr != ":8080" {
		t.Errorf("ListenAddr = %q, want %q", cfg.ListenAddr, ":8080")
	}

	if len(cfg.Paths) != 2 {
		t.Fatalf("len(Paths) = %d, want 2", len(cfg.Paths))
	}

	// Check /api/v1/products GET
	products, ok := cfg.Paths["/api/v1/products"]
	if !ok {
		t.Fatal("missing path /api/v1/products")
	}
	getRoute, ok := products["get"]
	if !ok {
		t.Fatal("missing method GET for /api/v1/products")
	}

	if getRoute.Backend.TargetURL != "https://api.example.com/products" {
		t.Errorf("TargetURL = %q, want %q", getRoute.Backend.TargetURL, "https://api.example.com/products")
	}
	if len(getRoute.Security) == 0 {
		t.Fatal("Security is empty, want at least one entry")
	}
	if getRoute.Security[0].KMSKeyID != "key-123" {
		t.Errorf("KMSKeyID = %q, want %q", getRoute.Security[0].KMSKeyID, "key-123")
	}
	if getRoute.Security[0].InjectHeader != "Authorization" {
		t.Errorf("InjectHeader = %q, want %q", getRoute.Security[0].InjectHeader, "Authorization")
	}
	if getRoute.Security[0].InjectFormat != "Bearer {token}" {
		t.Errorf("InjectFormat = %q, want %q", getRoute.Security[0].InjectFormat, "Bearer {token}")
	}

	if getRoute.Traffic == nil {
		t.Fatal("Traffic is nil, want non-nil")
	}
	if getRoute.Traffic.RPS != 5.0 {
		t.Errorf("RPS = %f, want 5.0", getRoute.Traffic.RPS)
	}
	if getRoute.Traffic.Burst != 10 {
		t.Errorf("Burst = %d, want 10", getRoute.Traffic.Burst)
	}
	if getRoute.Traffic.MaxWait.Duration != 30*time.Second {
		t.Errorf("MaxWait = %v, want 30s", getRoute.Traffic.MaxWait.Duration)
	}

	if getRoute.Resilience == nil {
		t.Fatal("Resilience is nil, want non-nil")
	}
	if getRoute.Resilience.CircuitBreaker != "standard" {
		t.Errorf("CircuitBreaker = %q, want %q", getRoute.Resilience.CircuitBreaker, "standard")
	}

	// Check /api/v1/products POST (no security, traffic, resilience)
	postRoute, ok := products["post"]
	if !ok {
		t.Fatal("missing method POST for /api/v1/products")
	}
	if len(postRoute.Security) != 0 {
		t.Error("POST Security should be empty")
	}
	if postRoute.Traffic != nil {
		t.Error("POST Traffic should be nil")
	}

	// Check circuit breaker profile
	cb, ok := cfg.CircuitBreakers["standard"]
	if !ok {
		t.Fatal("missing circuit_breaker profile 'standard'")
	}
	if cb.MaxRequests != 5 {
		t.Errorf("CB MaxRequests = %d, want 5", cb.MaxRequests)
	}
	if cb.Timeout.Duration != 30*time.Second {
		t.Errorf("CB Timeout = %v, want 30s", cb.Timeout.Duration)
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := Load("/nonexistent/config.yaml")
	if err == nil {
		t.Fatal("Load() should fail for missing file")
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	path := writeTemp(t, `{{{not yaml`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() should fail for invalid YAML")
	}
}

func TestValidate_MissingListenAddr(t *testing.T) {
	cfg := &Config{
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{Backend: BackendConfig{TargetURL: "http://localhost"}}},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should fail without listen_addr")
	}
}

func TestValidate_NoPaths(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Paths:      map[string]PathConfig{},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should fail with empty paths")
	}
}

func TestValidate_MissingTargetURL(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{}},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should fail without target_url")
	}
}

func TestValidate_UndefinedCircuitBreaker(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{
				Backend:    BackendConfig{TargetURL: "http://localhost"},
				Resilience: &ResilienceConfig{CircuitBreaker: "nonexistent"},
			}},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should fail for undefined circuit_breaker profile")
	}
}

func TestValidate_ValidCircuitBreakerRef(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		CircuitBreakers: map[string]CircuitBreakerProfile{
			"my_breaker": {MaxRequests: 5, FailureThreshold: 3},
		},
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{
				Backend:    BackendConfig{TargetURL: "http://localhost"},
				Resilience: &ResilienceConfig{CircuitBreaker: "my_breaker"},
			}},
		},
	}
	err := cfg.Validate()
	if err != nil {
		t.Fatalf("Validate() unexpected error: %v", err)
	}
}

func TestValidate_TLS_RequiresBothFiles(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8443",
		TLS:        &TLSConfig{CertFile: "cert.pem"},
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{Backend: BackendConfig{TargetURL: "http://localhost"}}},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should fail when TLS key_file is missing")
	}
}

func TestValidate_TLS_InvalidMinVersion(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8443",
		TLS:        &TLSConfig{CertFile: "cert.pem", KeyFile: "key.pem", MinVersion: "1.1"},
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{Backend: BackendConfig{TargetURL: "http://localhost"}}},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should fail for min_version 1.1")
	}
}

func TestValidate_TLS_ValidMinVersions(t *testing.T) {
	for _, v := range []string{"1.2", "1.3"} {
		t.Run(v, func(t *testing.T) {
			cfg := &Config{
				ListenAddr: ":8443",
				TLS:        &TLSConfig{CertFile: "cert.pem", KeyFile: "key.pem", MinVersion: v},
				Paths: map[string]PathConfig{
					"/test": {"get": RouteConfig{Backend: BackendConfig{TargetURL: "http://localhost"}}},
				},
			}
			if err := cfg.Validate(); err != nil {
				t.Fatalf("Validate() error: %v", err)
			}
		})
	}
}

func TestValidate_BackendTLS_CertWithoutKey(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{
				Backend: BackendConfig{
					TargetURL: "https://api.example.com",
					TLS:       &BackendTLSConfig{CertFile: "client.pem"},
				},
			}},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should fail when backend TLS cert_file is set without key_file")
	}
}

func TestValidate_SecurityOverNonTLS_Warning(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{
				Backend: BackendConfig{TargetURL: "http://insecure-upstream.example.com"},
				Security: SecurityConfigs{
					{
						TokenRef:     "my_token",
						KMSKeyID:     "key-1",
						InjectHeader: "Authorization",
					},
				},
			}},
		},
	}
	err := cfg.Validate()
	if err != nil {
		t.Fatalf("Validate() should not error (warning only): %v", err)
	}
	if len(cfg.Warnings) == 0 {
		t.Error("expected security warning for credentials over non-TLS upstream")
	}
}

func TestValidate_SecurityOverTLS_NoWarning(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{
				Backend: BackendConfig{TargetURL: "https://secure-upstream.example.com"},
				Security: SecurityConfigs{
					{
						TokenRef:     "my_token",
						KMSKeyID:     "key-1",
						InjectHeader: "Authorization",
					},
				},
			}},
		},
	}
	err := cfg.Validate()
	if err != nil {
		t.Fatalf("Validate() error: %v", err)
	}
	if len(cfg.Warnings) != 0 {
		t.Errorf("expected no warnings for HTTPS upstream, got %v", cfg.Warnings)
	}
}

func TestLoad_TLSConfig(t *testing.T) {
	yaml := `
listen_addr: ":8443"
tls:
  cert_file: "/etc/csar/tls/cert.pem"
  key_file: "/etc/csar/tls/key.pem"
  client_ca_file: "/etc/csar/tls/ca.pem"
  min_version: "1.3"
paths:
  /api:
    get:
      x-csar-backend:
        target_url: "https://api.example.com"
        tls:
          insecure_skip_verify: true
          ca_file: "/etc/csar/upstream-ca.pem"
          cert_file: "/etc/csar/client-cert.pem"
          key_file: "/etc/csar/client-key.pem"
`
	path := writeTemp(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.TLS == nil {
		t.Fatal("TLS is nil, want non-nil")
	}
	if cfg.TLS.CertFile != "/etc/csar/tls/cert.pem" {
		t.Errorf("TLS.CertFile = %q", cfg.TLS.CertFile)
	}
	if cfg.TLS.KeyFile != "/etc/csar/tls/key.pem" {
		t.Errorf("TLS.KeyFile = %q", cfg.TLS.KeyFile)
	}
	if cfg.TLS.ClientCAFile != "/etc/csar/tls/ca.pem" {
		t.Errorf("TLS.ClientCAFile = %q", cfg.TLS.ClientCAFile)
	}
	if cfg.TLS.MinVersion != "1.3" {
		t.Errorf("TLS.MinVersion = %q, want 1.3", cfg.TLS.MinVersion)
	}

	// Check backend TLS
	route := cfg.Paths["/api"]["get"]
	if route.Backend.TLS == nil {
		t.Fatal("Backend.TLS is nil")
	}
	if !route.Backend.TLS.InsecureSkipVerify {
		t.Error("InsecureSkipVerify = false, want true")
	}
	if route.Backend.TLS.CAFile != "/etc/csar/upstream-ca.pem" {
		t.Errorf("Backend.TLS.CAFile = %q", route.Backend.TLS.CAFile)
	}
	if route.Backend.TLS.CertFile != "/etc/csar/client-cert.pem" {
		t.Errorf("Backend.TLS.CertFile = %q", route.Backend.TLS.CertFile)
	}
}

func TestFlatRoutes(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Paths: map[string]PathConfig{
			"/a": {
				"get":  RouteConfig{Backend: BackendConfig{TargetURL: "http://a"}},
				"post": RouteConfig{Backend: BackendConfig{TargetURL: "http://a"}},
			},
			"/b": {
				"get": RouteConfig{Backend: BackendConfig{TargetURL: "http://b"}},
			},
		},
	}

	flat := cfg.FlatRoutes()
	if len(flat) != 3 {
		t.Errorf("FlatRoutes() returned %d routes, want 3", len(flat))
	}

	// Verify all routes are present (order not guaranteed)
	found := make(map[string]bool)
	for _, fr := range flat {
		found[fr.Method+":"+fr.Path] = true
	}
	for _, want := range []string{"get:/a", "post:/a", "get:/b"} {
		if !found[want] {
			t.Errorf("FlatRoutes() missing %s", want)
		}
	}
}

func TestDuration_UnmarshalYAML(t *testing.T) {
	tests := []struct {
		yaml string
		want time.Duration
	}{
		{`max_wait: "30s"`, 30 * time.Second},
		{`max_wait: "5m"`, 5 * time.Minute},
		{`max_wait: "1h"`, time.Hour},
		{`max_wait: "500ms"`, 500 * time.Millisecond},
	}

	for _, tt := range tests {
		t.Run(tt.yaml, func(t *testing.T) {
			var v struct {
				MaxWait Duration `yaml:"max_wait"`
			}
			if err := unmarshalYAML([]byte(tt.yaml), &v); err != nil {
				t.Fatalf("unmarshal error: %v", err)
			}
			if v.MaxWait.Duration != tt.want {
				t.Errorf("Duration = %v, want %v", v.MaxWait.Duration, tt.want)
			}
		})
	}
}

func TestDuration_UnmarshalYAML_Invalid(t *testing.T) {
	var v struct {
		MaxWait Duration `yaml:"max_wait"`
	}
	err := unmarshalYAML([]byte(`max_wait: "not-a-duration"`), &v)
	if err == nil {
		t.Fatal("should fail for invalid duration")
	}
}

func TestValidate_Security_MissingTokenRef(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{
				Backend: BackendConfig{TargetURL: "https://api.example.com"},
				Security: SecurityConfigs{
					{
						KMSKeyID:     "key-1",
						TokenRef:     "", // missing!
						InjectHeader: "Authorization",
					},
				},
			}},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should fail when token_ref is empty")
	}
	if !containsStr(err.Error(), "token_ref") {
		t.Errorf("error should mention token_ref, got: %v", err)
	}
}

func TestValidate_Security_MissingInjectHeader(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{
				Backend: BackendConfig{TargetURL: "https://api.example.com"},
				Security: SecurityConfigs{
					{
						KMSKeyID:     "key-1",
						TokenRef:     "my_token",
						InjectHeader: "", // missing!
					},
				},
			}},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should fail when inject_header is empty")
	}
	if !containsStr(err.Error(), "inject_header") {
		t.Errorf("error should mention inject_header, got: %v", err)
	}
}

func TestValidate_Security_MissingKMSKeyID(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{
				Backend: BackendConfig{TargetURL: "https://api.example.com"},
				Security: SecurityConfigs{
					{
						KMSKeyID:     "", // missing!
						TokenRef:     "my_token",
						InjectHeader: "Authorization",
					},
				},
			}},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should fail when kms_key_id is empty")
	}
	if !containsStr(err.Error(), "kms_key_id") {
		t.Errorf("error should mention kms_key_id, got: %v", err)
	}
}

func TestValidate_Security_AllFieldsPresent_OK(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{
				Backend: BackendConfig{TargetURL: "https://api.example.com"},
				Security: SecurityConfigs{
					{
						KMSKeyID:     "key-1",
						TokenRef:     "my_token",
						InjectHeader: "Authorization",
						InjectFormat: "Bearer {token}",
					},
				},
			}},
		},
	}
	err := cfg.Validate()
	if err != nil {
		t.Fatalf("Validate() should pass with complete security config: %v", err)
	}
}

func TestValidate_Security_MultipleEntries_OK(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{
				Backend: BackendConfig{TargetURL: "https://api.example.com"},
				Security: SecurityConfigs{
					{
						KMSKeyID:     "key-1",
						TokenRef:     "bearer_token",
						InjectHeader: "Authorization",
						InjectFormat: "Bearer {token}",
					},
					{
						KMSKeyID:     "key-2",
						TokenRef:     "client_secret",
						InjectHeader: "X-Client-Secret",
						InjectFormat: "{token}",
					},
				},
			}},
		},
	}
	err := cfg.Validate()
	if err != nil {
		t.Fatalf("Validate() should pass with multiple security entries: %v", err)
	}
}

func TestHasSecureRoutes(t *testing.T) {
	// No security config
	cfg := &Config{
		ListenAddr: ":8080",
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{
				Backend: BackendConfig{TargetURL: "http://localhost"},
			}},
		},
	}
	if cfg.HasSecureRoutes() {
		t.Error("HasSecureRoutes() should be false with no security config")
	}

	// With security config
	cfg.Paths["/secure"] = PathConfig{
		"post": RouteConfig{
			Backend: BackendConfig{TargetURL: "https://api.example.com"},
			Security: SecurityConfigs{
				{
					KMSKeyID:     "key-1",
					TokenRef:     "tok",
					InjectHeader: "Authorization",
				},
			},
		},
	}
	if !cfg.HasSecureRoutes() {
		t.Error("HasSecureRoutes() should be true with security config")
	}
}

// ==========================================================================
// Coordinator config validation tests
// ==========================================================================

func TestValidate_Coordinator_EnabledMissingAddress(t *testing.T) {
	cfg := &Config{
		ListenAddr:  ":8080",
		Coordinator: CoordinatorConfig{Enabled: true}, // no address
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{Backend: BackendConfig{TargetURL: "http://localhost"}}},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should fail when coordinator.enabled but address is empty")
	}
	if !containsStr(err.Error(), "address") {
		t.Errorf("error should mention address, got: %v", err)
	}
}

func TestValidate_Coordinator_CertWithoutKey(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Coordinator: CoordinatorConfig{
			Enabled:  true,
			Address:  "localhost:9090",
			CAFile:   "/etc/ca.pem",
			CertFile: "/etc/client.pem",
			// KeyFile missing
		},
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{Backend: BackendConfig{TargetURL: "http://localhost"}}},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should fail when cert_file is set without key_file")
	}
	if !containsStr(err.Error(), "cert_file") && !containsStr(err.Error(), "key_file") {
		t.Errorf("error should mention cert/key, got: %v", err)
	}
}

func TestValidate_Coordinator_KeyWithoutCert(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Coordinator: CoordinatorConfig{
			Enabled: true,
			Address: "localhost:9090",
			CAFile:  "/etc/ca.pem",
			KeyFile: "/etc/client-key.pem",
			// CertFile missing
		},
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{Backend: BackendConfig{TargetURL: "http://localhost"}}},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should fail when key_file is set without cert_file")
	}
}

func TestValidate_Coordinator_mTLSWithoutCA(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Coordinator: CoordinatorConfig{
			Enabled:  true,
			Address:  "localhost:9090",
			CertFile: "/etc/client.pem",
			KeyFile:  "/etc/client-key.pem",
			// CAFile missing
		},
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{Backend: BackendConfig{TargetURL: "http://localhost"}}},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should fail when mTLS cert/key are set without ca_file")
	}
	if !containsStr(err.Error(), "ca_file") {
		t.Errorf("error should mention ca_file, got: %v", err)
	}
}

func TestValidate_Coordinator_NoTransportSecurity(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Coordinator: CoordinatorConfig{
			Enabled: true,
			Address: "localhost:9090",
			// No CAFile, no AllowInsecure
		},
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{Backend: BackendConfig{TargetURL: "http://localhost"}}},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should fail when no transport security is configured")
	}
	if !containsStr(err.Error(), "transport security") {
		t.Errorf("error should mention transport security, got: %v", err)
	}
}

func TestValidate_Coordinator_AllowInsecure_OK(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Coordinator: CoordinatorConfig{
			Enabled:       true,
			Address:       "localhost:9090",
			AllowInsecure: true,
		},
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{Backend: BackendConfig{TargetURL: "http://localhost"}}},
		},
	}
	err := cfg.Validate()
	if err != nil {
		t.Fatalf("Validate() should pass with allow_insecure: %v", err)
	}
}

func TestValidate_Coordinator_TLS_OK(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Coordinator: CoordinatorConfig{
			Enabled: true,
			Address: "localhost:9090",
			CAFile:  "/etc/csar/coordinator-ca.pem",
		},
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{Backend: BackendConfig{TargetURL: "http://localhost"}}},
		},
	}
	err := cfg.Validate()
	if err != nil {
		t.Fatalf("Validate() should pass with CA file: %v", err)
	}
}

func TestValidate_Coordinator_mTLS_OK(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Coordinator: CoordinatorConfig{
			Enabled:  true,
			Address:  "localhost:9090",
			CAFile:   "/etc/csar/coordinator-ca.pem",
			CertFile: "/etc/csar/client.pem",
			KeyFile:  "/etc/csar/client-key.pem",
		},
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{Backend: BackendConfig{TargetURL: "http://localhost"}}},
		},
	}
	err := cfg.Validate()
	if err != nil {
		t.Fatalf("Validate() should pass with full mTLS config: %v", err)
	}
}

func TestValidate_Coordinator_CAFileAndInsecure_Warning(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Coordinator: CoordinatorConfig{
			Enabled:       true,
			Address:       "localhost:9090",
			CAFile:        "/etc/csar/coordinator-ca.pem",
			AllowInsecure: true, // contradictory
		},
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{Backend: BackendConfig{TargetURL: "http://localhost"}}},
		},
	}
	err := cfg.Validate()
	if err != nil {
		t.Fatalf("Validate() should pass (warning, not error): %v", err)
	}
	if len(cfg.Warnings) == 0 {
		t.Error("expected warning for contradictory ca_file + allow_insecure")
	}
	foundWarning := false
	for _, w := range cfg.Warnings {
		if containsStr(w, "allow_insecure") && containsStr(w, "ca_file") {
			foundWarning = true
		}
	}
	if !foundWarning {
		t.Errorf("expected warning mentioning allow_insecure+ca_file, got: %v", cfg.Warnings)
	}
}

func TestValidate_Coordinator_Disabled_TLSFieldsWarning(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Coordinator: CoordinatorConfig{
			Enabled: false,
			CAFile:  "/etc/csar/coordinator-ca.pem",
		},
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{Backend: BackendConfig{TargetURL: "http://localhost"}}},
		},
	}
	err := cfg.Validate()
	if err != nil {
		t.Fatalf("Validate() should pass: %v", err)
	}
	if len(cfg.Warnings) == 0 {
		t.Error("expected warning for disabled coordinator with TLS fields")
	}
}

// ==========================================================================
// Profile enforcement tests (audit follow-up §1, §2)
// ==========================================================================

func TestValidate_Profile_UnknownProfile(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Profile:    "production-mega", // invalid
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{Backend: BackendConfig{TargetURL: "http://localhost"}}},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should fail for unknown profile")
	}
	if !containsStr(err.Error(), "unknown profile") {
		t.Errorf("error should mention unknown profile, got: %v", err)
	}
}

func TestValidate_Profile_DevLocal_AllowsEverything(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Profile:    "dev-local",
		Coordinator: CoordinatorConfig{
			AllowInsecure: true, // should be allowed
		},
		SecurityPolicy: &SecurityPolicyConfig{
			Environment: "dev",
		},
		KMS: &KMSConfig{
			Provider: "local",
		},
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{
				Backend: BackendConfig{TargetURL: "http://localhost"},
				Security: SecurityConfigs{
					{TokenRef: "tok", KMSKeyID: "key-1", InjectHeader: "Authorization"},
				},
			}},
		},
	}
	err := cfg.Validate()
	if err != nil {
		t.Fatalf("Validate() should pass for dev-local with relaxed settings: %v", err)
	}
}

func TestValidate_Profile_ProdSingle_RejectsInsecureCoordinator(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Profile:    "prod-single",
		Coordinator: CoordinatorConfig{
			AllowInsecure: true,
		},
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{Backend: BackendConfig{TargetURL: "http://localhost"}}},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should fail for prod-single with allow_insecure")
	}
	if !containsStr(err.Error(), "allow_insecure") {
		t.Errorf("error should mention allow_insecure, got: %v", err)
	}
}

func TestValidate_Profile_ProdSingle_RejectsDevEnvironment(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Profile:    "prod-single",
		SecurityPolicy: &SecurityPolicyConfig{
			Environment: "dev",
		},
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{Backend: BackendConfig{TargetURL: "http://localhost"}}},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should fail for prod-single with dev environment")
	}
	if !containsStr(err.Error(), "dev") {
		t.Errorf("error should mention dev, got: %v", err)
	}
}

func TestValidate_Profile_ProdSingle_RequiresTLSForSecureRoutes(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Profile:    "prod-single",
		// No TLS configured
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{
				Backend: BackendConfig{TargetURL: "https://api.example.com"},
				Security: SecurityConfigs{
					{TokenRef: "tok", KMSKeyID: "key-1", InjectHeader: "Authorization"},
				},
			}},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should fail for prod-single with secure routes but no TLS")
	}
	if !containsStr(err.Error(), "TLS") {
		t.Errorf("error should mention TLS, got: %v", err)
	}
}

func TestValidate_Profile_ProdSingle_RejectsLocalKMS(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Profile:    "prod-single",
		TLS:        &TLSConfig{CertFile: "cert.pem", KeyFile: "key.pem"},
		KMS: &KMSConfig{
			Provider: "local",
		},
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{
				Backend: BackendConfig{TargetURL: "https://api.example.com"},
				Security: SecurityConfigs{
					{TokenRef: "tok", KMSKeyID: "key-1", InjectHeader: "Authorization"},
				},
			}},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should fail for prod-single with local KMS and secure routes")
	}
	if !containsStr(err.Error(), "local") {
		t.Errorf("error should mention local, got: %v", err)
	}
}

func TestValidate_Profile_ProdSingle_PassesWithValidConfig(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Profile:    "prod-single",
		TLS:        &TLSConfig{CertFile: "cert.pem", KeyFile: "key.pem"},
		KMS: &KMSConfig{
			Provider: "yandexapi",
			Yandex:   &YandexKMSConfig{AuthMode: "metadata"},
		},
		SecurityPolicy: &SecurityPolicyConfig{
			Environment: "prod",
		},
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{
				Backend: BackendConfig{TargetURL: "https://api.example.com"},
				Security: SecurityConfigs{
					{TokenRef: "tok", KMSKeyID: "key-1", InjectHeader: "Authorization"},
				},
			}},
		},
	}
	err := cfg.Validate()
	if err != nil {
		t.Fatalf("Validate() should pass for valid prod-single config: %v", err)
	}
}

func TestValidate_Profile_ProdDistributed_RequiresCoordinatorEnabled(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Profile:    "prod-distributed",
		TLS:        &TLSConfig{CertFile: "cert.pem", KeyFile: "key.pem"},
		Coordinator: CoordinatorConfig{
			Enabled: false, // must be true
		},
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{Backend: BackendConfig{TargetURL: "http://localhost"}}},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should fail for prod-distributed without coordinator enabled")
	}
	if !containsStr(err.Error(), "coordinator") {
		t.Errorf("error should mention coordinator, got: %v", err)
	}
}

func TestValidate_Profile_ProdDistributed_RequiresCoordinatorAddress(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Profile:    "prod-distributed",
		TLS:        &TLSConfig{CertFile: "cert.pem", KeyFile: "key.pem"},
		Coordinator: CoordinatorConfig{
			Enabled: true,
			Address: "", // must be non-empty
			CAFile:  "/path/to/ca.pem",
		},
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{Backend: BackendConfig{TargetURL: "http://localhost"}}},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should fail for prod-distributed without coordinator address")
	}
}

func TestValidate_Profile_ProdDistributed_RequiresCoordinatorCA(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Profile:    "prod-distributed",
		TLS:        &TLSConfig{CertFile: "cert.pem", KeyFile: "key.pem"},
		Coordinator: CoordinatorConfig{
			Enabled: true,
			Address: "coord:9090",
			CAFile:  "", // must be non-empty
		},
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{Backend: BackendConfig{TargetURL: "http://localhost"}}},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should fail for prod-distributed without coordinator CA")
	}
	if !containsStr(err.Error(), "ca_file") {
		t.Errorf("error should mention ca_file, got: %v", err)
	}
}

func TestValidate_Profile_ProdDistributed_PassesWithValidConfig(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Profile:    "prod-distributed",
		TLS:        &TLSConfig{CertFile: "cert.pem", KeyFile: "key.pem"},
		KMS: &KMSConfig{
			Provider: "yandexapi",
			Yandex:   &YandexKMSConfig{AuthMode: "metadata"},
		},
		Coordinator: CoordinatorConfig{
			Enabled: true,
			Address: "coord:9090",
			CAFile:  "/path/to/ca.pem",
		},
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{
				Backend: BackendConfig{TargetURL: "https://api.example.com"},
				Security: SecurityConfigs{
					{TokenRef: "tok", KMSKeyID: "key-1", InjectHeader: "Authorization"},
				},
			}},
		},
	}
	err := cfg.Validate()
	if err != nil {
		t.Fatalf("Validate() should pass for valid prod-distributed config: %v", err)
	}
}

// ==========================================================================
// ValidateResolvedKMSProvider tests (audit follow-up §1)
// ==========================================================================

func TestValidateResolvedKMSProvider_NoProfile(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{
				Backend: BackendConfig{TargetURL: "https://api.example.com"},
				Security: SecurityConfigs{
					{TokenRef: "tok", KMSKeyID: "key-1", InjectHeader: "Authorization"},
				},
			}},
		},
	}
	// No profile — local should be fine
	if err := cfg.ValidateResolvedKMSProvider("local"); err != nil {
		t.Fatalf("should pass with no profile: %v", err)
	}
}

func TestValidateResolvedKMSProvider_DevLocal_AllowsLocal(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Profile:    "dev-local",
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{
				Backend: BackendConfig{TargetURL: "https://api.example.com"},
				Security: SecurityConfigs{
					{TokenRef: "tok", KMSKeyID: "key-1", InjectHeader: "Authorization"},
				},
			}},
		},
	}
	if err := cfg.ValidateResolvedKMSProvider("local"); err != nil {
		t.Fatalf("should pass for dev-local with local KMS: %v", err)
	}
}

func TestValidateResolvedKMSProvider_ProdSingle_RejectsLocal(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Profile:    "prod-single",
		TLS:        &TLSConfig{CertFile: "cert.pem", KeyFile: "key.pem"},
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{
				Backend: BackendConfig{TargetURL: "https://api.example.com"},
				Security: SecurityConfigs{
					{TokenRef: "tok", KMSKeyID: "key-1", InjectHeader: "Authorization"},
				},
			}},
		},
	}
	err := cfg.ValidateResolvedKMSProvider("local")
	if err == nil {
		t.Fatal("should fail for prod-single with resolved local KMS and secure routes")
	}
	if !containsStr(err.Error(), "local") {
		t.Errorf("error should mention local, got: %v", err)
	}
}

func TestValidateResolvedKMSProvider_ProdSingle_AllowsYandex(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Profile:    "prod-single",
		TLS:        &TLSConfig{CertFile: "cert.pem", KeyFile: "key.pem"},
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{
				Backend: BackendConfig{TargetURL: "https://api.example.com"},
				Security: SecurityConfigs{
					{TokenRef: "tok", KMSKeyID: "key-1", InjectHeader: "Authorization"},
				},
			}},
		},
	}
	if err := cfg.ValidateResolvedKMSProvider("yandexapi"); err != nil {
		t.Fatalf("should pass for prod-single with yandexapi: %v", err)
	}
}

func TestValidateResolvedKMSProvider_ProdSingle_LocalOK_NoSecureRoutes(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Profile:    "prod-single",
		TLS:        &TLSConfig{CertFile: "cert.pem", KeyFile: "key.pem"},
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{Backend: BackendConfig{TargetURL: "http://localhost"}}},
		},
	}
	// local KMS is only rejected when there are secure routes
	if err := cfg.ValidateResolvedKMSProvider("local"); err != nil {
		t.Fatalf("should pass when no secure routes exist: %v", err)
	}
}

func TestValidateResolvedKMSProvider_ProdDistributed_RejectsLocal(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Profile:    "prod-distributed",
		TLS:        &TLSConfig{CertFile: "cert.pem", KeyFile: "key.pem"},
		Coordinator: CoordinatorConfig{
			Enabled: true,
			Address: "coord:9090",
			CAFile:  "/path/to/ca.pem",
		},
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{
				Backend: BackendConfig{TargetURL: "https://api.example.com"},
				Security: SecurityConfigs{
					{TokenRef: "tok", KMSKeyID: "key-1", InjectHeader: "Authorization"},
				},
			}},
		},
	}
	err := cfg.ValidateResolvedKMSProvider("local")
	if err == nil {
		t.Fatal("should fail for prod-distributed with resolved local KMS and secure routes")
	}
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// --- helpers ---

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func unmarshalYAML(data []byte, v interface{}) error {
	return yamlPkg.Unmarshal(data, v)
}

// ==========================================================================
// insecure_skip_verify in prod tests
// ==========================================================================

func TestValidate_InsecureSkipVerify_Prod_Error(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		TLS: &TLSConfig{
			CertFile: "/etc/csar/cert.pem",
			KeyFile:  "/etc/csar/key.pem",
		},
		SecurityPolicy: &SecurityPolicyConfig{
			Environment:          "prod",
			ForbidInsecureInProd: true,
		},
		Paths: map[string]PathConfig{
			"/api": {"get": RouteConfig{
				Backend: BackendConfig{
					TargetURL: "https://upstream.example.com",
					TLS: &BackendTLSConfig{
						InsecureSkipVerify: true, // should be rejected in prod
					},
				},
			}},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should fail: insecure_skip_verify in prod with forbid_insecure_in_prod")
	}
	if !containsStr(err.Error(), "insecure_skip_verify") {
		t.Errorf("error should mention insecure_skip_verify, got: %v", err)
	}
}

func TestValidate_InsecureSkipVerify_NonProd_Warning(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		SecurityPolicy: &SecurityPolicyConfig{
			Environment: "stage",
		},
		Paths: map[string]PathConfig{
			"/api": {"get": RouteConfig{
				Backend: BackendConfig{
					TargetURL: "https://upstream.example.com",
					TLS: &BackendTLSConfig{
						InsecureSkipVerify: true, // warning only outside prod
					},
				},
			}},
		},
	}
	err := cfg.Validate()
	if err != nil {
		t.Fatalf("Validate() should pass in non-prod (warning only): %v", err)
	}
	if len(cfg.Warnings) == 0 {
		t.Error("expected warning for insecure_skip_verify on HTTPS upstream")
	}
}

// ==========================================================================
// safeExpandEnv tests (audit §1 — os.ExpandEnv bug)
// ==========================================================================

func TestSafeExpandEnv_PreservesBackReferences(t *testing.T) {
	// $1, $2 are regex back-references in path_rewrite — they must survive.
	input := `path_rewrite: "/users/$1/orders/$2"`
	result := safeExpandEnv(input)
	if result != input {
		t.Errorf("safeExpandEnv mangled back-references:\n  got:  %s\n  want: %s", result, input)
	}
}

func TestSafeExpandEnv_ExpandsRealEnvVars(t *testing.T) {
	t.Setenv("CSAR_TEST_DSN", "postgres://u:p@h:5432/db")
	input := `dsn: "${CSAR_TEST_DSN}"`
	want := `dsn: "postgres://u:p@h:5432/db"`
	result := safeExpandEnv(input)
	if result != want {
		t.Errorf("safeExpandEnv didn't expand env var:\n  got:  %s\n  want: %s", result, want)
	}
}

func TestSafeExpandEnv_MixedBackRefsAndEnvVars(t *testing.T) {
	t.Setenv("CSAR_TEST_HOST", "api.example.com")
	input := `target_url: "https://${CSAR_TEST_HOST}/users/$1"`
	want := `target_url: "https://api.example.com/users/$1"`
	result := safeExpandEnv(input)
	if result != want {
		t.Errorf("safeExpandEnv:\n  got:  %s\n  want: %s", result, want)
	}
}

func TestSafeExpandEnv_UndefinedEnvVar(t *testing.T) {
	// Undefined env vars expand to empty string (same as os.ExpandEnv).
	input := `value: "${CSAR_UNDEFINED_VAR_12345}"`
	want := `value: ""`
	result := safeExpandEnv(input)
	if result != want {
		t.Errorf("safeExpandEnv:\n  got:  %s\n  want: %s", result, want)
	}
}

func TestSafeExpandEnv_BracedDigitPreserved(t *testing.T) {
	// ${1} is parsed by os.Expand as variable "1" — our mapping returns "$1",
	// so the back-reference value is preserved even though braces are consumed.
	input := `path_rewrite: "/items/${1}/detail"`
	want := `path_rewrite: "/items/$1/detail"`
	result := safeExpandEnv(input)
	if result != want {
		t.Errorf("safeExpandEnv:\n  got:  %s\n  want: %s", result, want)
	}
}

func TestLoad_EnvVarExpansion_PostUnmarshal(t *testing.T) {
	t.Setenv("CSAR_TEST_TARGET_URL", "https://api.example.com/v2")
	t.Setenv("CSAR_TEST_LISTEN", ":9090")
	yamlStr := `
listen_addr: "${CSAR_TEST_LISTEN}"
paths:
  /api:
    get:
      x-csar-backend:
        target_url: "${CSAR_TEST_TARGET_URL}"
      x-csar-headers:
        X-Custom: "prefix-${CSAR_TEST_LISTEN}-suffix"
`
	path := writeTemp(t, yamlStr)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.ListenAddr != ":9090" {
		t.Errorf("ListenAddr = %q, want env-expanded %q", cfg.ListenAddr, ":9090")
	}

	route := cfg.Paths["/api"]["get"]
	if route.Backend.TargetURL != "https://api.example.com/v2" {
		t.Errorf("TargetURL = %q, want env-expanded value", route.Backend.TargetURL)
	}
	wantHeader := "prefix-:9090-suffix"
	if route.Headers["X-Custom"] != wantHeader {
		t.Errorf("Header X-Custom = %q, want %q", route.Headers["X-Custom"], wantHeader)
	}
}

func TestLoad_YAMLInjection_Safe(t *testing.T) {
	// Set an env var containing YAML control characters.
	// With pre-unmarshal expansion, this would corrupt the YAML structure.
	// With post-unmarshal expansion, it is safely contained in the string field.
	t.Setenv("CSAR_TEST_EVIL", "value\"\nmalicious_field: true")
	yamlStr := `
listen_addr: ":8080"
paths:
  /api:
    get:
      x-csar-backend:
        target_url: "https://api.example.com"
      x-csar-headers:
        X-Custom: "${CSAR_TEST_EVIL}"
`
	path := writeTemp(t, yamlStr)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	route := cfg.Paths["/api"]["get"]
	got := route.Headers["X-Custom"]
	want := "value\"\nmalicious_field: true"
	if got != want {
		t.Errorf("Header value = %q, want %q (env var should be safely injected post-unmarshal)", got, want)
	}

	// Verify the malicious field did NOT create a new config key.
	if cfg.ListenAddr != ":8080" {
		t.Errorf("ListenAddr = %q, want %q (should not be altered by injection)", cfg.ListenAddr, ":8080")
	}
}

func TestExpandEnvInStruct_StringFields(t *testing.T) {
	t.Setenv("CSAR_TEST_ADDR", "localhost:9090")
	t.Setenv("CSAR_TEST_URL", "https://backend.local")

	cfg := &Config{
		ListenAddr: "${CSAR_TEST_ADDR}",
		Paths: map[string]PathConfig{
			"/test": {
				"get": RouteConfig{
					Backend: BackendConfig{
						TargetURL:   "${CSAR_TEST_URL}",
						PathRewrite: "/users/$1", // back-reference must survive
					},
				},
			},
		},
	}

	expandEnvInStruct(reflect.ValueOf(cfg).Elem())

	if cfg.ListenAddr != "localhost:9090" {
		t.Errorf("ListenAddr = %q, want %q", cfg.ListenAddr, "localhost:9090")
	}

	route := cfg.Paths["/test"]["get"]
	if route.Backend.TargetURL != "https://backend.local" {
		t.Errorf("TargetURL = %q, want %q", route.Backend.TargetURL, "https://backend.local")
	}
	if route.Backend.PathRewrite != "/users/$1" {
		t.Errorf("PathRewrite = %q, want %q (back-reference mangled)", route.Backend.PathRewrite, "/users/$1")
	}
}

func TestExpandEnvInStruct_SecretFields(t *testing.T) {
	t.Setenv("CSAR_TEST_SECRET", "s3cret-password")

	cfg := &Config{
		Redis: &RedisConfig{
			Address:  "localhost:6379",
			Password: logging.NewSecret("${CSAR_TEST_SECRET}"),
		},
	}

	expandEnvInStruct(reflect.ValueOf(cfg).Elem())

	if cfg.Redis.Password.Plaintext() != "s3cret-password" {
		t.Errorf("Redis.Password = %q, want env-expanded value", cfg.Redis.Password.Plaintext())
	}
}

func TestExpandEnvInStruct_SliceFields(t *testing.T) {
	t.Setenv("CSAR_TEST_HOST1", "host1.example.com")
	t.Setenv("CSAR_TEST_HOST2", "host2.example.com")

	cfg := &Config{
		Paths: map[string]PathConfig{
			"/test": {
				"get": RouteConfig{
					Backend: BackendConfig{
						TargetURL: "https://primary.example.com",
						Targets:   []string{"https://${CSAR_TEST_HOST1}", "https://${CSAR_TEST_HOST2}"},
					},
				},
			},
		},
	}

	expandEnvInStruct(reflect.ValueOf(cfg).Elem())

	route := cfg.Paths["/test"]["get"]
	if route.Backend.Targets[0] != "https://host1.example.com" {
		t.Errorf("Targets[0] = %q, want expanded", route.Backend.Targets[0])
	}
	if route.Backend.Targets[1] != "https://host2.example.com" {
		t.Errorf("Targets[1] = %q, want expanded", route.Backend.Targets[1])
	}
}

func TestLoad_PathRewrite_BackReferencesPreserved(t *testing.T) {
	yamlStr := `
listen_addr: ":8080"
paths:
  /api/v1/users/{id:[0-9]+}:
    get:
      x-csar-backend:
        target_url: "https://users.internal"
        path_rewrite: "/users/$1"
`
	path := writeTemp(t, yamlStr)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	for _, methods := range cfg.Paths {
		for _, route := range methods {
			if route.Backend.PathRewrite != "/users/$1" {
				t.Errorf("path_rewrite = %q, want %q (back-reference mangled by env expansion)",
					route.Backend.PathRewrite, "/users/$1")
			}
			return
		}
	}
	t.Fatal("no route found in config")
}

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

// ==========================================================================
// Path Mode tests (Feature C)
// ==========================================================================

func TestValidate_PathMode_Invalid(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{
				Backend: BackendConfig{
					TargetURL: "https://api.example.com",
					PathMode:  "forward", // invalid
				},
			}},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should fail for unknown path_mode")
	}
	if !containsStr(err.Error(), "path_mode") {
		t.Errorf("error should mention path_mode, got: %v", err)
	}
	if !containsStr(err.Error(), "forward") {
		t.Errorf("error should mention the invalid value, got: %v", err)
	}
}

func TestValidate_PathMode_Replace(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{
				Backend: BackendConfig{
					TargetURL: "https://api.example.com",
					PathMode:  "replace",
				},
			}},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() should pass for path_mode=replace: %v", err)
	}
}

func TestValidate_PathMode_Append(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{
				Backend: BackendConfig{
					TargetURL: "https://api.example.com",
					PathMode:  "append",
				},
			}},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() should pass for path_mode=append: %v", err)
	}
}

func TestValidate_PathMode_Empty_OK(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{
				Backend: BackendConfig{
					TargetURL: "https://api.example.com",
					// PathMode: "" — default, should be fine
				},
			}},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() should pass with empty path_mode: %v", err)
	}
}

func TestBackendConfig_IsAppendPathMode(t *testing.T) {
	tests := []struct {
		mode string
		want bool
	}{
		{"append", true},
		{"APPEND", true},
		{"Append", true},
		{"replace", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			bc := BackendConfig{PathMode: tt.mode}
			if got := bc.IsAppendPathMode(); got != tt.want {
				t.Errorf("IsAppendPathMode(%q) = %v, want %v", tt.mode, got, tt.want)
			}
		})
	}
}

func TestLoad_PathMode_FromYAML(t *testing.T) {
	yamlStr := `
listen_addr: ":8080"
paths:
  /api/v1/products:
    get:
      x-csar-backend:
        target_url: "https://api.example.com/v1/products"
        path_mode: "replace"
  /api/proxy:
    get:
      x-csar-backend:
        target_url: "https://internal-api.local/v2"
        path_mode: "append"
`
	path := writeTemp(t, yamlStr)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	replaceRoute := cfg.Paths["/api/v1/products"]["get"]
	if replaceRoute.Backend.PathMode != "replace" {
		t.Errorf("PathMode = %q, want %q", replaceRoute.Backend.PathMode, "replace")
	}

	appendRoute := cfg.Paths["/api/proxy"]["get"]
	if appendRoute.Backend.PathMode != "append" {
		t.Errorf("PathMode = %q, want %q", appendRoute.Backend.PathMode, "append")
	}
}
