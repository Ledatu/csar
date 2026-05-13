package config

import (
	"testing"
	"time"
)

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

func TestValidate_CacheRedisRequiresTopLevelRedis(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Paths: map[string]PathConfig{
			"/analytics": {"get": RouteConfig{
				Backend: BackendConfig{TargetURL: "http://localhost"},
				Cache:   &CacheConfig{Store: "redis"},
			}},
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() should fail when redis cache has no top-level redis config")
	}
}

func TestValidate_AuthenticatedCacheRequiresAuthBoundary(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Paths: map[string]PathConfig{
			"/analytics": {"get": RouteConfig{
				Backend:      BackendConfig{TargetURL: "http://localhost"},
				AuthValidate: &AuthValidateConfig{JWKSURL: "http://authn/.well-known/jwks.json"},
				Cache:        &CacheConfig{Key: "analytics:{query.marketplace}"},
			}},
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() should fail when authenticated cache key lacks tenant or subject")
	}

	cfg.Paths["/analytics"]["get"] = RouteConfig{
		Backend:      BackendConfig{TargetURL: "http://localhost"},
		AuthValidate: &AuthValidateConfig{JWKSURL: "http://authn/.well-known/jwks.json"},
		Cache:        &CacheConfig{Key: "analytics:{tenant}:{query.marketplace}"},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() unexpected error with tenant boundary: %v", err)
	}
}

func TestValidate_CacheInvalidationRequiresTags(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Paths: map[string]PathConfig{
			"/skus/{sku_id}": {"patch": RouteConfig{
				Backend:         BackendConfig{TargetURL: "http://localhost"},
				CacheInvalidate: &CacheInvalidationConfig{},
			}},
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() should fail when cache invalidation has no tags")
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

func TestValidate_AuthValidateJWT_UnknownJWKSTLSPolicy(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Paths: map[string]PathConfig{
			"/svc/test": {
				"get": RouteConfig{
					Backend: BackendConfig{TargetURL: "https://upstream.example.com"},
					AuthValidate: &AuthValidateConfig{
						Mode:    "jwt",
						JWKSURL: "https://auth.example.com/.well-known/jwks.json",
						JWKSTLS: "missing-policy",
					},
				},
			},
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should fail for undefined jwks_tls policy")
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

func TestValidate_Security_MissingKMSKeyID_OKForPassthrough(t *testing.T) {
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
	if err != nil {
		t.Fatalf("Validate() should allow empty kms_key_id for passthrough tokens: %v", err)
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
// Path Mode validate tests
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

func TestValidate_BackendPoolUnknown(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{
				Backend: BackendConfig{
					TargetURL: "https://api.example.com",
					Pool:      "missing",
				},
			}},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should fail for unknown backend pool")
	}
	if !containsStr(err.Error(), "backend_pools") || !containsStr(err.Error(), "missing") {
		t.Errorf("error should mention missing backend pool, got: %v", err)
	}
}

func TestValidate_BackendPoolAndTimeout(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		BackendPools: map[string]BackendPoolConfig{
			"identity-critical": {
				MaxIdleConns:          64,
				MaxIdleConnsPerHost:   16,
				MaxConnsPerHost:       64,
				DialTimeout:           Duration{Duration: 300 * time.Millisecond},
				TLSHandshakeTimeout:   Duration{Duration: 500 * time.Millisecond},
				ResponseHeaderTimeout: Duration{Duration: 800 * time.Millisecond},
				IdleConnTimeout:       Duration{Duration: 30 * time.Second},
				ExpectContinueTimeout: Duration{Duration: time.Second},
			},
		},
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{
				Backend: BackendConfig{
					TargetURL: "https://api.example.com",
					Pool:      "identity-critical",
					Timeout:   Duration{Duration: 1200 * time.Millisecond},
				},
			}},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() should pass for configured backend pool and timeout: %v", err)
	}
}

func TestValidate_BackendPoolRejectsNegativeValues(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		BackendPools: map[string]BackendPoolConfig{
			"bad": {MaxConnsPerHost: -1},
		},
		Paths: map[string]PathConfig{
			"/test": {"get": RouteConfig{Backend: BackendConfig{TargetURL: "http://localhost"}}},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() should fail for negative backend pool values")
	}
	if !containsStr(err.Error(), "max_conns_per_host") {
		t.Errorf("error should mention max_conns_per_host, got: %v", err)
	}
}

// containsStr is a helper shared across validate tests.
func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
