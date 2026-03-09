package configsource

import (
	"testing"
	"time"

	"github.com/Ledatu/csar-core/configutil"
	"github.com/ledatu/csar/internal/config"
	"github.com/ledatu/csar/internal/statestore"
)

func TestConfigToRouteEntries_FullParity(t *testing.T) {
	cfg := &config.Config{
		Paths: map[string]config.PathConfig{
			"/api/v1/users": {
				"get": config.RouteConfig{
					Backend: config.BackendConfig{
						TargetURL:    "https://primary.example.com",
						Targets:      []string{"https://secondary.example.com"},
						LoadBalancer: "round_robin",
						PathRewrite:  "/users",
						PathMode:     "replace",
					},
					Security: config.SecurityConfigs{
						{
							KMSKeyID:     "key-1",
							TokenRef:     "tok-a",
							InjectHeader: "Authorization",
							InjectFormat: "Bearer {token}",
							OnKMSError:   "fail_closed",
						},
						{
							KMSKeyID:     "key-2",
							TokenRef:     "tok-b",
							InjectHeader: "X-Client-Secret",
							InjectFormat: "{token}",
						},
					},
					Headers: map[string]string{
						"X-Custom": "value",
					},
					Traffic: &config.TrafficConfig{
						RPS:   100,
						Burst: 50,
						MaxWait: configutil.Duration{
							Duration: 5 * time.Second,
						},
						Backend:    "redis",
						Key:        "per-ip",
						ExcludeIPs: []string{"10.0.0.0/8"},
					},
					Resilience: &config.ResilienceConfig{
						CircuitBreaker: "aggressive",
					},
					Retry: &config.RetryConfig{},
					CORS:  &config.CORSConfig{},
					Cache: &config.CacheConfig{},
				},
			},
		},
	}

	entries := ConfigToRouteEntries(cfg)

	entry, ok := entries["GET:/api/v1/users"]
	if !ok {
		t.Fatal("expected route GET:/api/v1/users")
	}

	// Propagated fields
	if entry.ID != "GET:/api/v1/users" {
		t.Errorf("ID = %q, want %q", entry.ID, "GET:/api/v1/users")
	}
	if entry.Path != "/api/v1/users" {
		t.Errorf("Path = %q, want %q", entry.Path, "/api/v1/users")
	}
	if entry.Method != "GET" {
		t.Errorf("Method = %q, want %q", entry.Method, "GET")
	}
	if entry.TargetURL != "https://primary.example.com" {
		t.Errorf("TargetURL = %q, want explicit TargetURL", entry.TargetURL)
	}
	if entry.Security == nil {
		t.Fatal("Security should be set (first credential)")
	}
	if entry.Security.KMSKeyID != "key-1" {
		t.Errorf("Security.KMSKeyID = %q, want %q", entry.Security.KMSKeyID, "key-1")
	}
	if entry.Security.TokenRef != "tok-a" {
		t.Errorf("Security.TokenRef = %q, want %q", entry.Security.TokenRef, "tok-a")
	}
	if entry.Security.InjectHeader != "Authorization" {
		t.Errorf("Security.InjectHeader = %q, want %q", entry.Security.InjectHeader, "Authorization")
	}
	if entry.Security.InjectFormat != "Bearer {token}" {
		t.Errorf("Security.InjectFormat = %q, want %q", entry.Security.InjectFormat, "Bearer {token}")
	}
	if entry.Traffic == nil {
		t.Fatal("Traffic should be set")
	}
	if entry.Traffic.RPS != 100 {
		t.Errorf("Traffic.RPS = %v, want 100", entry.Traffic.RPS)
	}
	if entry.Traffic.Burst != 50 {
		t.Errorf("Traffic.Burst = %v, want 50", entry.Traffic.Burst)
	}
	if entry.Traffic.MaxWait != 5*time.Second {
		t.Errorf("Traffic.MaxWait = %v, want 5s", entry.Traffic.MaxWait)
	}
	if entry.ResilienceProfile != "aggressive" {
		t.Errorf("ResilienceProfile = %q, want %q", entry.ResilienceProfile, "aggressive")
	}
}

func TestConfigToRouteEntries_FallbackToFirstTarget(t *testing.T) {
	cfg := &config.Config{
		Paths: map[string]config.PathConfig{
			"/lb": {
				"post": config.RouteConfig{
					Backend: config.BackendConfig{
						Targets: []string{"https://a.example.com", "https://b.example.com"},
					},
				},
			},
		},
	}

	entries := ConfigToRouteEntries(cfg)
	entry := entries["POST:/lb"]
	if entry.TargetURL != "https://a.example.com" {
		t.Errorf("TargetURL = %q, want first target", entry.TargetURL)
	}
}

func TestConfigToRouteEntries_NoSecurity(t *testing.T) {
	cfg := &config.Config{
		Paths: map[string]config.PathConfig{
			"/open": {
				"get": config.RouteConfig{
					Backend: config.BackendConfig{TargetURL: "https://open.example.com"},
				},
			},
		},
	}

	entries := ConfigToRouteEntries(cfg)
	entry := entries["GET:/open"]
	if entry.Security != nil {
		t.Error("Security should be nil for routes without security config")
	}
	if entry.Traffic != nil {
		t.Error("Traffic should be nil for routes without traffic config")
	}
	if entry.ResilienceProfile != "" {
		t.Error("ResilienceProfile should be empty for routes without resilience config")
	}
}

func TestConfigToRouteEntries_IntentionallyExcludedFields(t *testing.T) {
	trueVal := true
	cfg := &config.Config{
		Paths: map[string]config.PathConfig{
			"/full": {
				"get": config.RouteConfig{
					Backend: config.BackendConfig{
						TargetURL: "https://target.example.com",
					},
					Security: config.SecurityConfigs{
						{
							KMSKeyID:         "key-1",
							TokenRef:         "tok",
							InjectHeader:     "Authorization",
							InjectFormat:     "Bearer {token}",
							OnKMSError:       "serve_stale",
							StripTokenParams: &trueVal,
							TokenVersion:     "v2",
						},
					},
					Headers:         map[string]string{"X-H": "val"},
					AuthValidate:    &config.AuthValidateConfig{},
					Access:          &config.AccessControlConfig{},
					Retry:           &config.RetryConfig{},
					Redact:          &config.RedactConfig{},
					Tenant:          &config.TenantConfig{},
					CORS:            &config.CORSConfig{},
					Cache:           &config.CacheConfig{},
					MaxResponseSize: 1024,
					Protocol:        &config.ProtocolPolicy{},
				},
			},
		},
	}

	entries := ConfigToRouteEntries(cfg)
	entry := entries["GET:/full"]

	// These are the only fields we expect in the statestore entry.
	want := statestore.RouteEntry{
		ID:        "GET:/full",
		Path:      "/full",
		Method:    "GET",
		TargetURL: "https://target.example.com",
		Security: &statestore.SecurityEntry{
			KMSKeyID:     "key-1",
			TokenRef:     "tok",
			InjectHeader: "Authorization",
			InjectFormat: "Bearer {token}",
		},
	}

	if entry.ID != want.ID {
		t.Errorf("ID = %q, want %q", entry.ID, want.ID)
	}
	if entry.TargetURL != want.TargetURL {
		t.Errorf("TargetURL = %q, want %q", entry.TargetURL, want.TargetURL)
	}
	if entry.Security.KMSKeyID != want.Security.KMSKeyID {
		t.Errorf("Security.KMSKeyID = %q, want %q", entry.Security.KMSKeyID, want.Security.KMSKeyID)
	}
	if entry.Traffic != nil {
		t.Error("Traffic should be nil (not configured)")
	}
	if entry.ResilienceProfile != "" {
		t.Error("ResilienceProfile should be empty (not configured)")
	}
}
