package configsource

import (
	"testing"
	"time"

	"github.com/ledatu/csar-core/configutil"
	"github.com/ledatu/csar/internal/config"
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

	if entry.ID != "GET:/api/v1/users" {
		t.Errorf("ID = %q, want %q", entry.ID, "GET:/api/v1/users")
	}
	if entry.Path != "/api/v1/users" {
		t.Errorf("Path = %q, want %q", entry.Path, "/api/v1/users")
	}
	if entry.Method != "GET" {
		t.Errorf("Method = %q, want %q", entry.Method, "GET")
	}

	// Full route config is now carried through.
	if entry.Route.Backend.TargetURL != "https://primary.example.com" {
		t.Errorf("Backend.TargetURL = %q, want explicit TargetURL", entry.Route.Backend.TargetURL)
	}
	if len(entry.Route.Security) != 2 {
		t.Fatalf("Security count = %d, want 2", len(entry.Route.Security))
	}
	if entry.Route.Security[0].KMSKeyID != "key-1" {
		t.Errorf("Security[0].KMSKeyID = %q, want %q", entry.Route.Security[0].KMSKeyID, "key-1")
	}
	if entry.Route.Security[1].InjectHeader != "X-Client-Secret" {
		t.Errorf("Security[1].InjectHeader = %q, want %q", entry.Route.Security[1].InjectHeader, "X-Client-Secret")
	}
	if entry.Route.Traffic == nil {
		t.Fatal("Traffic should be set")
	}
	if entry.Route.Traffic.RPS != 100 {
		t.Errorf("Traffic.RPS = %v, want 100", entry.Route.Traffic.RPS)
	}
	if entry.Route.Traffic.Burst != 50 {
		t.Errorf("Traffic.Burst = %v, want 50", entry.Route.Traffic.Burst)
	}
	if entry.Route.Traffic.Backend != "redis" {
		t.Errorf("Traffic.Backend = %q, want redis", entry.Route.Traffic.Backend)
	}
	if entry.Route.Traffic.Key != "per-ip" {
		t.Errorf("Traffic.Key = %q, want per-ip", entry.Route.Traffic.Key)
	}
	if entry.Route.Resilience == nil || entry.Route.Resilience.CircuitBreaker != "aggressive" {
		t.Errorf("Resilience.CircuitBreaker = %v, want aggressive", entry.Route.Resilience)
	}
	if entry.Route.Headers["X-Custom"] != "value" {
		t.Errorf("Headers[X-Custom] = %q, want value", entry.Route.Headers["X-Custom"])
	}
	if entry.Route.Retry == nil {
		t.Error("Retry should be set")
	}
	if entry.Route.CORS == nil {
		t.Error("CORS should be set")
	}
	if entry.Route.Cache == nil {
		t.Error("Cache should be set")
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
	if len(entry.Route.Backend.Targets) != 2 {
		t.Errorf("Targets count = %d, want 2", len(entry.Route.Backend.Targets))
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
	if len(entry.Route.Security) != 0 {
		t.Error("Security should be empty for routes without security config")
	}
	if entry.Route.Traffic != nil {
		t.Error("Traffic should be nil for routes without traffic config")
	}
	if entry.Route.Resilience != nil {
		t.Error("Resilience should be nil for routes without resilience config")
	}
}

func TestConfigToRouteEntries_AllFieldsPropagated(t *testing.T) {
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
					AuthValidate:    &config.AuthValidateConfig{JWKSURL: "https://auth.example.com/.well-known/jwks.json"},
					Access:          &config.AccessControlConfig{AllowCIDRs: []string{"10.0.0.0/8"}},
					Retry:           &config.RetryConfig{MaxAttempts: 3},
					Redact:          &config.RedactConfig{Fields: []string{"email"}},
					Tenant:          &config.TenantConfig{Header: "X-Tenant-ID"},
					CORS:            &config.CORSConfig{AllowedOrigins: []string{"*"}},
					Cache:           &config.CacheConfig{},
					MaxResponseSize: 1024,
					Protocol:        &config.ProtocolPolicy{EmitWaitMS: &trueVal},
				},
			},
		},
	}

	entries := ConfigToRouteEntries(cfg)
	entry := entries["GET:/full"]

	if entry.Route.Backend.TargetURL != "https://target.example.com" {
		t.Errorf("TargetURL = %q", entry.Route.Backend.TargetURL)
	}
	if len(entry.Route.Security) != 1 {
		t.Fatalf("Security count = %d, want 1", len(entry.Route.Security))
	}
	if entry.Route.Security[0].OnKMSError != "serve_stale" {
		t.Errorf("OnKMSError = %q, want serve_stale", entry.Route.Security[0].OnKMSError)
	}
	if entry.Route.Headers["X-H"] != "val" {
		t.Errorf("Headers[X-H] = %q", entry.Route.Headers["X-H"])
	}
	if entry.Route.AuthValidate == nil {
		t.Error("AuthValidate should be set")
	}
	if entry.Route.Access == nil || len(entry.Route.Access.AllowCIDRs) != 1 {
		t.Error("Access should have 1 CIDR")
	}
	if entry.Route.Retry == nil || entry.Route.Retry.MaxAttempts != 3 {
		t.Error("Retry.MaxAttempts should be 3")
	}
	if entry.Route.Redact == nil || len(entry.Route.Redact.Fields) != 1 {
		t.Error("Redact should have 1 field")
	}
	if entry.Route.Tenant == nil || entry.Route.Tenant.Header != "X-Tenant-ID" {
		t.Error("Tenant.Header should be X-Tenant-ID")
	}
	if entry.Route.CORS == nil || len(entry.Route.CORS.AllowedOrigins) != 1 {
		t.Error("CORS should have 1 origin")
	}
	if entry.Route.MaxResponseSize != 1024 {
		t.Errorf("MaxResponseSize = %d, want 1024", entry.Route.MaxResponseSize)
	}
	if entry.Route.Protocol == nil || entry.Route.Protocol.EmitWaitMS == nil || !*entry.Route.Protocol.EmitWaitMS {
		t.Error("Protocol.EmitWaitMS should be true")
	}
}
