package config

import (
	"strings"
	"testing"
	"time"

	yamlPkg "gopkg.in/yaml.v3"
)

// ---------------------------------------------------------------------------
// Throttle policy tests
// ---------------------------------------------------------------------------

func TestLoad_ThrottlePolicyBareStringRef(t *testing.T) {
	yaml := `
listen_addr: ":8080"

throttling_policies:
  standard-api:
    rate: 10
    burst: 20
    max_wait: "500ms"

paths:
  /api/v1/products:
    get:
      x-csar-backend:
        target_url: "https://api.example.com/products"
      x-csar-traffic: "standard-api"
`
	path := writeTemp(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	traffic := cfg.Paths["/api/v1/products"]["get"].Traffic
	if traffic == nil {
		t.Fatal("traffic should not be nil after policy resolution")
	}
	if traffic.RPS != 10 {
		t.Errorf("RPS = %v, want 10", traffic.RPS)
	}
	if traffic.Burst != 20 {
		t.Errorf("Burst = %v, want 20", traffic.Burst)
	}
	if traffic.MaxWait.Duration != 500*time.Millisecond {
		t.Errorf("MaxWait = %v, want 500ms", traffic.MaxWait.Duration)
	}
	if traffic.Use != "" {
		t.Errorf("Use = %q, should be empty after resolution", traffic.Use)
	}
}

func TestLoad_ThrottlePolicyUseWithOverride(t *testing.T) {
	yaml := `
listen_addr: ":8080"

throttling_policies:
  heavy-task:
    rate: 0.5
    burst: 1
    max_wait: "30s"

paths:
  /api/v1/reports:
    post:
      x-csar-backend:
        target_url: "https://reports.example.com"
      x-csar-traffic:
        use: "heavy-task"
        max_wait: "60s"
`
	path := writeTemp(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	traffic := cfg.Paths["/api/v1/reports"]["post"].Traffic
	if traffic == nil {
		t.Fatal("traffic should not be nil")
	}
	if traffic.RPS != 0.5 {
		t.Errorf("RPS = %v, want 0.5 (from policy)", traffic.RPS)
	}
	if traffic.MaxWait.Duration != 60*time.Second {
		t.Errorf("MaxWait = %v, want 60s (inline override)", traffic.MaxWait.Duration)
	}
}

func TestLoad_ThrottlePolicyUnknownRef(t *testing.T) {
	yaml := `
listen_addr: ":8080"

paths:
  /api/v1/products:
    get:
      x-csar-backend:
        target_url: "https://api.example.com/products"
      x-csar-traffic: "nonexistent-policy"
`
	path := writeTemp(t, yaml)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for unknown policy reference")
	}
	if !strings.Contains(err.Error(), "nonexistent-policy") {
		t.Errorf("error should mention policy name, got: %v", err)
	}
}

func TestLoad_GlobalThrottle(t *testing.T) {
	yaml := `
listen_addr: ":8080"

global_throttle:
  rate: 1000
  burst: 2000
  max_wait: "0s"

paths:
  /api/v1/products:
    get:
      x-csar-backend:
        target_url: "https://api.example.com/products"
`
	path := writeTemp(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.GlobalThrottle == nil {
		t.Fatal("GlobalThrottle should not be nil")
	}
	if cfg.GlobalThrottle.RPS != 1000 {
		t.Errorf("RPS = %v, want 1000", cfg.GlobalThrottle.RPS)
	}
	if cfg.GlobalThrottle.Burst != 2000 {
		t.Errorf("Burst = %v, want 2000", cfg.GlobalThrottle.Burst)
	}
}

func TestLoad_GlobalThrottle_InvalidRate(t *testing.T) {
	yaml := `
listen_addr: ":8080"

global_throttle:
  rate: 0
  burst: 2000

paths:
  /api/v1/products:
    get:
      x-csar-backend:
        target_url: "https://api.example.com/products"
`
	path := writeTemp(t, yaml)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid global_throttle.rate")
	}
	if !strings.Contains(err.Error(), "global_throttle.rate") {
		t.Errorf("error should mention global_throttle.rate, got: %v", err)
	}
}

func TestLoad_ThrottlePolicyWithDynamicKey(t *testing.T) {
	yaml := `
listen_addr: ":8080"

redis:
  address: "redis.internal:6379"
  key_prefix: "csar:rl:"

throttling_policies:
  per-seller:
    rate: 5
    burst: 10
    max_wait: "10s"
    backend: "redis"
    key: "seller:{query.seller_id}"

paths:
  /api/v1/orders:
    get:
      x-csar-backend:
        target_url: "https://orders.example.com"
      x-csar-traffic: "per-seller"
`
	path := writeTemp(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	traffic := cfg.Paths["/api/v1/orders"]["get"].Traffic
	if traffic == nil {
		t.Fatal("traffic should not be nil")
	}
	if traffic.Key != "seller:{query.seller_id}" {
		t.Errorf("Key = %q, want %q", traffic.Key, "seller:{query.seller_id}")
	}
	if traffic.Backend != "redis" {
		t.Errorf("Backend = %q, want %q", traffic.Backend, "redis")
	}
}

func TestLoad_DynamicKeyRequiresRedisBackend(t *testing.T) {
	yaml := `
listen_addr: ":8080"

paths:
  /api/v1/orders:
    get:
      x-csar-backend:
        target_url: "https://orders.example.com"
      x-csar-traffic:
        rps: 5
        burst: 10
        max_wait: "10s"
        key: "seller:{query.seller_id}"
        backend: "local"
`
	path := writeTemp(t, yaml)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error when dynamic key is used with non-redis backend")
	}
	if !strings.Contains(err.Error(), "requires backend") {
		t.Errorf("error should mention backend requirement, got: %v", err)
	}
}

func TestLoad_ThrottlePolicyExcludeIPs(t *testing.T) {
	yaml := `
listen_addr: ":8080"

paths:
  /api/v1/products:
    get:
      x-csar-backend:
        target_url: "https://api.example.com/products"
      x-csar-traffic:
        rps: 10
        burst: 20
        max_wait: "500ms"
        exclude_ips:
          - "10.0.0.0/8"
          - "192.168.1.100"
`
	path := writeTemp(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	traffic := cfg.Paths["/api/v1/products"]["get"].Traffic
	if len(traffic.ExcludeIPs) != 2 {
		t.Errorf("ExcludeIPs length = %d, want 2", len(traffic.ExcludeIPs))
	}
}

func TestLoad_ThrottlePolicyExcludeIPs_Invalid(t *testing.T) {
	yaml := `
listen_addr: ":8080"

paths:
  /api/v1/products:
    get:
      x-csar-backend:
        target_url: "https://api.example.com/products"
      x-csar-traffic:
        rps: 10
        burst: 20
        max_wait: "500ms"
        exclude_ips:
          - "not-an-ip"
`
	path := writeTemp(t, yaml)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid exclude_ips entry")
	}
}

func TestLoad_VIPOverridesUnknownPolicy(t *testing.T) {
	yaml := `
listen_addr: ":8080"

throttling_policies:
  standard-api:
    rate: 10
    burst: 20
    max_wait: "500ms"

paths:
  /api/v1/products:
    get:
      x-csar-backend:
        target_url: "https://api.example.com/products"
      x-csar-traffic:
        rps: 10
        burst: 20
        max_wait: "500ms"
        vip_overrides:
          - header: "X-API-Key"
            values:
              "vip-123": "nonexistent-vip-policy"
`
	path := writeTemp(t, yaml)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for VIP override referencing unknown policy")
	}
	if !strings.Contains(err.Error(), "nonexistent-vip-policy") {
		t.Errorf("error should mention unknown policy, got: %v", err)
	}
}

func TestTrafficConfig_UnmarshalYAML_BareString(t *testing.T) {
	var tc TrafficConfig
	node := yamlPkg.Node{
		Kind:  yamlPkg.ScalarNode,
		Value: "my-policy",
	}
	if err := tc.UnmarshalYAML(&node); err != nil {
		t.Fatalf("UnmarshalYAML error: %v", err)
	}
	if tc.Use != "my-policy" {
		t.Errorf("Use = %q, want %q", tc.Use, "my-policy")
	}
}

func TestResolveThrottlePolicies_MergeOrder(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		ThrottlingPolicies: map[string]ThrottlingPolicy{
			"base": {
				RPS:     10,
				Burst:   20,
				MaxWait: Duration{500 * time.Millisecond},
				Backend: "local",
			},
		},
		Paths: map[string]PathConfig{
			"/api": {
				"get": RouteConfig{
					Backend: BackendConfig{TargetURL: "http://example.com"},
					Traffic: &TrafficConfig{
						Use:     "base",
						Burst:   50,                              // override burst
						MaxWait: Duration{2 * time.Second},      // override max_wait
					},
				},
			},
		},
	}

	if err := cfg.ResolveThrottlePolicies(); err != nil {
		t.Fatalf("ResolveThrottlePolicies() error: %v", err)
	}

	traffic := cfg.Paths["/api"]["get"].Traffic
	if traffic.RPS != 10 {
		t.Errorf("RPS = %v, want 10 (from policy)", traffic.RPS)
	}
	if traffic.Burst != 50 {
		t.Errorf("Burst = %v, want 50 (inline override)", traffic.Burst)
	}
	if traffic.MaxWait.Duration != 2*time.Second {
		t.Errorf("MaxWait = %v, want 2s (inline override)", traffic.MaxWait.Duration)
	}
	if traffic.Backend != "local" {
		t.Errorf("Backend = %q, want %q (from policy)", traffic.Backend, "local")
	}
	if traffic.Use != "" {
		t.Errorf("Use = %q, should be empty after resolution", traffic.Use)
	}
}
