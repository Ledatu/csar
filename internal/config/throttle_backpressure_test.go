package config

import (
	"path/filepath"
	"reflect"
	"testing"
)

const policyBackpressureFixture = `
listen_addr: ":8080"
throttling_policies:
  upstream:
    requests: 3
    period: 1m
    burst: 1
    client_limit_mode: advisory
    adaptive_backpressure:
      enabled: true
      respect_headers: [X-Ratelimit-Retry, Retry-After, X-Ratelimit-Reset]
      suspend_bucket: true
      max_body_buffer: 12345
paths:
  /inherited:
    get:
      x-csar-backend: {target_url: "https://example.com"}
      x-csar-traffic: upstream
  /disabled:
    get:
      x-csar-backend: {target_url: "https://example.com"}
      x-csar-traffic:
        use: upstream
        client_limit_mode: ignore
        adaptive_backpressure: {enabled: false}
  /overridden:
    get:
      x-csar-backend: {target_url: "https://example.com"}
      x-csar-traffic:
        use: upstream
        adaptive_backpressure: {enabled: true, respect_headers: [Retry-After]}
  /sibling:
    get:
      x-csar-backend: {target_url: "https://example.com"}
      x-csar-traffic: {use: upstream}
`

func TestThrottlePolicyBackpressure(t *testing.T) {
	cfg, err := ParseBytes([]byte(policyBackpressureFixture))
	if err != nil {
		t.Fatal(err)
	}
	inherited := cfg.Paths["/inherited"]["get"].Traffic
	policy := cfg.ThrottlingPolicies["upstream"]
	if !reflect.DeepEqual(inherited.AdaptiveBackpressure, policy.AdaptiveBackpressure) || inherited.ClientLimitMode != "advisory" {
		t.Fatalf("policy not inherited: %+v", inherited)
	}
	disabled := cfg.Paths["/disabled"]["get"].Traffic
	if disabled.AdaptiveBackpressure == nil || disabled.AdaptiveBackpressure.Enabled || disabled.AdaptiveBackpressure.SuspendBucket || disabled.ClientLimitMode != "ignore" {
		t.Fatalf("explicit disabling was overwritten: %+v", disabled)
	}
	overridden := cfg.Paths["/overridden"]["get"].Traffic.AdaptiveBackpressure
	if !overridden.Enabled || overridden.SuspendBucket || overridden.MaxBodyBuffer != 0 || !reflect.DeepEqual(overridden.RespectHeaders, []string{"Retry-After"}) {
		t.Fatalf("inline block must replace the whole policy block: %+v", overridden)
	}
	// Consumers may default or adjust these values; no sibling may be mutated.
	inherited.AdaptiveBackpressure.Enabled = false
	inherited.AdaptiveBackpressure.RespectHeaders[0] = "Changed"
	sibling := cfg.Paths["/sibling"]["get"].Traffic.AdaptiveBackpressure
	if !policy.AdaptiveBackpressure.Enabled || !sibling.Enabled || policy.AdaptiveBackpressure.RespectHeaders[0] != "X-Ratelimit-Retry" || sibling.RespectHeaders[0] != "X-Ratelimit-Retry" {
		t.Fatal("inherited backpressure shares mutable state with its policy or sibling")
	}
}

func TestCompilePolicyBackpressure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	writeFile(t, path, policyBackpressureFixture)
	compiled, err := Compile(path)
	if err != nil {
		t.Fatal(err)
	}
	fromSource, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	fromCompiled, err := ParseBytes(compiled)
	if err != nil {
		t.Fatal(err)
	}
	for path := range fromSource.Paths {
		if !reflect.DeepEqual(fromSource.Paths[path]["get"].Traffic, fromCompiled.Paths[path]["get"].Traffic) {
			t.Errorf("compilation changed resolved traffic at %s", path)
		}
	}
}
