package config

import (
	"testing"
	"time"
)

func quotaConfig() *Config {
	return &Config{Paths: map[string]PathConfig{"/read": {"get": {Traffic: &TrafficConfig{Backend: "redis", Key: "read:{path.cabinet}", Quotas: []RequestQuota{{Name: "day", Key: "data:{path.cabinet}", Requests: 20, Window: Duration{Duration: 24 * time.Hour}}}}}}}}
}
func TestRequestQuotasRejectUnsafeConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*TrafficConfig)
	}{
		{"local", func(t *TrafficConfig) { t.Backend = "local" }},
		{"wait", func(t *TrafficConfig) { t.MaxWait.Duration = time.Second }},
		{"bypass", func(t *TrafficConfig) { t.ExcludeIPs = []string{"127.0.0.1"} }},
		{"missing_key", func(t *TrafficConfig) { t.Quotas[0].Key = "" }},
		{"negative", func(t *TrafficConfig) { t.Quotas[0].Requests = -1 }},
		{"oversized", func(t *TrafficConfig) { t.Quotas[0].Requests = 10001 }},
		{"window", func(t *TrafficConfig) { t.Quotas[0].Window.Duration = 25 * time.Hour }},
		{"duplicate", func(t *TrafficConfig) { t.Quotas = append(t.Quotas, t.Quotas[0]) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := quotaConfig()
			tc.change(c.Paths["/read"]["get"].Traffic)
			if c.ValidateRequestQuotas() == nil {
				t.Fatal("unsafe quota accepted")
			}
		})
	}
	c := quotaConfig()
	if err := c.ValidateRequestQuotas(); err != nil {
		t.Fatal(err)
	}
	// An older coordinator must not clear active quota semantics implicitly.
	if c.CheckPolicySnapshot(c.RequiredCapabilities()) == nil {
		t.Fatal("unversioned snapshot accepted")
	}
}
func TestNamedQuotaPolicyIsCopied(t *testing.T) {
	c := quotaConfig()
	traffic := c.Paths["/read"]["get"].Traffic
	c.ThrottlingPolicies = map[string]ThrottlingPolicy{"reads": {Backend: traffic.Backend, Key: traffic.Key, Quotas: traffic.Quotas}}
	c.Paths["/read"]["get"] = RouteConfig{Traffic: &TrafficConfig{Use: "reads"}}
	if err := c.ResolveThrottlePolicies(); err != nil {
		t.Fatal(err)
	}
	got := c.Paths["/read"]["get"].Traffic
	if len(got.Quotas) != 1 {
		t.Fatal("quota not inherited")
	}
	got.Quotas[0].Requests = 1
	if c.ThrottlingPolicies["reads"].Quotas[0].Requests != 20 {
		t.Fatal("quota policy aliased")
	}
}

func TestQuotaPoliciesRejectEveryInlineReplayPath(t *testing.T) {
	yes, no := true, false
	for _, tc := range []struct {
		name     string
		retry    *RetryConfig
		protocol *ProtocolPolicy
		bad      bool
	}{
		{name: "no_retry"},
		{name: "one_attempt", retry: &RetryConfig{MaxAttempts: 1}},
		{name: "ordinary_retry", retry: &RetryConfig{MaxAttempts: 2}, bad: true},
		{name: "retry_defaults", retry: &RetryConfig{}},
		{name: "auto_retry", retry: &RetryConfig{MaxAttempts: 1, AutoRetry429: true}, bad: true},
		{name: "protocol_retry", protocol: &ProtocolPolicy{TransparentRetry: &yes}, bad: true},
		{name: "protocol_enables_retry", retry: &RetryConfig{MaxAttempts: 1}, protocol: &ProtocolPolicy{TransparentRetry: &yes}, bad: true},
		{name: "protocol_disables_retry", retry: &RetryConfig{MaxAttempts: 1, AutoRetry429: true}, protocol: &ProtocolPolicy{TransparentRetry: &no}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := quotaConfig()
			r := c.Paths["/read"]["get"]
			r.Retry = tc.retry
			r.Protocol = tc.protocol
			c.Paths["/read"]["get"] = r
			if err := c.ValidateRequestQuotas(); (err != nil) != tc.bad {
				t.Fatal("unexpected quota/replay validation", err)
			}
		})
	}
	c := quotaConfig()
	c.RetryPolicies = map[string]RetryConfig{"inherited": {MaxAttempts: 2}}
	r := c.Paths["/read"]["get"]
	r.Retry = &RetryConfig{Use: "inherited"}
	c.Paths["/read"]["get"] = r
	if err := c.ResolvePolicies(); err != nil {
		t.Fatal(err)
	}
	if c.ValidateRequestQuotas() == nil {
		t.Fatal("inherited retry bypassed quota validation")
	}
}
