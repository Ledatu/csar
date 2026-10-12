package config

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"
	"gopkg.in/yaml.v3"
)

func TestPeriodRateResolution(t *testing.T) {
	for _, override := range []struct {
		fields string
		want   float64
	}{
		{"", 1.0 / 60},
		{"requests: 10, period: 6s,", 10.0 / 6},
		{"rps: 2,", 2},
	} {
		t.Run(override.fields, func(t *testing.T) {
			source := fmt.Sprintf(`
listen_addr: ":8080"
global_throttle: {requests: 30, period: 1m, burst: 2}
throttling_policies:
  slow: {requests: 1, period: 1m, burst: 1}
  legacy: {rate: 7, burst: 8}
paths:
  /report:
    get:
      x-csar-backend: {target_url: "https://example.com"}
      x-csar-traffic: {use: slow, %s max_wait: 250ms}
  /inline:
    get:
      x-csar-backend: {target_url: "https://example.com"}
      x-csar-traffic: {requests: 10, period: 6s, burst: 5}
`, override.fields)
			cfg, err := ParseBytes([]byte(source))
			if err != nil {
				t.Fatal(err)
			}
			traffic := cfg.Paths["/report"]["get"].Traffic
			if traffic.RPS != override.want || traffic.Burst != 1 || traffic.Use != "" {
				t.Fatalf("resolved traffic = %+v, want RPS %v, burst 1", traffic, override.want)
			}
			if cfg.GlobalThrottle.RPS != 0.5 || cfg.ThrottlingPolicies["legacy"].RPS != 7 || cfg.Paths["/inline"]["get"].Traffic.RPS != 10.0/6 {
				t.Fatal("global, legacy or inline rate did not resolve")
			}
			if err := cfg.ResolveThrottlePolicies(); err != nil {
				t.Fatalf("resolution must be idempotent: %v", err)
			}
			path := filepath.Join(t.TempDir(), "config.yaml")
			writeFile(t, path, source)
			compiled, err := Compile(path)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(compiled), "requests:") || strings.Contains(string(compiled), "period:") {
				t.Fatal("compiled output must use canonical legacy rate fields")
			}
			reloaded, err := ParseBytes(compiled)
			if err != nil {
				t.Fatal(err)
			}
			if reloaded.Paths["/report"]["get"].Traffic.RPS != override.want {
				t.Fatal("rate changed during compilation")
			}
		})
	}
}

func TestPeriodRateValidation(t *testing.T) {
	for _, fields := range []string{
		"requests: 1", "period: 1m", "requests: 0, period: 1m",
		"requests: -1, period: 1m", "requests: 1.5, period: 1m",
		"requests: null, period: 1m", "requests: 1, period: null",
		"requests: 1, period: 0s", "requests: 1, period: -1m",
		"requests: 1, period: nonsense", "requests: 1, period: 999999999999h",
		"rate: 0, requests: 1, period: 1m", "rate: null, requests: 1, period: 1m",
		"rate: 2, requests: 1, period: 1m", "rate: .nan", "rate: .inf",
	} {
		t.Run(fields, func(t *testing.T) {
			for _, template := range []string{
				"throttling_policies:\n  unused: {%s, burst: 1}",
				"global_throttle: {%s, burst: 1}",
				"paths:\n  /x:\n    get:\n      x-csar-backend: {target_url: https://example.com}\n      x-csar-traffic: {%s, burst: 1}",
			} {
				actual := fields
				if strings.HasPrefix(template, "paths:") {
					actual = strings.ReplaceAll(actual, "rate:", "rps:")
				}
				source := "listen_addr: ':8080'\n" + fmt.Sprintf(template, actual)
				if !strings.HasPrefix(template, "paths:") {
					source += "\npaths:\n  /ok:\n    get:\n      x-csar-backend: {target_url: https://example.com}"
				}
				if _, err := ParseBytes([]byte(source)); err == nil {
					t.Fatalf("accepted invalid config: %s", source)
				}
			}
		})
	}
	var cfg Config
	if err := yaml.Unmarshal([]byte("throttling_policies:\n  base: &base {rate: 1, burst: 1}\n  bad: {<<: *base, requests: 1, period: 1m}"), &cfg); err == nil {
		t.Fatal("YAML merge bypassed mutual exclusion")
	}
}

func TestNormalizeRateProgrammaticValidation(t *testing.T) {
	count := 1
	for _, rps := range []float64{math.NaN(), math.Inf(1), -1} {
		if err := (&Config{ThrottlingPolicies: map[string]ThrottlingPolicy{"invalid": {RPS: rps}}}).ResolveThrottlePolicies(); err == nil {
			t.Fatalf("accepted invalid programmatic rate %v", rps)
		}
	}
	if err := (&Config{GlobalThrottle: &GlobalThrottleConfig{Requests: &count}}).ResolveThrottlePolicies(); err == nil {
		t.Fatal("accepted incomplete programmatic pair")
	}
}

func TestRateSchema(t *testing.T) {
	data, err := os.ReadFile("../../csar.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	embedded, err := os.ReadFile("../../cmd/csar-mcp/schema.json")
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err == nil && string(data) != string(embedded) {
		t.Fatal("MCP schema differs from the router schema")
	}
	for _, name := range []string{"ThrottlingPolicy", "GlobalThrottleConfig", "TrafficConfigObject"} {
		var root jsonschema.Schema
		if err := json.Unmarshal(data, &root); err != nil {
			t.Fatal(err)
		}
		subschema := jsonschema.Schema{Defs: root.Defs, Ref: "#/$defs/" + name}
		resolved, err := subschema.Resolve(nil)
		if err != nil {
			t.Fatal(err)
		}
		legacy := "rate"
		if name == "TrafficConfigObject" {
			legacy = "rps"
		}
		for _, test := range []struct {
			fields string
			valid  bool
		}{
			{`"requests":1,"period":"1m"`, true},
			{`"requests":10,"period":"6s"`, true},
			{`"requests":1,"period":"1m","adaptive_backpressure":{"enabled":true,"respect_headers":["X-Ratelimit-Retry"],"suspend_bucket":true}`, name != "GlobalThrottleConfig"},
			{`"requests":1,"period":"1m","adaptive_backpressure":{"enabled":"yes"}`, false},
			{fmt.Sprintf(`%q:0.5`, legacy), true},
			{`"requests":1`, false}, {`"period":"1m"`, false},
			{`"requests":1.5,"period":"1m"`, false},
			{`"requests":0,"period":"1m"`, false},
			{`"requests":1,"period":"0s0m"`, false},
			{`"requests":1,"period":"-1m"`, false},
			{fmt.Sprintf(`%q:1,"requests":1,"period":"1m"`, legacy), false},
			{`"use":"slow"`, name == "TrafficConfigObject"},
		} {
			var instance any
			if err := json.Unmarshal([]byte(`{"burst":1,`+test.fields+`}`), &instance); err != nil {
				t.Fatal(err)
			}
			if err := resolved.Validate(instance); (err == nil) != test.valid {
				t.Errorf("%s: %s valid=%v, error=%v", name, test.fields, test.valid, err)
			}
		}
	}
}
