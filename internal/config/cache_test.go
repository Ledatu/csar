package config

import (
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestCacheConfig_UnmarshalYAML_BareString(t *testing.T) {
	var cc CacheConfig
	node := &yaml.Node{Kind: yaml.ScalarNode, Value: "analytics-cache"}
	if err := cc.UnmarshalYAML(node); err != nil {
		t.Fatalf("UnmarshalYAML error: %v", err)
	}
	if cc.Use != "analytics-cache" {
		t.Fatalf("Use = %q, want analytics-cache", cc.Use)
	}
}

func TestResolveCachePolicies_POSTRequestLimit(t *testing.T) {
	for _, inline := range []int64{0, 16 * 1024} {
		cfg := &Config{}
		authored := fmt.Sprintf(`listen_addr: ":0"
cache_policies:
  stocks:
    key: "stocks:{subject}"
    max_request_body_size: 131072
    methods: [POST]
paths:
  /stocks:
    post:
      x-csar-backend: {target_url: "http://upstream"}
      x-csar-cache: {use: stocks, max_request_body_size: %d}
`, inline)
		if err := yaml.Unmarshal([]byte(authored), cfg); err != nil {
			t.Fatal(err)
		}
		if err := cfg.ResolveCachePolicies(); err != nil {
			t.Fatal(err)
		}
		if err := cfg.Validate(); err != nil {
			t.Fatal(err)
		}
		got := cfg.Paths["/stocks"]["post"].Cache
		want := int64(128 * 1024)
		if inline != 0 {
			want = inline
		}
		if got.MaxRequestBodySize != want || len(got.Methods) != 1 || got.Methods[0] != "POST" {
			t.Fatalf("resolved policy = %+v", got)
		}
		if cfg.CachePolicies["stocks"].MaxRequestBodySize != 128*1024 {
			t.Fatal("inline override changed named policy")
		}
	}
}

func TestValidateCache_POSTRequiresKeyIdentity(t *testing.T) {
	for _, tc := range []struct {
		key       string
		wantError bool
	}{
		{key: "stocks", wantError: true},
		{key: "stocks:{subject}"},
		{key: "stocks:{tenant}"},
	} {
		cfg := &Config{
			ListenAddr: ":0",
			CachePolicies: map[string]CacheConfig{
				"stocks": {Key: tc.key, Tags: []string{"stocks:{tenant}"}, Methods: []string{"post"}},
			},
			Paths: map[string]PathConfig{
				"/stocks": {"post": {
					Backend:      BackendConfig{TargetURL: "http://upstream"},
					AuthValidate: &AuthValidateConfig{Mode: "session", SessionEndpoint: "http://authn", CookieName: "session"},
					Cache:        &CacheConfig{Use: "stocks"},
				}},
			},
		}
		if err := cfg.ResolveCachePolicies(); err != nil {
			t.Fatal(err)
		}
		err := cfg.Validate()
		if tc.wantError {
			if err == nil || !strings.Contains(err.Error(), "authenticated POST cache requires") {
				t.Fatalf("key %q validation = %v", tc.key, err)
			}
		} else if err != nil {
			t.Fatal(err)
		}
	}
}

func TestValidateCache_RequestBodyLimit(t *testing.T) {
	for _, limit := range []int64{-1, math.MaxInt64} {
		cfg := &Config{
			ListenAddr: ":0",
			Paths: map[string]PathConfig{
				"/stocks": {"post": {
					Backend: BackendConfig{TargetURL: "http://upstream"},
					Cache:   &CacheConfig{MaxRequestBodySize: limit, Methods: []string{"POST"}},
				}},
			},
		}
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "max_request_body_size") {
			t.Fatalf("limit %d validation = %v", limit, err)
		}
	}
}

func TestResolveCachePolicies_MergeAdditiveFields(t *testing.T) {
	cfg := &Config{
		CachePolicies: map[string]CacheConfig{
			"analytics-cache": {
				Store:            "redis",
				Key:              "analytics:{tenant}:{query.marketplace}",
				TTL:              Duration{Duration: 3 * time.Hour},
				TTLJitter:        "5%",
				OperationTimeout: Duration{Duration: 75 * time.Millisecond},
				KeyQuery:         &CacheKeyQueryConfig{Include: []string{"marketplace"}, Sort: true},
				StaleIfError:     Duration{Duration: time.Hour},
				Tags:             []string{"analytics:{tenant}"},
				ResponseTags:     []CacheResponseTag{{Header: "X-CSAR-Cache-Tags", Prefix: "analytics:{tenant}:"}},
				Namespaces:       []string{"analytics:skus:{tenant}"},
				VaryHeaders:      []string{"Accept"},
				Methods:          []string{"GET"},
				CacheStatuses:    []string{"200"},
				ContentTypes:     []string{"application/json"},
				Coalesce:         &CacheCoalesceConfig{Enabled: true, Wait: Duration{Duration: 30 * time.Second}},
				TTLRules: []CacheTTLRule{
					{When: "query.date_range_contains_today", TTL: Duration{Duration: 20 * time.Minute}},
				},
				ResponseTTLRules: []CacheResponseTTLRule{
					{When: "response.header_equals", Header: "X-Data-Freshness", Value: "final", TTL: Duration{Duration: 3 * time.Hour}},
				},
			},
		},
		Paths: map[string]PathConfig{
			"/analytics/skus": {"get": RouteConfig{
				Backend: BackendConfig{TargetURL: "http://localhost"},
				Cache: &CacheConfig{
					Use:              "analytics-cache",
					TTL:              Duration{Duration: time.Hour},
					TTLJitter:        "10%",
					StaleIfError:     Duration{Duration: 2 * time.Hour},
					Tags:             []string{"analytics:{tenant}:{query.marketplace}"},
					Namespaces:       []string{"analytics:skus:{tenant}:{query.marketplace}"},
					VaryHeaders:      []string{"X-Report-Format"},
					Methods:          []string{"HEAD"},
					CacheStatuses:    []string{"2xx"},
					ContentTypes:     []string{"text/csv"},
					OperationTimeout: Duration{Duration: 25 * time.Millisecond},
					TTLRules: []CacheTTLRule{
						{When: "query.date_range_contains_today", From: "from", To: "to", TTL: Duration{Duration: 5 * time.Minute}},
					},
					ResponseTTLRules: []CacheResponseTTLRule{
						{When: "response.header_equals", Header: "X-Data-Freshness", Value: "partial", TTL: Duration{Duration: 10 * time.Minute}},
					},
				},
			}},
		},
	}

	if err := cfg.ResolveCachePolicies(); err != nil {
		t.Fatalf("ResolveCachePolicies: %v", err)
	}
	got := cfg.Paths["/analytics/skus"]["get"].Cache
	if got.Use != "" {
		t.Fatalf("Use = %q, want cleared", got.Use)
	}
	if got.Store != "redis" {
		t.Fatalf("Store = %q, want redis", got.Store)
	}
	if got.TTL.Duration != time.Hour {
		t.Fatalf("TTL = %s, want 1h", got.TTL.Duration)
	}
	if got.TTLJitter != "10%" {
		t.Fatalf("TTLJitter = %q, want 10%%", got.TTLJitter)
	}
	if got.StaleIfError.Duration != 2*time.Hour {
		t.Fatalf("StaleIfError = %s, want 2h", got.StaleIfError.Duration)
	}
	if got.OperationTimeout.Duration != 25*time.Millisecond {
		t.Fatalf("OperationTimeout = %s, want 25ms", got.OperationTimeout.Duration)
	}
	if len(got.Tags) != 2 {
		t.Fatalf("Tags = %#v, want policy + inline", got.Tags)
	}
	if len(got.VaryHeaders) != 2 {
		t.Fatalf("VaryHeaders = %#v, want policy + inline", got.VaryHeaders)
	}
	if len(got.Methods) != 2 {
		t.Fatalf("Methods = %#v, want policy + inline", got.Methods)
	}
	if len(got.CacheStatuses) != 2 {
		t.Fatalf("CacheStatuses = %#v, want policy + inline", got.CacheStatuses)
	}
	if len(got.TTLRules) != 2 || got.TTLRules[0].TTL.Duration != 5*time.Minute {
		t.Fatalf("TTLRules = %#v, want inline rule first then policy rule", got.TTLRules)
	}
	if len(got.ResponseTTLRules) != 2 {
		t.Fatalf("ResponseTTLRules = %#v, want policy + inline", got.ResponseTTLRules)
	}
	if len(got.Namespaces) != 2 {
		t.Fatalf("Namespaces = %#v, want policy + inline", got.Namespaces)
	}
	if len(got.ContentTypes) != 2 {
		t.Fatalf("ContentTypes = %#v, want policy + inline", got.ContentTypes)
	}
}

func TestCacheInvalidationConfig_UnmarshalYAML_BareString(t *testing.T) {
	var ci CacheInvalidationConfig
	node := &yaml.Node{Kind: yaml.ScalarNode, Value: "analytics-sku-invalidation"}
	if err := ci.UnmarshalYAML(node); err != nil {
		t.Fatalf("UnmarshalYAML error: %v", err)
	}
	if ci.Use != "analytics-sku-invalidation" {
		t.Fatalf("Use = %q, want analytics-sku-invalidation", ci.Use)
	}
}

func TestResolveCacheInvalidationPolicies_MergeAdditiveFields(t *testing.T) {
	cfg := &Config{
		CacheInvalidationPolicies: map[string]CacheInvalidationConfig{
			"analytics-sku-invalidation": {
				Store:            "redis",
				OperationTimeout: Duration{Duration: 75 * time.Millisecond},
				Tags:             []string{"analytics:skus:{tenant}"},
				BumpNamespaces:   []string{"analytics:skus:{tenant}"},
				Debounce:         Duration{Duration: 2 * time.Second},
				OnStatus:         []string{"2xx"},
			},
		},
		Paths: map[string]PathConfig{
			"/skus/{sku_id}": {"patch": RouteConfig{
				Backend: BackendConfig{TargetURL: "http://localhost"},
				CacheInvalidate: &CacheInvalidationConfig{
					Use:              "analytics-sku-invalidation",
					OperationTimeout: Duration{Duration: 25 * time.Millisecond},
					Tags:             []string{"analytics:skus:{tenant}:{path.sku_id}"},
					BumpNamespaces:   []string{"analytics:skus:{tenant}:{path.sku_id}"},
					OnStatus:         []string{"204"},
				},
			}},
		},
	}

	if err := cfg.ResolveCacheInvalidationPolicies(); err != nil {
		t.Fatalf("ResolveCacheInvalidationPolicies: %v", err)
	}
	got := cfg.Paths["/skus/{sku_id}"]["patch"].CacheInvalidate
	if got.Use != "" {
		t.Fatalf("Use = %q, want cleared", got.Use)
	}
	if got.Store != "redis" {
		t.Fatalf("Store = %q, want redis", got.Store)
	}
	if got.OperationTimeout.Duration != 25*time.Millisecond {
		t.Fatalf("OperationTimeout = %s, want 25ms", got.OperationTimeout.Duration)
	}
	if len(got.Tags) != 2 {
		t.Fatalf("Tags = %#v, want policy + inline", got.Tags)
	}
	if len(got.BumpNamespaces) != 2 {
		t.Fatalf("BumpNamespaces = %#v, want policy + inline", got.BumpNamespaces)
	}
	if got.Debounce.Duration != 2*time.Second {
		t.Fatalf("Debounce = %s, want policy debounce", got.Debounce.Duration)
	}
	if len(got.OnStatus) != 2 {
		t.Fatalf("OnStatus = %#v, want policy + inline", got.OnStatus)
	}
}

func TestValidateCacheInvalidation_AllowsNamespaceOnly(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":0",
		Paths: map[string]PathConfig{
			"/skus/{sku_id}": {"patch": RouteConfig{
				Backend: BackendConfig{TargetURL: "http://localhost"},
				CacheInvalidate: &CacheInvalidationConfig{
					BumpNamespaces: []string{"analytics:skus:{tenant}"},
				},
			}},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidateCacheBypassRequiresScope(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":0",
		Paths: map[string]PathConfig{
			"/data": {"get": RouteConfig{
				Backend: BackendConfig{TargetURL: "http://localhost"},
				Cache: &CacheConfig{
					Bypass: &CacheBypassConfig{Headers: []CacheBypassHeader{{Name: "X-CSAR-Cache-Bypass"}}},
				},
			}},
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate should reject bypass headers without require_gateway_scope")
	}
}
