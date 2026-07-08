package protoconv

import (
	"testing"
	"time"

	"github.com/ledatu/csar/internal/config"
	csarv1 "github.com/ledatu/csar/proto/csar/v1"
	"google.golang.org/protobuf/types/known/durationpb"
)

func TestProtoToAuthValidateConfig_PreservesJWKSTLS(t *testing.T) {
	cfg := protoToAuthValidateConfig(&csarv1.AuthValidateConfigProto{
		Mode:    "jwt",
		JwksUrl: "https://auth.example.com/.well-known/jwks.json",
		JwksTls: "authn-mtls",
	})

	if cfg.JWKSTLS != "authn-mtls" {
		t.Fatalf("JWKSTLS = %q, want authn-mtls", cfg.JWKSTLS)
	}
}

func TestProtoToAuthValidateConfig_PreservesIssueTokens(t *testing.T) {
	cfg := protoToAuthValidateConfig(&csarv1.AuthValidateConfigProto{
		Mode: "session",
		IssueTokens: []*csarv1.IssueTokenConfigProto{{
			Profile:        "telegram-webapp",
			InjectHeader:   "Authorization",
			InjectFormat:   "Bearer {token}",
			OnMissingClaim: "fail_closed",
		}},
	})

	if len(cfg.IssueTokens) != 1 {
		t.Fatalf("IssueTokens len = %d, want 1", len(cfg.IssueTokens))
	}
	got := cfg.IssueTokens[0]
	if got.Profile != "telegram-webapp" || got.InjectHeader != "Authorization" ||
		got.InjectFormat != "Bearer {token}" || got.OnMissingClaim != "fail_closed" {
		t.Fatalf("IssueToken = %#v", got)
	}
}

func TestProtoToAccessControl_PreservesTrustedProxyCIDRs(t *testing.T) {
	cfg := protoToAccessControl(&csarv1.AccessControlProto{
		AllowCidrs:        []string{"203.0.113.0/24"},
		TrustProxy:        true,
		TrustedProxyCidrs: []string{"127.0.0.1/32"},
	})

	if got, want := cfg.AllowCIDRs[0], "203.0.113.0/24"; got != want {
		t.Fatalf("AllowCIDRs[0] = %q, want %q", got, want)
	}
	if !cfg.TrustProxy {
		t.Fatal("TrustProxy = false, want true")
	}
	if got, want := cfg.TrustedProxyCIDRs[0], "127.0.0.1/32"; got != want {
		t.Fatalf("TrustedProxyCIDRs[0] = %q, want %q", got, want)
	}
}

func TestFullSnapshotToConfig_BackendTLSPolicies(t *testing.T) {
	snap := &csarv1.FullConfigSnapshot{
		BackendTlsPolicies: map[string]*csarv1.BackendTLSConfigProto{
			"authn-mtls": {
				CaFile:   "/etc/csar/tls/ca.pem",
				CertFile: "/etc/csar/tls/csar-client.pem",
				KeyFile:  "/etc/csar/tls/csar-client-key.pem",
			},
			"insecure-dev": {
				InsecureSkipVerify: true,
			},
		},
	}

	cfg := FullSnapshotToConfig(snap)

	if len(cfg.BackendTLSPolicies) != 2 {
		t.Fatalf("BackendTLSPolicies len = %d, want 2", len(cfg.BackendTLSPolicies))
	}

	mtls, ok := cfg.BackendTLSPolicies["authn-mtls"]
	if !ok {
		t.Fatal("BackendTLSPolicies missing authn-mtls")
	}
	if mtls.CAFile != "/etc/csar/tls/ca.pem" {
		t.Errorf("CAFile = %q, want /etc/csar/tls/ca.pem", mtls.CAFile)
	}
	if mtls.CertFile != "/etc/csar/tls/csar-client.pem" {
		t.Errorf("CertFile = %q, want /etc/csar/tls/csar-client.pem", mtls.CertFile)
	}
	if mtls.KeyFile != "/etc/csar/tls/csar-client-key.pem" {
		t.Errorf("KeyFile = %q, want /etc/csar/tls/csar-client-key.pem", mtls.KeyFile)
	}
	if mtls.InsecureSkipVerify {
		t.Error("authn-mtls InsecureSkipVerify = true, want false")
	}

	dev, ok := cfg.BackendTLSPolicies["insecure-dev"]
	if !ok {
		t.Fatal("BackendTLSPolicies missing insecure-dev")
	}
	if !dev.InsecureSkipVerify {
		t.Error("insecure-dev InsecureSkipVerify = false, want true")
	}
}

func TestFullSnapshotToConfig_BackendTLSPoliciesNil(t *testing.T) {
	snap := &csarv1.FullConfigSnapshot{}
	cfg := FullSnapshotToConfig(snap)

	if cfg.BackendTLSPolicies != nil {
		t.Fatalf("BackendTLSPolicies = %v, want nil for empty snapshot", cfg.BackendTLSPolicies)
	}
}

func TestFullSnapshotToConfig_BackendPoolsAndRouteTimeout(t *testing.T) {
	snap := &csarv1.FullConfigSnapshot{
		BackendPools: map[string]*csarv1.BackendPoolConfigProto{
			"identity-critical": {
				MaxIdleConns:          128,
				MaxIdleConnsPerHost:   32,
				MaxConnsPerHost:       128,
				DialTimeout:           durationpb.New(500 * time.Millisecond),
				TlsHandshakeTimeout:   durationpb.New(time.Second),
				ResponseHeaderTimeout: durationpb.New(10 * time.Second),
				IdleConnTimeout:       durationpb.New(30 * time.Second),
				ExpectContinueTimeout: durationpb.New(time.Second),
			},
		},
		Routes: []*csarv1.RouteConfig{
			{
				Path:   "/svc",
				Method: "POST",
				Backend: &csarv1.BackendConfigProto{
					TargetUrl: "https://authz:9092",
					PathMode:  "append",
					Pool:      "identity-critical",
					Timeout:   durationpb.New(1200 * time.Millisecond),
				},
			},
		},
	}

	cfg := FullSnapshotToConfig(snap)
	pool, ok := cfg.BackendPools["identity-critical"]
	if !ok {
		t.Fatal("BackendPools missing identity-critical")
	}
	if pool.MaxConnsPerHost != 128 {
		t.Errorf("MaxConnsPerHost = %d, want 128", pool.MaxConnsPerHost)
	}
	if pool.ResponseHeaderTimeout.Duration != 10*time.Second {
		t.Errorf("ResponseHeaderTimeout = %s, want 10s", pool.ResponseHeaderTimeout.Duration)
	}
	route := cfg.Paths["/svc"]["post"]
	if route.Backend.Pool != "identity-critical" {
		t.Errorf("route pool = %q, want identity-critical", route.Backend.Pool)
	}
	if route.Backend.Timeout.Duration != 1200*time.Millisecond {
		t.Errorf("route timeout = %s, want 1200ms", route.Backend.Timeout.Duration)
	}
}

func TestFullSnapshotToConfig_SessionTLSWithBackendTLSPolicy(t *testing.T) {
	snap := &csarv1.FullConfigSnapshot{
		Routes: []*csarv1.RouteConfig{
			{
				Path:   "/support/tickets/{ticketID}",
				Method: "PATCH",
				Backend: &csarv1.BackendConfigProto{
					TargetUrl: "https://support:8086",
					PathMode:  "append",
					Tls: &csarv1.BackendTLSConfigProto{
						CaFile:   "/etc/csar/tls/ca.pem",
						CertFile: "/etc/csar/tls/csar-client.pem",
						KeyFile:  "/etc/csar/tls/csar-client-key.pem",
					},
				},
				AuthValidate: &csarv1.AuthValidateConfigProto{
					Mode:            "session",
					SessionEndpoint: "https://authn:8081/auth/validate",
					SessionTls:      "authn-mtls",
					CookieName:      "csar_session",
					ForwardHeaders:  []string{"X-Gateway-Subject"},
				},
			},
		},
		BackendTlsPolicies: map[string]*csarv1.BackendTLSConfigProto{
			"authn-mtls": {
				CaFile:   "/etc/csar/tls/ca.pem",
				CertFile: "/etc/csar/tls/csar-client.pem",
				KeyFile:  "/etc/csar/tls/csar-client-key.pem",
			},
		},
	}

	cfg := FullSnapshotToConfig(snap)

	route, ok := cfg.Paths["/support/tickets/{ticketID}"]["patch"]
	if !ok {
		t.Fatal("route PATCH /support/tickets/{ticketID} not found")
	}
	if route.AuthValidate == nil {
		t.Fatal("route AuthValidate is nil")
	}
	if route.AuthValidate.SessionTLS != "authn-mtls" {
		t.Errorf("SessionTLS = %q, want authn-mtls", route.AuthValidate.SessionTLS)
	}

	policy, ok := cfg.BackendTLSPolicies["authn-mtls"]
	if !ok {
		t.Fatal("BackendTLSPolicies missing authn-mtls")
	}
	if policy.CertFile != "/etc/csar/tls/csar-client.pem" {
		t.Errorf("policy CertFile = %q, want /etc/csar/tls/csar-client.pem", policy.CertFile)
	}
}

func TestFullSnapshotToConfig_AuditExplicitFalse(t *testing.T) {
	snap := &csarv1.FullConfigSnapshot{
		Routes: []*csarv1.RouteConfig{
			{
				Path:   "/svc/s3",
				Method: "POST",
				Backend: &csarv1.BackendConfigProto{
					TargetUrl: "https://s3:8087",
				},
				AuditSet:  true,
				AuditMode: "off",
			},
		},
	}

	cfg := FullSnapshotToConfig(snap)
	route, ok := cfg.Paths["/svc/s3"]["post"]
	if !ok {
		t.Fatal("route not found")
	}
	if route.Audit == nil || *route.Audit != config.AuditModeOff {
		t.Fatalf("Audit = %v, want pointer to off", route.Audit)
	}
}

func TestFullSnapshotToConfig_CachePolicyMaps(t *testing.T) {
	snap := &csarv1.FullConfigSnapshot{
		CachePolicies: map[string]*csarv1.CacheConfigProto{
			"short": {
				EnabledSet:       true,
				Enabled:          true,
				Ttl:              durationpb.New(30 * time.Second),
				MaxEntries:       100,
				Store:            "redis",
				Key:              "analytics:{tenant}",
				Tags:             []string{"t:{path.id}"},
				VaryHeaders:      []string{"Accept"},
				OperationTimeout: durationpb.New(50 * time.Millisecond),
				CacheStatuses:    []string{"200"},
				TtlRules: []*csarv1.CacheTTLRuleProto{
					{
						When: "query.date_range_contains_today",
						Ttl:  durationpb.New(time.Minute),
					},
				},
				KeyQuery: &csarv1.CacheKeyQueryConfigProto{
					Include: []string{"marketplace"},
					Sort:    true,
				},
			},
		},
		CacheInvalidationPolicies: map[string]*csarv1.CacheInvalidationConfigProto{
			"on-write": {
				Tags: []string{"widgets:{path.id}"},
			},
		},
		Routes: []*csarv1.RouteConfig{
			{
				Path:    "/x",
				Method:  "GET",
				Backend: &csarv1.BackendConfigProto{TargetUrl: "http://upstream:8080"},
			},
		},
	}

	cfg := FullSnapshotToConfig(snap)
	cc, ok := cfg.CachePolicies["short"]
	if !ok {
		t.Fatal("CachePolicies missing short")
	}
	if cc.Enabled == nil || !*cc.Enabled {
		t.Fatalf("cache policy enabled = %v", cc.Enabled)
	}
	if cc.TTL.Duration != 30*time.Second {
		t.Errorf("TTL = %v", cc.TTL.Duration)
	}
	if cc.MaxEntries != 100 {
		t.Errorf("MaxEntries = %d", cc.MaxEntries)
	}
	if cc.Store != "redis" || cc.Key != "analytics:{tenant}" {
		t.Errorf("store/key = %q %q", cc.Store, cc.Key)
	}
	if len(cc.Tags) != 1 || cc.Tags[0] != "t:{path.id}" {
		t.Errorf("tags = %v", cc.Tags)
	}
	if len(cc.VaryHeaders) != 1 || cc.VaryHeaders[0] != "Accept" {
		t.Errorf("vary = %v", cc.VaryHeaders)
	}
	if cc.OperationTimeout.Duration != 50*time.Millisecond {
		t.Errorf("operation_timeout = %v", cc.OperationTimeout)
	}
	if len(cc.CacheStatuses) != 1 || cc.CacheStatuses[0] != "200" {
		t.Errorf("cache_statuses = %v", cc.CacheStatuses)
	}
	if len(cc.TTLRules) != 1 || cc.TTLRules[0].When != "query.date_range_contains_today" {
		t.Errorf("ttl_rules = %+v", cc.TTLRules)
	}
	if cc.KeyQuery == nil || len(cc.KeyQuery.Include) != 1 || !cc.KeyQuery.Sort {
		t.Errorf("key_query = %+v", cc.KeyQuery)
	}

	ci, ok := cfg.CacheInvalidationPolicies["on-write"]
	if !ok {
		t.Fatal("CacheInvalidationPolicies missing on-write")
	}
	if len(ci.Tags) != 1 || ci.Tags[0] != "widgets:{path.id}" {
		t.Errorf("tags = %v", ci.Tags)
	}
}
