package coordinator

import (
	"reflect"
	"testing"

	"github.com/ledatu/csar/internal/config"
	"github.com/ledatu/csar/internal/configsource"
	"github.com/ledatu/csar/internal/protoconv"
	csarv1 "github.com/ledatu/csar/proto/csar/v1"
	"google.golang.org/protobuf/proto"
)

func TestTokenPolicySurvivesConfigSnapshot(t *testing.T) {
	cfg, err := config.ParseBytes([]byte(`
listen_addr: ":8080"
backend_tls_policies:
  token-mtls:
    ca_file: /etc/csar/ca.pem
    cert_file: /etc/csar/client.pem
    key_file: /etc/csar/client-key.pem
auth_validate_policies:
  personal-key:
    mode: token
    introspection_endpoint: https://authn:8081/auth/token/introspect
    introspection_tls: token-mtls
    required_scope: adverts:read
    seller_path_param: cabinet_id
    cache_ttl: 15s
paths:
  /v1/wildberries/{cabinet_id}/adverts/bidder-settings:
    get:
      x-csar-backend: {target_url: "https://api:8080"}
      x-csar-authn-validate: personal-key
`))
	if err != nil {
		t.Fatal(err)
	}
	const path = "/v1/wildberries/{cabinet_id}/adverts/bidder-settings"
	entries := configsource.ConfigToRouteEntries(cfg)
	entry := entries["GET:"+path]
	snapshot := &csarv1.FullConfigSnapshot{
		Routes:             []*csarv1.RouteConfig{routeEntryToProto(&entry)},
		BackendTlsPolicies: backendTLSPoliciesToProto(cfg.BackendTLSPolicies),
	}
	data, err := proto.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	var decoded csarv1.FullConfigSnapshot
	if err := proto.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	reconstructed := protoconv.FullSnapshotToConfig(&decoded)
	if err := reconstructed.ResolvePolicies(); err != nil {
		t.Fatal(err)
	}
	want := cfg.Paths[path]["get"].AuthValidate
	got := reconstructed.Paths[path]["get"].AuthValidate
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("token policy changed in snapshot: got %+v, want %+v", got, want)
	}
	if !reflect.DeepEqual(reconstructed.BackendTLSPolicies, cfg.BackendTLSPolicies) {
		t.Fatal("snapshot lost the token introspection TLS policy")
	}
}

func TestAuthValidateToProto_PreservesJWKSTLS(t *testing.T) {
	pb := authValidateToProto(&config.AuthValidateConfig{
		Mode:    "jwt",
		JWKSURL: "https://auth.example.com/.well-known/jwks.json",
		JWKSTLS: "authn-mtls",
	})

	if pb.GetJwksTls() != "authn-mtls" {
		t.Fatalf("JwksTls = %q, want authn-mtls", pb.GetJwksTls())
	}
}

func TestAuthValidateToProto_PreservesIssueTokens(t *testing.T) {
	pb := authValidateToProto(&config.AuthValidateConfig{
		Mode: "session",
		IssueTokens: []config.IssueTokenConfig{{
			Profile:        "telegram-webapp",
			InjectHeader:   "Authorization",
			InjectFormat:   "Bearer {token}",
			OnMissingClaim: "fail_closed",
		}},
	})

	if len(pb.GetIssueTokens()) != 1 {
		t.Fatalf("IssueTokens len = %d, want 1", len(pb.GetIssueTokens()))
	}
	got := pb.GetIssueTokens()[0]
	if got.GetProfile() != "telegram-webapp" || got.GetInjectHeader() != "Authorization" ||
		got.GetInjectFormat() != "Bearer {token}" || got.GetOnMissingClaim() != "fail_closed" {
		t.Fatalf("IssueToken = %#v", got)
	}
}
