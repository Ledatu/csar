package coordinator

import (
	"testing"

	"github.com/ledatu/csar/internal/config"
)

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
