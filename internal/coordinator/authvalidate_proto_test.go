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
