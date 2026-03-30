package protoconv

import (
	"testing"

	csarv1 "github.com/ledatu/csar/proto/csar/v1"
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
