package config

import "testing"

func TestOriginIssuerValidation(t *testing.T) {
	base := OriginIssuerConfig{Endpoint: "https://authn/root", Issuer: "authn", JWKSURL: "https://authn/jwks", TLS: BackendTLSPolicy{CertFile: "router.pem", KeyFile: "router.key"}}
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []string{"http://authn/root", "https://user:pass@authn/root", "https://authn/root?secret=value", "https://authn/root#fragment", "https://authn/a/../root", "https://authn//root", "https://authn/%72oot", "https://authn"} {
		for _, field := range []string{"endpoint", "jwks_url"} {
			t.Run(field+endpoint, func(t *testing.T) {
				cfg := base
				if field == "endpoint" {
					cfg.Endpoint = endpoint
				} else {
					cfg.JWKSURL = endpoint
				}
				if err := cfg.Validate(); err == nil {
					t.Fatal("unsafe issuer URL accepted")
				}
			})
		}
	}
	for _, change := range []func(*OriginIssuerConfig){
		func(c *OriginIssuerConfig) { c.Issuer = " " },
		func(c *OriginIssuerConfig) { c.TLS.CertFile = "" },
		func(c *OriginIssuerConfig) { c.TLS.KeyFile = "" },
		func(c *OriginIssuerConfig) { c.TLS.InsecureSkipVerify = true },
	} {
		cfg := base
		change(&cfg)
		if err := cfg.Validate(); err == nil {
			t.Fatal("missing issuer or unverified/missing mTLS accepted")
		}
	}
}
