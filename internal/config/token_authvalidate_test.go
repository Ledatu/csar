package config

import (
	"strings"
	"testing"
)

func TestLoadTokenAuthValidatePolicy(t *testing.T) {
	config := `
listen_addr: ":8080"
backend_tls_policies:
  authn-mtls:
    ca_file: /etc/ca.pem
    cert_file: /etc/client.pem
    key_file: /etc/client-key.pem
auth_validate_policies:
  personal-key:
    mode: token
    introspection_endpoint: https://authn:8081/auth/token/introspect
    introspection_tls: authn-mtls
    required_scope: adverts:read
    seller_path_param: seller_id
    cache_ttl: 15s
paths:
  /v1/wildberries/{seller_id}/adverts/bidder-settings:
    get:
      x-csar-backend:
        target_url: https://api:8080
      x-csar-authn-validate: personal-key
`
	cfg, err := Load(writeTemp(t, config))
	if err != nil {
		t.Fatal(err)
	}
	auth := cfg.Paths["/v1/wildberries/{seller_id}/adverts/bidder-settings"]["get"].AuthValidate
	if auth == nil || auth.Mode != "token" || auth.RequiredScope != "adverts:read" {
		t.Fatalf("token policy not resolved: %+v", auth)
	}
	if _, err := Load(writeTemp(t, strings.Replace(config, "cache_ttl: 15s", "cache_ttl: 31s", 1))); err == nil {
		t.Fatal("token introspection cache over 30 seconds must be rejected")
	}
	if _, err := Load(writeTemp(t, strings.Replace(config, "https://authn", "http://authn", 1))); err == nil {
		t.Fatal("plaintext token introspection must be rejected")
	}
}
