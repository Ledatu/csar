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

func TestMCPTransportValidation(t *testing.T) {
	const valid = `
listen_addr: ":8080"
backend_tls_policies:
  router-client:
    cert_file: /etc/seller-router.pem
    key_file: /etc/seller-router-key.pem
authz:
  address: authz:9091
paths:
  /rpc:
    post:
      x-csar-authn-validate:
        mode: mcp
        introspection_endpoint: https://authn/delegate
        introspection_tls: router-client
        required_scope: analytics:read
      x-csar-authz:
        subject: "{header.X-Gateway-Subject}"
        resource: campaign_module
        action: analytics.read
        scope_type: tenant
        scope_id: "{header.X-Gateway-Tenant}"
      x-csar-backend:
        target_url: https://seller-mcp
        tls: router-client
`
	if _, err := Load(writeTemp(t, valid)); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, before, after string }{
		{"plaintext report destination", "https://seller-mcp", "http://seller-mcp"},
		{"missing backend client identity", "        tls: router-client", ""},
		{"unverified introspection", "    cert_file:", "    insecure_skip_verify: true\n    cert_file:"},
		{"cached exchange", "        mode: mcp", "        mode: mcp\n        cache_ttl: 10s"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Load(writeTemp(t, strings.Replace(valid, tc.before, tc.after, 1))); err == nil {
				t.Fatal("accepted unsafe MCP transport configuration")
			}
		})
	}
}

func TestServiceDelegationPolicy(t *testing.T) {
	const policy = `
listen_addr: ":8080"
backend_tls_policies:
  issuer-client: {cert_file: client.pem, key_file: client.key}
authz: {address: "authz:9091"}
paths:
  /projects/{project}/documents:
    get:
      x-csar-authn-validate:
        mode: grant-resource
        required_scope: documents:read
        audiences: ["https://projects.example"]
        resource_path_param: project
        introspection_endpoint: https://projects-issuer/v1/introspect
        introspection_tls: issuer-client
      x-csar-authz: {subject: "{header.X-Gateway-Subject}", resource: document, action: read, scope_type: tenant, scope_id: "{header.X-Gateway-Tenant}"}
      x-csar-backend: {target_url: "https://documents"}
`
	if _, err := ParseBytes([]byte(policy)); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, old, new string }{
		{"absent audience", `audiences: ["https://projects.example"]`, ""},
		{"ambiguous audience", `audiences: ["https://projects.example"]`, `audiences: [a,b]`},
		{"unknown route parameter", "resource_path_param: project", "resource_path_param: company"},
		{"unbound use", "resource_path_param: project", ""},
		{"unverified issuer", "cert_file: client.pem", "insecure_skip_verify: true, cert_file: client.pem"},
		{"cached use", "mode: grant-resource", "mode: grant-resource\n        cache_ttl: 1s"},
		{"no permission policy", `x-csar-authz: {subject: "{header.X-Gateway-Subject}", resource: document, action: read, scope_type: tenant, scope_id: "{header.X-Gateway-Tenant}"}`, ""},
		{"discovery with resource input", "mode: grant-resource", "mode: grant-discovery"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseBytes([]byte(strings.Replace(policy, tc.old, tc.new, 1))); err == nil {
				t.Fatal("unsafe delegation policy accepted")
			}
		})
	}
}
