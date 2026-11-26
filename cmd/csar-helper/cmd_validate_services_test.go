package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const helperAuthnReceiver = `base_url: https://id.example.test
database: {dsn: postgres://fixture}
oauth: {enabled: false}
cookie: {secure: true}
audit_outbox_enabled: true
audit:
  router_base_url: https://router.example.test
  sts_endpoint: https://id.example.test/sts/token
  audience: https://router.example.test
  service_name: issuer
  assertion_audience: https://id.example.test/sts/token
  jwt: {private_key_file: /service/key.pem, public_key_file: /service/public.pem}
tls: {enabled: true, cert_file: /server/cert.pem, key_file: /server/key.pem, client_ca_file: /general/ca.pem}
credentials:
  version: 1
  enabled: true
  issuer_url: https://id.example.test
  consent_url: https://console.example.test/consent
  mutation_origins: [https://console.example.test]
  consent_cookie_name: __Host-credential-consent
  decisions:
    router_base_url: https://router.example.test
    sts_endpoint: https://id.example.test/sts/token
    audience: https://router.example.test
    service_name: issuer
    assertion_audience: https://id.example.test/sts/token
    router_timeout: 5s
    jwt: {private_key_file: /service/key.pem, public_key_file: /service/public.pem}
  trust_policies:
    - {id: ingress, ca_file: /dedicated/ca.pem, peer_cn: credentials-router}
  profiles:
    - id: facts
      revision: 2
      accepted_grant_revisions: [1, 2]
      audience: https://facts.example.test
      scopes: [{scope: 'facts:read', decision_profile: facts-reader}]
      namespaces: [workspace]
      selection_modes: [selected, current_and_future]
      access_ttl: 1h
      grant_ttl: 24h
      proof_ttl: 1m
      trust_policy: ingress
`

const helperAuthzReceiver = `admin:
  enabled: true
  allowed_client_cn: gateway
  tls: {cert_file: server.pem, key_file: key.pem, client_ca_file: ca.pem}
  service_assignable_roles: [reader]
policy:
  roles: [{name: reader}, {name: operator}]
service_policies:
  version: 1
  enabled: true
  decision_profiles:
    - id: reports
      audience: https://reports.example.test
      resource: report
      action: read
      bindings: [{namespace: workspace, scope_type: tenant, scope_id_prefix: 'workspace:'}]
  services:
    - subject: svc:writer
      operations:
        - {operation: grant_role, profiles: [reports], roles: [reader]}
        - {operation: list_scope_assignments, profiles: [reports]}
`

func TestServiceValidationCLIUsesMatchingReceiverPreflight(t *testing.T) {
	oldAuthn, oldAuthz := validateAuthnPath, validateAuthzPath
	t.Cleanup(func() { validateAuthnPath, validateAuthzPath = oldAuthn, oldAuthz })
	path := filepath.Join(t.TempDir(), "config.yaml")
	validateAuthnPath, validateAuthzPath = path, path
	for name, run := range map[string]struct {
		body    string
		check   func() error
		invalid []string
	}{
		"authn": {helperAuthnReceiver, func() error { return validateAuthnCmd.RunE(validateAuthnCmd, nil) }, []string{
			strings.Replace(helperAuthnReceiver, "cookie: {secure: true}", "cookie: {secure: false}", 1),
			strings.Replace(helperAuthnReceiver, "cookie: {secure: true}", "cookie: {name: __Host-credential-consent, secure: true}", 1),
			strings.Replace(helperAuthnReceiver, "audit_outbox_enabled: true", "audit_outbox_enabled: false", 1),
		}},
		"authz": {helperAuthzReceiver, func() error { return validateAuthzCmd.RunE(validateAuthzCmd, nil) }, []string{
			strings.Replace(helperAuthzReceiver, "allowed_client_cn: gateway", "allowed_client_cn: ''", 1),
			strings.Replace(helperAuthzReceiver, "client_ca_file: ca.pem", "client_ca_file: ''", 1),
			strings.Replace(helperAuthzReceiver, "roles: [reader]}", "roles: [operator]}", 1),
		}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(run.body), 0600); err != nil {
				t.Fatal(err)
			}
			if err := run.check(); err != nil {
				t.Fatal("compatible runtime config rejected", err)
			}
			for _, body := range run.invalid {
				if err := os.WriteFile(path, []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
				if err := run.check(); err == nil {
					t.Fatal("unsafe receiver config accepted")
				}
			}
		})
	}
}
