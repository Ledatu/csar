package config

import (
	"strings"
	"testing"
)

const selectionYAML = `
listen_addr: :8080
auth_validate_policies:
  browser:
    mode: session
    session_endpoint: https://authn/auth/validate
    cookie_name: csar_session
  service:
    mode: jwt
    jwks_url: https://authn/jwks
    audiences: [catalog-reader]
  shared:
    mode: select
    methods: [browser, service]
paths:
  /catalog:
    get:
      x-csar-backend: {target_url: https://catalog}
      x-csar-authn-validate: shared
`

func TestLoadSelectionResolvesAndValidatesTerminalPolicies(t *testing.T) {
	cfg, err := ParseBytes([]byte(selectionYAML))
	if err != nil {
		t.Fatal(err)
	}
	a := cfg.Paths["/catalog"]["get"].AuthValidate
	if len(a.Methods) != 2 || a.Methods[0].SessionEndpoint != "https://authn/auth/validate" || a.Methods[1].JWKSURL != "https://authn/jwks" {
		t.Fatalf("incomplete methods: %+v", a)
	}
}

func TestLoadSelectionRejectsInvalidMethods(t *testing.T) {
	for _, replacement := range []string{
		"methods: [browser]",
		"methods: [browser, service, browser, service]",
		"methods: [browser, browser]",
		"methods: [browser, missing]",
		"methods: [browser, shared]",
		"methods: [browser, {mode: token}]",
		"methods: [browser, {mode: session, cookie_name: c}]",
		"methods: [browser, {mode: jwt}]",
		"methods: [browser, {mode: jwt, jwks_url: https://authn/jwks, header_name: X-Other}]",
		"cookie_name: c\n    methods: [browser, service]",
	} {
		t.Run(replacement, func(t *testing.T) {
			_, err := ParseBytes([]byte(strings.Replace(selectionYAML, "methods: [browser, service]", replacement, 1)))
			if err == nil {
				t.Fatal("accepted invalid selector")
			}
		})
	}
}
