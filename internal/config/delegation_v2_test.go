package config

import (
	"strings"
	"testing"

	"github.com/ledatu/csar-core/authntokens"
)

const delegationV2YAML = `listen_addr: ':8080'
backend_tls_policies:
  issuer: {cert_file: client.pem, key_file: client.key}
authz: {address: 'authz:9091'}
paths:
  /workspaces/{workspace}/facts:
    get:
      x-csar-authn-validate:
        mode: grant-resource-v2
        credential_profile: facts
        resource_namespace: workspace
        resource_path_param: workspace
        required_scope: facts:read
        audiences: ['https://facts.example.test']
        introspection_endpoint: https://id.example.test/internal/credentials/v2/introspect
        introspection_tls: issuer
      x-csar-authz: {subject: '{header.X-Gateway-Subject}', resource: facts, action: read, scope_type: tenant, scope_id: '{header.X-Gateway-Tenant}'}
      x-csar-backend: {target_url: 'https://facts.example.test'}
`

func TestV2RequiredBindingsAndCapability(t *testing.T) {
	cfg, err := ParseBytes([]byte(delegationV2YAML))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RequiredCapabilities()[DelegationV2Capability] != 2 {
		t.Fatal("required version not declared")
	}
	if cfg.CheckPolicySnapshot(nil) == nil {
		t.Fatal("old snapshot accepted")
	}
	cfg.PolicyVersions = PolicyCapabilities()
	if cfg.CheckPolicySnapshot(nil) != nil {
		t.Fatal("compatible snapshot rejected")
	}
	for _, tc := range []struct{ old, new string }{{"credential_profile: facts", ""}, {"resource_namespace: workspace", ""}, {"mode: grant-resource-v2", "mode: grant-resource"}, {"resource_path_param: workspace", "resource_path_param: other"}, {"mode: grant-resource-v2", "mode: grant-resource-v2\n        cache_ttl: 1s"}} {
		if _, err := ParseBytes([]byte(strings.Replace(delegationV2YAML, tc.old, tc.new, 1))); err == nil {
			t.Fatal("unsafe v2 config accepted", tc.old)
		}
	}
	a := AuthValidateConfig{Mode: authntokens.GrantResourceV2, Audiences: []string{"https://facts.test"}, RequiredScope: "facts:read", ResourcePathParam: "workspace"}
	if a.ValidateDelegationV2("/workspaces/{workspace}") == nil {
		t.Fatal("snapshot field loss became defaults")
	}
}

func TestNamedV2PolicyRequiresCapabilityAndCyclicReferenceDoesNotRecurse(t *testing.T) {
	c := &Config{AuthValidatePolicies: map[string]AuthValidateConfig{"v2": {Mode: authntokens.GrantDiscoveryV2}, "cycle": {Mode: "select", Methods: []AuthValidateConfig{{Use: "cycle"}}}}}
	if !c.AuthValidateNeedsDelegationV2(&AuthValidateConfig{Use: "v2"}) {
		t.Fatal("named v2 policy omitted capability")
	}
	if !c.AuthValidateNeedsDelegationV2(&AuthValidateConfig{Use: "cycle"}) {
		t.Fatal("invalid cyclic configuration did not fail closed")
	}
}
