package config

import "fmt"

const AccessResourceCapability = "csar.access_resource_version"
const AccountOriginCapability = "csar.account_origin_version"

const DelegationV2Capability = "csar.delegation_contract_version"
const AuditReleaseCapability = "csar.audit_release_policy_version"
const RequestQuotaCapability = "csar.request_quota_policy_version"
const UsageBudgetCapability = "csar.usage_budget_policy_version"
const ResponseCompressionCapability = "csar.response_compression_policy_version"

// PolicyCapabilities returns owned version metadata for distributed route
// semantics. New policies extend this registry instead of another wire field.
func PolicyCapabilities() map[string]uint32 {
	return map[string]uint32{AccessResourceCapability: 1, AccountOriginCapability: 1, AuditReleaseCapability: 1, UsageBudgetCapability: 1, RequestQuotaCapability: 1, DelegationV2Capability: 2, ResponseCompressionCapability: 1}
}

func (c *Config) RequiredCapabilities() map[string]uint32 {
	required := make(map[string]uint32)
	for _, methods := range c.Paths {
		for method := range methods {
			if methods[method].ResponseCompression != nil {
				required[ResponseCompressionCapability] = 1
			}
			if traffic := methods[method].Traffic; traffic != nil && len(traffic.Quotas) > 0 {
				required[RequestQuotaCapability] = 1
			}
			if methods[method].UsageBudget != nil {
				required[UsageBudgetCapability] = 1
			}
			if c.AuthValidateNeedsDelegationV2(methods[method].AuthValidate) {
				required[DelegationV2Capability] = 2
			}
			if c.AuthValidateNeedsAccessResource(methods[method].AuthValidate) {
				required[AccessResourceCapability] = 1
			}
			if methods[method].OriginBinding == "account" {
				required[AccountOriginCapability] = 1
			}
			if methods[method].AuditRelease {
				required[AuditReleaseCapability] = 1
			}
		}
	}
	return required
}

// CheckPolicySnapshot retains the last good router when an old coordinator
// cannot preserve an active policy, but permits explicit versioned removal.
func (c *Config) CheckPolicySnapshot(active map[string]uint32) error {
	if c.SnapshotOriginBindingMissing {
		return fmt.Errorf("coordinator dropped origin binding fields")
	}
	required := c.RequiredCapabilities()
	for name, version := range active {
		required[name] = version
	}
	for name, version := range PolicyCapabilities() {
		got := c.PolicyVersions[name]
		if got > version || required[name] != 0 && got != version {
			return fmt.Errorf("coordinator snapshot cannot preserve policy %s", name)
		}
	}
	return nil
}

func (c *Config) AuthValidateNeedsDelegationV2(a *AuthValidateConfig) bool {
	return c.authValidateNeeds(a, func(a *AuthValidateConfig) bool { return a.RequiresDelegationV2() })
}
func (c *Config) AuthValidateNeedsAccessResource(a *AuthValidateConfig) bool {
	return c.authValidateNeeds(a, func(a *AuthValidateConfig) bool { return a.Mode == "access-resource-v2" })
}
func (c *Config) authValidateNeeds(a *AuthValidateConfig, match func(*AuthValidateConfig) bool) bool {
	seen := map[string]bool{}
	var walk func(*AuthValidateConfig, int) bool
	walk = func(a *AuthValidateConfig, depth int) bool {
		if a == nil {
			return false
		}
		if depth > 8 {
			return true
		}
		if match(a) {
			return true
		}
		if a.Use != "" && c != nil {
			if seen[a.Use] {
				return true
			}
			seen[a.Use] = true
			p := c.AuthValidatePolicies[a.Use]
			if walk(&p, depth+1) {
				return true
			}
			delete(seen, a.Use)
		}
		for i := range a.Methods {
			if walk(&a.Methods[i], depth+1) {
				return true
			}
		}
		return false
	}
	return walk(a, 0)
}
