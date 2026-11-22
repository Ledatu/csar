package config

import "fmt"

const AuditReleaseCapability = "csar.audit_release_policy_version"

// PolicyCapabilities returns owned version metadata for distributed route
// semantics. New policies extend this registry instead of another wire field.
func PolicyCapabilities() map[string]uint32 {
	return map[string]uint32{AuditReleaseCapability: 1}
}

func (c *Config) RequiredCapabilities() map[string]uint32 {
	required := make(map[string]uint32)
	for _, methods := range c.Paths {
		for method := range methods {
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
