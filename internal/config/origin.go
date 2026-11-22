package config

// OriginPolicyVersion and OriginPolicyCapability describe preservation support,
// not whether root issuance has been configured on a particular router.
const (
	OriginPolicyVersion    uint32 = 1
	OriginPolicyCapability        = "csar.origin_policy_version"
)

func (c *Config) HasOriginReceivers() bool {
	for _, methods := range c.Paths {
		for method := range methods {
			if methods[method].OriginReceiver != "" {
				return true
			}
		}
	}
	return false
}
