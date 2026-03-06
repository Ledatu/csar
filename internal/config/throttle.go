package config

import "fmt"

// ResolveThrottlePolicies replaces throttle policy references with the full
// ThrottlingPolicy from throttling_policies. Inline fields override policy
// values (shallow merge). Must be called after Load / before Validate.
func (c *Config) ResolveThrottlePolicies() error {
	for path, methods := range c.Paths {
		for method, route := range methods {
			if route.Traffic == nil || route.Traffic.Use == "" {
				continue
			}
			policyName := route.Traffic.Use
			if len(c.ThrottlingPolicies) == 0 {
				return fmt.Errorf("path %s method %s: throttle policy %q referenced but no throttling_policies defined",
					path, method, policyName)
			}
			policy, ok := c.ThrottlingPolicies[policyName]
			if !ok {
				return fmt.Errorf("path %s method %s: throttle policy %q not found in throttling_policies",
					path, method, policyName)
			}
			// Merge: inline fields override policy defaults.
			merged := route.Traffic
			if merged.RPS == 0 {
				merged.RPS = policy.RPS
			}
			if merged.Burst == 0 {
				merged.Burst = policy.Burst
			}
			if merged.MaxWait.Duration == 0 {
				merged.MaxWait = policy.MaxWait
			}
			if merged.Backend == "" {
				merged.Backend = policy.Backend
			}
			if merged.Key == "" {
				merged.Key = policy.Key
			}
			if len(merged.ExcludeIPs) == 0 {
				merged.ExcludeIPs = policy.ExcludeIPs
			}
			if len(merged.VIPOverrides) == 0 {
				merged.VIPOverrides = policy.VIPOverrides
			}
			merged.Use = "" // clear ref after resolution
			route.Traffic = merged
			annotatePolicy(&route, "x-csar-traffic", policyName)
			methods[method] = route
		}
	}
	return nil
}
