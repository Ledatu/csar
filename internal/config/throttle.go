package config

import "fmt"

// ResolveThrottlePolicies replaces throttle policy references with the full
// ThrottlingPolicy from throttling_policies. Inline fields override policy
// values (shallow merge). Must be called after Load / before Validate.
func (c *Config) ResolveThrottlePolicies() error {
	for name := range c.ThrottlingPolicies {
		policy := c.ThrottlingPolicies[name]
		if err := normalizeRate(&policy.RPS, &policy.Requests, &policy.Period); err != nil {
			return fmt.Errorf("throttling_policies.%s: %w", name, err)
		}
		c.ThrottlingPolicies[name] = policy
	}
	if global := c.GlobalThrottle; global != nil {
		if err := normalizeRate(&global.RPS, &global.Requests, &global.Period); err != nil {
			return fmt.Errorf("global_throttle: %w", err)
		}
	}
	for path, methods := range c.Paths {
		for method := range methods {
			route := methods[method]
			if route.Traffic == nil {
				continue
			}
			if err := normalizeRate(&route.Traffic.RPS, &route.Traffic.Requests, &route.Traffic.Period); err != nil {
				return fmt.Errorf("path %s method %s: x-csar-traffic: %w", path, method, err)
			}
			if route.Traffic.Use == "" {
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
			if merged.AdaptiveBackpressure == nil && policy.AdaptiveBackpressure != nil {
				adaptive := *policy.AdaptiveBackpressure
				adaptive.RespectHeaders = append([]string(nil), adaptive.RespectHeaders...)
				merged.AdaptiveBackpressure = &adaptive
			}
			if merged.ClientLimitMode == "" {
				merged.ClientLimitMode = policy.ClientLimitMode
			}
			merged.Use = "" // clear ref after resolution
			route.Traffic = merged
			annotatePolicy(&route, "x-csar-traffic", policyName)
			methods[method] = route
		}
	}
	return nil
}
