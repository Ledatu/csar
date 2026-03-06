package config

import "fmt"

// ResolveRedactPolicies replaces redact policy references with the full
// RedactConfig from redact_policies. Inline fields override policy values
// (shallow merge). Must be called after Load / before Validate.
func (c *Config) ResolveRedactPolicies() error {
	for path, methods := range c.Paths {
		for method, route := range methods {
			if route.Redact == nil || route.Redact.Use == "" {
				continue
			}
			policyName := route.Redact.Use
			if len(c.RedactPolicies) == 0 {
				return fmt.Errorf("path %s method %s: redact policy %q referenced but no redact_policies defined",
					path, method, policyName)
			}
			policy, ok := c.RedactPolicies[policyName]
			if !ok {
				return fmt.Errorf("path %s method %s: redact policy %q not found in redact_policies",
					path, method, policyName)
			}
			merged := policy
			if len(route.Redact.Fields) > 0 {
				merged.Fields = route.Redact.Fields
			}
			if route.Redact.Mask != "" {
				merged.Mask = route.Redact.Mask
			}
			if route.Redact.Enabled != nil {
				merged.Enabled = route.Redact.Enabled
			}
			merged.Use = ""
			route.Redact = &merged
			annotatePolicy(&route, "x-csar-redact", policyName)
			methods[method] = route
		}
	}
	return nil
}
