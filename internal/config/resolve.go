package config

import "fmt"

// ResolvePolicies runs all policy resolution steps in the correct order.
// Coordinator-driven snapshots use this without Validate() because snapshot
// configs omit root-only fields like listen_addr.
func (c *Config) ResolvePolicies() error {
	steps := []struct {
		name string
		fn   func() error
	}{
		{"security profiles", c.ResolveSecurityProfiles},
		{"throttle policies", c.ResolveThrottlePolicies},
		{"CORS policies", c.ResolveCORSPolicies},
		{"cache policies", c.ResolveCachePolicies},
		{"cache invalidation policies", c.ResolveCacheInvalidationPolicies},
		{"retry policies", c.ResolveRetryPolicies},
		{"redact policies", c.ResolveRedactPolicies},
		{"auth-validate policies", c.ResolveAuthValidatePolicies},
		{"authz policies", c.ResolveAuthzPolicies},
		{"backend TLS policies", c.ResolveBackendTLSPolicies},
	}
	for _, step := range steps {
		if err := step.fn(); err != nil {
			return fmt.Errorf("resolving %s: %w", step.name, err)
		}
	}
	return nil
}

// resolveAndValidate runs policy resolution then validates the fully-resolved
// config. Both Load() and ParseBytes() call this after environment variable expansion.
func (c *Config) resolveAndValidate() error {
	if err := c.ResolvePolicies(); err != nil {
		return err
	}
	if err := c.Validate(); err != nil {
		return fmt.Errorf("validating config: %w", err)
	}
	return nil
}
