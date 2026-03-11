package config

import "fmt"

// ResolveRetryPolicies replaces retry policy references with the full
// RetryConfig from retry_policies. Inline fields override policy values
// (shallow merge). Must be called after Load / before Validate.
func (c *Config) ResolveRetryPolicies() error {
	for path, methods := range c.Paths {
		for method := range methods {
			route := methods[method]
			if route.Retry == nil || route.Retry.Use == "" {
				continue
			}
			policyName := route.Retry.Use
			if len(c.RetryPolicies) == 0 {
				return fmt.Errorf("path %s method %s: retry policy %q referenced but no retry_policies defined",
					path, method, policyName)
			}
			policy, ok := c.RetryPolicies[policyName]
			if !ok {
				return fmt.Errorf("path %s method %s: retry policy %q not found in retry_policies",
					path, method, policyName)
			}
			merged := policy
			if route.Retry.MaxAttempts != 0 {
				merged.MaxAttempts = route.Retry.MaxAttempts
			}
			if route.Retry.Backoff.Duration != 0 {
				merged.Backoff = route.Retry.Backoff
			}
			if route.Retry.MaxBackoff.Duration != 0 {
				merged.MaxBackoff = route.Retry.MaxBackoff
			}
			if len(route.Retry.RetryableStatusCodes) > 0 {
				merged.RetryableStatusCodes = route.Retry.RetryableStatusCodes
			}
			if len(route.Retry.RetryableMethods) > 0 {
				merged.RetryableMethods = route.Retry.RetryableMethods
			}
			if route.Retry.AutoRetry429 {
				merged.AutoRetry429 = route.Retry.AutoRetry429
			}
			if route.Retry.MaxInternalWait.Duration != 0 {
				merged.MaxInternalWait = route.Retry.MaxInternalWait
			}
			merged.Use = ""
			route.Retry = &merged
			annotatePolicy(&route, "x-csar-retry", policyName)
			methods[method] = route
		}
	}
	return nil
}
