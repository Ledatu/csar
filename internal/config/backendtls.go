package config

import "fmt"

// ResolveBackendTLSPolicies replaces backend TLS policy references with the
// full BackendTLSConfig from backend_tls_policies. Inline fields override
// policy values (shallow merge). Must be called after Load / before Validate.
func (c *Config) ResolveBackendTLSPolicies() error {
	for path, methods := range c.Paths {
		for method := range methods {
			route := methods[method]
			bt := route.Backend.TLS
			if bt == nil || bt.Use == "" {
				continue
			}
			policyName := bt.Use
			if len(c.BackendTLSPolicies) == 0 {
				return fmt.Errorf("path %s method %s: backend TLS policy %q referenced but no backend_tls_policies defined",
					path, method, policyName)
			}
			policy, ok := c.BackendTLSPolicies[policyName]
			if !ok {
				return fmt.Errorf("path %s method %s: backend TLS policy %q not found in backend_tls_policies",
					path, method, policyName)
			}
			merged := BackendTLSConfig{
				InsecureSkipVerify: policy.InsecureSkipVerify,
				CAFile:             policy.CAFile,
				CertFile:           policy.CertFile,
				KeyFile:            policy.KeyFile,
			}
			if bt.CAFile != "" {
				merged.CAFile = bt.CAFile
			}
			if bt.CertFile != "" {
				merged.CertFile = bt.CertFile
			}
			if bt.KeyFile != "" {
				merged.KeyFile = bt.KeyFile
			}
			if bt.insecureSkipVerifySet {
				merged.InsecureSkipVerify = bt.InsecureSkipVerify
			}
			route.Backend.TLS = &merged
			annotatePolicy(&route, "x-csar-backend.tls", policyName)
			methods[method] = route
		}
	}
	return nil
}
