package config

import "fmt"

// ResolveAuthzPolicies replaces authz policy references with the full
// AuthzRouteConfig from authz_policies. Inline fields override policy values
// (shallow merge). Must be called after Load / before Validate.
func (c *Config) ResolveAuthzPolicies() error {
	for path, methods := range c.Paths {
		for method := range methods {
			route := methods[method]
			if route.Authz == nil || route.Authz.Use == "" {
				continue
			}
			policyName := route.Authz.Use
			if len(c.AuthzPolicies) == 0 {
				return fmt.Errorf("path %s method %s: authz policy %q referenced but no authz_policies defined",
					path, method, policyName)
			}
			policy, ok := c.AuthzPolicies[policyName]
			if !ok {
				return fmt.Errorf("path %s method %s: authz policy %q not found in authz_policies",
					path, method, policyName)
			}
			merged := policy
			if route.Authz.Subject != "" {
				merged.Subject = route.Authz.Subject
			}
			if route.Authz.Resource != "" {
				merged.Resource = route.Authz.Resource
			}
			if route.Authz.Action != "" {
				merged.Action = route.Authz.Action
			}
			if route.Authz.ScopeType != "" {
				merged.ScopeType = route.Authz.ScopeType
			}
			if route.Authz.ScopeID != "" {
				merged.ScopeID = route.Authz.ScopeID
			}
			if len(route.Authz.StripHeaders) > 0 {
				merged.StripHeaders = route.Authz.StripHeaders
			}
			merged.Use = ""
			route.Authz = &merged
			annotatePolicy(&route, "x-csar-authz", policyName)
			methods[method] = route
		}
	}
	return nil
}
