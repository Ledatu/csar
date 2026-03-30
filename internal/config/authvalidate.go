package config

import "fmt"

// ResolveAuthValidatePolicies replaces auth-validate policy references with
// the full AuthValidateConfig from auth_validate_policies. Inline fields
// override policy values (shallow merge). Must be called after Load / before Validate.
func (c *Config) ResolveAuthValidatePolicies() error {
	for path, methods := range c.Paths {
		for method := range methods {
			route := methods[method]
			if route.AuthValidate == nil || route.AuthValidate.Use == "" {
				continue
			}
			policyName := route.AuthValidate.Use
			if len(c.AuthValidatePolicies) == 0 {
				return fmt.Errorf("path %s method %s: auth-validate policy %q referenced but no auth_validate_policies defined",
					path, method, policyName)
			}
			policy, ok := c.AuthValidatePolicies[policyName]
			if !ok {
				return fmt.Errorf("path %s method %s: auth-validate policy %q not found in auth_validate_policies",
					path, method, policyName)
			}
			merged := policy
			if route.AuthValidate.Mode != "" {
				merged.Mode = route.AuthValidate.Mode
			}
			if route.AuthValidate.JWKSURL != "" {
				merged.JWKSURL = route.AuthValidate.JWKSURL
			}
			if route.AuthValidate.JWKSTLS != "" {
				merged.JWKSTLS = route.AuthValidate.JWKSTLS
			}
			if route.AuthValidate.SessionEndpoint != "" {
				merged.SessionEndpoint = route.AuthValidate.SessionEndpoint
			}
			if route.AuthValidate.SessionTLS != "" {
				merged.SessionTLS = route.AuthValidate.SessionTLS
			}
			if len(route.AuthValidate.ForwardHeaders) > 0 {
				merged.ForwardHeaders = route.AuthValidate.ForwardHeaders
			}
			if route.AuthValidate.Issuer != "" {
				merged.Issuer = route.AuthValidate.Issuer
			}
			if len(route.AuthValidate.Audiences) > 0 {
				merged.Audiences = route.AuthValidate.Audiences
			}
			if route.AuthValidate.HeaderName != "" {
				merged.HeaderName = route.AuthValidate.HeaderName
			}
			if route.AuthValidate.TokenPrefix != "" {
				merged.TokenPrefix = route.AuthValidate.TokenPrefix
			}
			if route.AuthValidate.CacheTTL.Duration != 0 {
				merged.CacheTTL = route.AuthValidate.CacheTTL
			}
			if len(route.AuthValidate.RequiredClaims) > 0 {
				merged.RequiredClaims = route.AuthValidate.RequiredClaims
			}
			if len(route.AuthValidate.ForwardClaims) > 0 {
				merged.ForwardClaims = route.AuthValidate.ForwardClaims
			}
			if route.AuthValidate.CookieName != "" {
				merged.CookieName = route.AuthValidate.CookieName
			}
			merged.Use = ""
			route.AuthValidate = &merged
			annotatePolicy(&route, "x-csar-authn-validate", policyName)
			methods[method] = route
		}
	}
	return nil
}
