package config

import "fmt"

// ResolveAuthValidatePolicies expands references, including selection methods.
func (c *Config) ResolveAuthValidatePolicies() error {
	for path, methods := range c.Paths {
		for method := range methods {
			route := methods[method]
			if route.AuthValidate == nil {
				continue
			}
			resolved, err := c.resolveAuthValidate(*route.AuthValidate, false)
			if err != nil {
				return fmt.Errorf("path %s method %s: %w", path, method, err)
			}
			if route.AuthValidate.Use != "" {
				annotatePolicy(&route, "x-csar-authn-validate", route.AuthValidate.Use)
			}
			route.AuthValidate = &resolved
			methods[method] = route
		}
	}
	return nil
}

func (c *Config) resolveAuthValidate(input AuthValidateConfig, terminal bool) (AuthValidateConfig, error) {
	policy := input
	if input.Use != "" {
		var ok bool
		policy, ok = c.AuthValidatePolicies[input.Use]
		if !ok {
			return input, fmt.Errorf("auth-validate policy %q not found", input.Use)
		}
		if policy.Use != "" {
			return input, fmt.Errorf("auth-validate policy references cannot chain")
		}
	}
	merged := policy
	if input.Mode != "" {
		merged.Mode = input.Mode
	}
	if input.JWKSURL != "" {
		merged.JWKSURL = input.JWKSURL
	}
	if input.JWKSTLS != "" {
		merged.JWKSTLS = input.JWKSTLS
	}
	if input.SessionEndpoint != "" {
		merged.SessionEndpoint = input.SessionEndpoint
	}
	if input.SessionTLS != "" {
		merged.SessionTLS = input.SessionTLS
	}
	if input.IntrospectionEndpoint != "" {
		merged.IntrospectionEndpoint = input.IntrospectionEndpoint
	}
	if input.IntrospectionTLS != "" {
		merged.IntrospectionTLS = input.IntrospectionTLS
	}
	if input.RequiredScope != "" {
		merged.RequiredScope = input.RequiredScope
	}
	if input.ResourcePathParam != "" {
		merged.ResourcePathParam = input.ResourcePathParam
	}
	if input.SellerPathParam != "" {
		merged.SellerPathParam = input.SellerPathParam
	}
	if len(input.ForwardHeaders) > 0 {
		merged.ForwardHeaders = input.ForwardHeaders
	}
	if input.Issuer != "" {
		merged.Issuer = input.Issuer
	}
	if len(input.Audiences) > 0 {
		merged.Audiences = input.Audiences
	}
	if input.HeaderName != "" {
		merged.HeaderName = input.HeaderName
	}
	if input.TokenPrefix != "" {
		merged.TokenPrefix = input.TokenPrefix
	}
	if input.CacheTTL.Duration != 0 {
		merged.CacheTTL = input.CacheTTL
	}
	if len(input.RequiredClaims) > 0 {
		merged.RequiredClaims = input.RequiredClaims
	}
	if len(input.ForwardClaims) > 0 {
		merged.ForwardClaims = input.ForwardClaims
	}
	if input.CookieName != "" {
		merged.CookieName = input.CookieName
	}
	if len(input.IssueTokens) > 0 {
		merged.IssueTokens = input.IssueTokens
	}

	if len(input.Methods) > 0 {
		merged.Methods = input.Methods
	}
	merged.Use = ""
	if terminal && (merged.Mode == "select" || len(merged.Methods) > 0) {
		return input, fmt.Errorf("nested authentication selection is forbidden")
	}
	merged.Methods = append([]AuthValidateConfig(nil), merged.Methods...)
	for i := range merged.Methods {
		resolved, err := c.resolveAuthValidate(merged.Methods[i], true)
		if err != nil {
			return input, err
		}
		merged.Methods[i] = resolved
	}
	return merged, nil
}
