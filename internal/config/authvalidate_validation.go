package config

import (
	"fmt"
	"net/textproto"
	"strings"
	"time"
)

func (c *Config) validateAuthValidate(a *AuthValidateConfig, path, method string) error {
	if a.Mode == "select" {
		parent := *a
		parent.Mode, parent.Methods = "", nil
		// A selector only carries methods; options belong on the chosen validator.
		if parent.Use != "" || parent.JWKSURL != "" || parent.JWKSTLS != "" || parent.SessionEndpoint != "" || parent.SessionTLS != "" || parent.IntrospectionEndpoint != "" || parent.IntrospectionTLS != "" || parent.RequiredScope != "" || parent.SellerPathParam != "" || parent.Issuer != "" || len(parent.Audiences) > 0 || parent.HeaderName != "" || parent.TokenPrefix != "" || parent.CookieName != "" || parent.CacheTTL.Duration != 0 || len(parent.ForwardHeaders) > 0 || len(parent.RequiredClaims) > 0 || len(parent.ForwardClaims) > 0 || len(parent.IssueTokens) > 0 {
			return fmt.Errorf("authentication select may only contain methods")
		}
		if len(a.Methods) < 2 || len(a.Methods) > 3 {
			return fmt.Errorf("authentication select requires 2..3 methods")
		}
		sources := map[string]bool{}
		for i := range a.Methods {
			child := &a.Methods[i]
			if child.Mode == "select" || len(child.Methods) > 0 || len(child.IssueTokens) > 0 {
				return fmt.Errorf("nested authentication selection is forbidden")
			}
			if err := c.validateAuthValidate(child, path, method); err != nil {
				return err
			}
			source, err := child.CredentialSource()
			if err != nil {
				return err
			}
			if sources[source] {
				return fmt.Errorf("authentication methods share credential source %s", source)
			}
			sources[source] = true
		}
		return nil
	}
	if len(a.Methods) > 0 {
		return fmt.Errorf("authentication methods require mode select")
	}
	switch a.Mode {
	case "session":
		if a.SessionEndpoint == "" {
			return fmt.Errorf("path %s method %s: x-csar-authn-validate.session_endpoint is required for session mode", path, method)
		}
		if !strings.HasPrefix(a.SessionEndpoint, "https://") && !strings.HasPrefix(a.SessionEndpoint, "http://") {
			return fmt.Errorf("path %s method %s: x-csar-authn-validate.session_endpoint must start with http:// or https://", path, method)
		}
		if a.CookieName == "" {
			return fmt.Errorf("path %s method %s: x-csar-authn-validate.cookie_name is required for session mode", path, method)
		}
	case "token":
		if len(a.IssueTokens) > 0 || a.CookieName != "" || a.HeaderName != "" || a.TokenPrefix != "" {
			return fmt.Errorf("path %s method %s: token mode cannot use session or JWT header options", path, method)
		}
		if !strings.HasPrefix(a.IntrospectionEndpoint, "https://") {
			return fmt.Errorf("path %s method %s: token introspection_endpoint must use https", path, method)
		}
		if a.IntrospectionTLS == "" {
			return fmt.Errorf("path %s method %s: token introspection_tls is required", path, method)
		}
		if _, ok := c.BackendTLSPolicies[a.IntrospectionTLS]; !ok {
			return fmt.Errorf("path %s method %s: token introspection_tls policy not found", path, method)
		}
		if a.RequiredScope == "" {
			return fmt.Errorf("path %s method %s: token required_scope is required", path, method)
		}
		if a.CacheTTL.Duration > 30*time.Second {
			return fmt.Errorf("path %s method %s: token cache_ttl exceeds 30s", path, method)
		}
	case "", "jwt":
		if len(a.IssueTokens) > 0 {
			return fmt.Errorf("path %s method %s: x-csar-authn-validate.issue_tokens requires mode \"session\"", path, method)
		}
		if a.JWKSURL == "" {
			return fmt.Errorf("path %s method %s: x-csar-authn-validate.jwks_url is required", path, method)
		}
		if !strings.HasPrefix(a.JWKSURL, "https://") && !strings.HasPrefix(a.JWKSURL, "http://") {
			return fmt.Errorf("path %s method %s: x-csar-authn-validate.jwks_url must start with http:// or https://", path, method)
		}
		if a.JWKSTLS != "" {
			if _, ok := c.BackendTLSPolicies[a.JWKSTLS]; !ok {
				return fmt.Errorf("path %s method %s: x-csar-authn-validate.jwks_tls policy %q not found in backend_tls_policies",
					path, method, a.JWKSTLS)
			}
		}
	default:
		return fmt.Errorf("path %s method %s: x-csar-authn-validate.mode %q is not recognized (expected \"jwt\", \"session\", or \"token\")", path, method, a.Mode)
	}
	for i := range a.IssueTokens {
		token := &a.IssueTokens[i]
		idx := fmt.Sprintf("[%d]", i)
		if token.Profile == "" {
			return fmt.Errorf("path %s method %s: x-csar-authn-validate.issue_tokens%s.profile is required", path, method, idx)
		}
		if token.InjectHeader == "" {
			return fmt.Errorf("path %s method %s: x-csar-authn-validate.issue_tokens%s.inject_header is required", path, method, idx)
		}
		token.InjectHeader = textproto.CanonicalMIMEHeaderKey(token.InjectHeader)
		if token.InjectFormat == "" {
			token.InjectFormat = "Bearer {token}"
		}
		if !strings.Contains(token.InjectFormat, "{token}") {
			return fmt.Errorf("path %s method %s: x-csar-authn-validate.issue_tokens%s.inject_format must contain {token}", path, method, idx)
		}
		switch token.OnMissingClaim {
		case "", "fail_closed":
			token.OnMissingClaim = "fail_closed"
		case "omit":
		default:
			return fmt.Errorf("path %s method %s: x-csar-authn-validate.issue_tokens%s.on_missing_claim must be \"fail_closed\" or \"omit\"", path, method, idx)
		}
	}
	return nil
}

// CredentialSource identifies a transport location, never the credential value.
func (a AuthValidateConfig) CredentialSource() (string, error) {
	switch a.Mode {
	case "session":
		return "cookie:" + a.CookieName, nil
	case "token":
		return "header:Authorization", nil
	case "", "jwt":
		if a.CookieName != "" {
			return "cookie:" + a.CookieName, nil
		}
		header := a.HeaderName
		if header == "" {
			header = "X-Csar-Authorization"
		}
		header = textproto.CanonicalMIMEHeaderKey(header)
		if header != "X-Csar-Authorization" && header != "Authorization" {
			return "", fmt.Errorf("authentication selection only supports Authorization and X-Csar-Authorization JWT headers")
		}
		return "header:" + header, nil
	default:
		return "", fmt.Errorf("unsupported authentication method %q", a.Mode)
	}
}
