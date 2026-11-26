package config

import (
	"fmt"
	"net/textproto"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/ledatu/csar-core/authntokens"
	"github.com/ledatu/csar-core/gatewayctx"
)

func (c *Config) validateAuthValidate(a *AuthValidateConfig, path, method string) error {
	if err := a.ValidateDelegationV2(path); err != nil {
		return err
	}
	if a.Mode == "select" {
		if err := a.ValidateSelection(); err != nil {
			return fmt.Errorf("path %s method %s: %w", path, method, err)
		}
		for i := range a.Methods {
			if err := c.validateAuthValidate(&a.Methods[i], path, method); err != nil {
				return err
			}
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
	case "token", "mcp", "mcp-account", "delegated", "delegated-discovery", authntokens.GrantExchange, authntokens.GrantDiscovery, authntokens.GrantResource, authntokens.GrantExchangeV2, authntokens.GrantDiscoveryV2, authntokens.GrantResourceV2, authntokens.AccessResourceV2:
		if authntokens.IsDelegation(a.Mode) || authntokens.IsDelegationV2(a.Mode) {
			if len(a.Audiences) != 1 || strings.TrimSpace(a.Audiences[0]) == "" || a.SellerPathParam != "" {
				return fmt.Errorf("path %s method %s: delegation requires one audience and forbids seller_path_param", path, method)
			}
			if (a.Mode == authntokens.GrantResource || a.Mode == authntokens.GrantResourceV2 || a.Mode == authntokens.AccessResourceV2) != (a.ResourcePathParam != "") ||
				(a.ResourcePathParam != "" && !strings.Contains(path, "{"+a.ResourcePathParam+"}")) {
				return fmt.Errorf("path %s method %s: grant-resource requires a matched resource_path_param", path, method)
			}
		} else if a.ResourcePathParam != "" {
			return fmt.Errorf("resource_path_param requires grant-resource")
		}
		if len(a.IssueTokens) > 0 || a.CookieName != "" || a.HeaderName != "" || a.TokenPrefix != "" {
			return fmt.Errorf("path %s method %s: token mode cannot use session or JWT header options", path, method)
		}
		if !strings.HasPrefix(a.IntrospectionEndpoint, "https://") {
			return fmt.Errorf("path %s method %s: token introspection_endpoint must use https", path, method)
		}
		if a.IntrospectionTLS == "" {
			return fmt.Errorf("path %s method %s: token introspection_tls is required", path, method)
		}
		policy, ok := c.BackendTLSPolicies[a.IntrospectionTLS]
		if !ok {
			return fmt.Errorf("path %s method %s: token introspection_tls policy not found", path, method)
		}
		if a.Mode != "token" && (policy.CertFile == "" || policy.KeyFile == "" || policy.InsecureSkipVerify) {
			return fmt.Errorf("path %s method %s: %s introspection requires verified mutual TLS", path, method, a.Mode)
		}
		if a.RequiredScope == "" {
			return fmt.Errorf("path %s method %s: token required_scope is required", path, method)
		}
		if a.Mode != "token" && a.CacheTTL.Duration != 0 {
			return fmt.Errorf("path %s method %s: %s credentials require per-request introspection", path, method, a.Mode)
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
		return fmt.Errorf("path %s method %s: x-csar-authn-validate.mode %q is not recognized (expected a supported authentication mode)", path, method, a.Mode)
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

// ValidateSelection is shared by config loading and route construction so a
// programmatically constructed route cannot bypass the selector invariants.
func (a *AuthValidateConfig) ValidateSelection() error {
	if a.Mode != "select" {
		return fmt.Errorf("authentication selection requires mode select")
	}
	// Reject any validator option, including fields added to the config later.
	options := *a
	options.Mode, options.Methods = "", nil
	if !reflect.ValueOf(options).IsZero() {
		return fmt.Errorf("authentication select may only contain methods")
	}
	if len(a.Methods) < 2 || len(a.Methods) > 3 {
		return fmt.Errorf("authentication select requires 2..3 methods")
	}
	sources := make(map[string]bool, len(a.Methods))
	for i := range a.Methods {
		child := &a.Methods[i]
		if child.Mode == "select" || len(child.Methods) > 0 {
			return fmt.Errorf("nested authentication selection is forbidden")
		}
		if len(child.IssueTokens) > 0 {
			return fmt.Errorf("authentication selection does not support session token issuance")
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

// CredentialSource identifies a transport location, never the credential value.
func (a AuthValidateConfig) CredentialSource() (string, error) {
	switch a.Mode {
	case "session":
		if a.CookieName == "" {
			return "", fmt.Errorf("session credential source requires a cookie_name")
		}
		return "cookie:" + a.CookieName, nil
	case "mcp", "mcp-account", authntokens.GrantExchange, authntokens.GrantExchangeV2:
		return "", fmt.Errorf("MCP ingress requires a dedicated route")
	case "delegated", "delegated-discovery", authntokens.GrantDiscovery, authntokens.GrantResource, authntokens.GrantDiscoveryV2, authntokens.GrantResourceV2:
		return "header:" + gatewayctx.HeaderCsarAuthorization, nil
	case "token", authntokens.AccessResourceV2:
		return "header:Authorization", nil
	case "", "jwt":
		if a.CookieName != "" {
			return "cookie:" + a.CookieName, nil
		}
		header := a.HeaderName
		if header == "" {
			header = gatewayctx.HeaderCsarAuthorization
		}
		header = textproto.CanonicalMIMEHeaderKey(header)
		if header != gatewayctx.HeaderCsarAuthorization && header != "Authorization" {
			return "", fmt.Errorf("authentication selection only supports Authorization and X-Csar-Authorization JWT headers")
		}
		return "header:" + header, nil
	default:
		return "", fmt.Errorf("unsupported authentication method %q", a.Mode)
	}
}

func (a *AuthValidateConfig) hasMode(modes ...string) bool {
	if slices.Contains(modes, a.Mode) {
		return true
	}
	for i := range a.Methods {
		if slices.Contains(modes, a.Methods[i].Mode) {
			return true
		}
	}
	return false
}

// ValidateGrantCache also applies when the router builds routes from a coordinator snapshot.
func (r *RouteConfig) ValidateGrantCache() error {
	if r.Cache != nil && r.Cache.IsEnabled() && r.AuthValidate != nil &&
		r.AuthValidate.hasMode(authntokens.GrantExchange, authntokens.GrantDiscovery, authntokens.GrantExchangeV2, authntokens.GrantDiscoveryV2) {
		return fmt.Errorf("delegated exchange and discovery routes must reach their owner on every request; disable response caching")
	}
	return nil
}

func (a *AuthValidateConfig) RequiresDelegationV2() bool {
	return a != nil && a.hasMode(authntokens.GrantExchangeV2, authntokens.GrantDiscoveryV2, authntokens.GrantResourceV2, authntokens.AccessResourceV2)
}

// Required independently on snapshot rebuilds: dropped new fields never default.
func (a *AuthValidateConfig) ValidateDelegationV2(path string) error {
	if a == nil {
		return nil
	}
	if a.Mode == "select" {
		for i := range a.Methods {
			if err := a.Methods[i].ValidateDelegationV2(path); err != nil {
				return err
			}
		}
	}
	if !authntokens.IsDelegationV2(a.Mode) {
		if a.CredentialProfile != "" || a.ResourceNamespace != "" {
			return fmt.Errorf("v2 bindings require a v2 mode")
		}
		return nil
	}
	if !authntokens.ValidProfileID(a.CredentialProfile) || !authntokens.ValidNamespace(a.ResourceNamespace) || len(a.Audiences) != 1 || !authntokens.ValidAudience(a.Audiences[0]) || !authntokens.ValidScope(a.RequiredScope) || a.SellerPathParam != "" || a.CacheTTL.Duration != 0 {
		return fmt.Errorf("invalid required v2 delegation bindings")
	}
	resource := a.Mode == authntokens.GrantResourceV2 || a.Mode == authntokens.AccessResourceV2
	if resource != (a.ResourcePathParam != "") || resource && !strings.Contains(path, "{"+a.ResourcePathParam+"}") {
		return fmt.Errorf("v2 resource requires a matched route parameter")
	}
	return nil
}

func (c *Config) ValidateRouteDelegationV2(a *AuthValidateConfig, path string, hasAuthz bool) error {
	if a == nil {
		return nil
	}
	if a.Mode == "select" {
		for i := range a.Methods {
			if err := c.ValidateRouteDelegationV2(&a.Methods[i], path, hasAuthz); err != nil {
				return err
			}
		}
		return nil
	}
	if !authntokens.IsDelegationV2(a.Mode) {
		return nil
	}
	if err := c.validateAuthValidate(a, path, ""); err != nil {
		return err
	}
	if (a.Mode == authntokens.GrantResourceV2 || a.Mode == authntokens.AccessResourceV2) && !hasAuthz {
		return fmt.Errorf("v2 resource requires authorization")
	}
	return nil
}

func (a *AuthValidateConfig) ForwardsDelegationV2() bool {
	return a != nil && a.hasMode(authntokens.GrantExchangeV2)
}
