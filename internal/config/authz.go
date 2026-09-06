package config

import (
	"fmt"
	"strings"
)

// Scope types accepted by csar-authz.
const (
	AuthzScopePlatform = "platform"
	AuthzScopeTenant   = "tenant"
)

// authzInlinePolicyName labels a check declared inline on a route.
const authzInlinePolicyName = "inline"

// ResolveAuthzPolicies replaces authz policy references with fully resolved
// AuthzRouteConfig values. Terminal references shallow-merge inline overrides
// over the policy; composite (any_of) references expand into their branches.
// Every resolved config is validated here as well as in Validate, because
// coordinator snapshots run policy resolution without the full validator.
// Must be called after Load / before Validate.
func (c *Config) ResolveAuthzPolicies() error {
	for path, methods := range c.Paths {
		for method := range methods {
			route := methods[method]
			if route.Authz == nil {
				continue
			}
			resolved, err := c.resolveAuthzRoute(route.Authz)
			if err != nil {
				return fmt.Errorf("path %s method %s: x-csar-authz: %w", path, method, err)
			}
			if err := resolved.validate(); err != nil {
				return fmt.Errorf("path %s method %s: x-csar-authz %w", path, method, err)
			}
			route.Authz = resolved
			if label := resolved.policyLabel(); label != "" {
				annotatePolicy(&route, "x-csar-authz", label)
			}
			methods[method] = route
		}
	}
	return nil
}

func (c *Config) resolveAuthzRoute(a *AuthzRouteConfig) (*AuthzRouteConfig, error) {
	switch {
	case a.Use != "":
		return c.resolveAuthzRef(a)
	case a.IsComposite():
		if a.hasTerminalFields() {
			return nil, fmt.Errorf("any_of cannot be combined with subject/resource/action/scope fields")
		}
		branches, err := c.resolveAuthzBranches(a.AnyOf, authzInlinePolicyName)
		if err != nil {
			return nil, err
		}
		return &AuthzRouteConfig{AnyOf: branches, StripHeaders: a.StripHeaders}, nil
	default:
		resolved := *a
		resolved.PolicyName = authzInlinePolicyName
		return &resolved, nil
	}
}

func (c *Config) lookupAuthzPolicy(name string) (AuthzRouteConfig, error) {
	if len(c.AuthzPolicies) == 0 {
		return AuthzRouteConfig{}, fmt.Errorf("authz policy %q referenced but no authz_policies defined", name)
	}
	policy, ok := c.AuthzPolicies[name]
	if !ok {
		return AuthzRouteConfig{}, fmt.Errorf("authz policy %q not found in authz_policies", name)
	}
	if policy.Use != "" {
		return AuthzRouteConfig{}, fmt.Errorf("authz policy %q: policy definitions cannot use \"use\"", name)
	}
	if policy.IsComposite() && policy.hasTerminalFields() {
		return AuthzRouteConfig{}, fmt.Errorf("authz policy %q: any_of cannot be combined with subject/resource/action/scope fields", name)
	}
	return policy, nil
}

func (c *Config) resolveAuthzRef(ref *AuthzRouteConfig) (*AuthzRouteConfig, error) {
	policy, err := c.lookupAuthzPolicy(ref.Use)
	if err != nil {
		return nil, err
	}
	if ref.IsComposite() {
		return nil, fmt.Errorf("authz policy reference %q cannot be combined with any_of", ref.Use)
	}

	if policy.IsComposite() {
		if ref.hasTerminalFields() {
			return nil, fmt.Errorf("authz policy %q is composite (any_of); only strip_headers may be overridden", ref.Use)
		}
		branches, err := c.resolveAuthzBranches(policy.AnyOf, ref.Use)
		if err != nil {
			return nil, fmt.Errorf("authz policy %q: %w", ref.Use, err)
		}
		strip := policy.StripHeaders
		if len(ref.StripHeaders) > 0 {
			strip = ref.StripHeaders
		}
		return &AuthzRouteConfig{AnyOf: branches, StripHeaders: strip, PolicyName: ref.Use}, nil
	}

	merged := mergeAuthzTerminal(policy, ref)
	merged.PolicyName = ref.Use
	return &merged, nil
}

func (c *Config) resolveAuthzBranches(branches []AuthzRouteConfig, owner string) ([]AuthzRouteConfig, error) {
	resolved := make([]AuthzRouteConfig, 0, len(branches))
	for i := range branches {
		branch := &branches[i]
		if branch.IsComposite() {
			return nil, fmt.Errorf("any_of[%d]: nested any_of is not supported", i)
		}
		if len(branch.StripHeaders) > 0 {
			return nil, fmt.Errorf("any_of[%d]: strip_headers belongs on the route or the composite policy, not on a branch", i)
		}
		if branch.Use == "" {
			inline := *branch
			inline.PolicyName = fmt.Sprintf("%s[%d]", owner, i)
			resolved = append(resolved, inline)
			continue
		}
		policy, err := c.lookupAuthzPolicy(branch.Use)
		if err != nil {
			return nil, fmt.Errorf("any_of[%d]: %w", i, err)
		}
		if policy.IsComposite() {
			return nil, fmt.Errorf("any_of[%d]: policy %q is itself composite; branches must be terminal", i, branch.Use)
		}
		merged := mergeAuthzTerminal(policy, branch)
		merged.PolicyName = branch.Use
		resolved = append(resolved, merged)
	}
	return resolved, nil
}

// mergeAuthzTerminal overlays the non-empty terminal fields of ref onto policy.
func mergeAuthzTerminal(policy AuthzRouteConfig, ref *AuthzRouteConfig) AuthzRouteConfig {
	merged := policy
	if ref.Subject != "" {
		merged.Subject = ref.Subject
	}
	if ref.Resource != "" {
		merged.Resource = ref.Resource
	}
	if ref.Action != "" {
		merged.Action = ref.Action
	}
	if ref.ScopeType != "" {
		merged.ScopeType = ref.ScopeType
	}
	if ref.ScopeID != "" {
		merged.ScopeID = ref.ScopeID
	}
	if len(ref.StripHeaders) > 0 {
		merged.StripHeaders = ref.StripHeaders
	}
	merged.Use = ""
	return merged
}

// policyLabel names the resolved config for diagnostics: the referenced policy
// name, or the branch names of an inline any_of.
func (a *AuthzRouteConfig) policyLabel() string {
	if a.PolicyName != "" && a.PolicyName != authzInlinePolicyName {
		return a.PolicyName
	}
	if !a.IsComposite() {
		return ""
	}
	names := make([]string, 0, len(a.AnyOf))
	for i := range a.AnyOf {
		names = append(names, a.AnyOf[i].PolicyName)
	}
	return strings.Join(names, "|")
}

// validate checks a resolved authz config: every branch must be a complete
// terminal check with a scope csar-authz accepts.
func (a *AuthzRouteConfig) validate() error {
	if a.Use != "" {
		return fmt.Errorf("has unresolved policy reference %q — call ResolveAuthzPolicies() before Validate()", a.Use)
	}
	if !a.IsComposite() {
		return a.validateTerminal()
	}
	if a.hasTerminalFields() {
		return fmt.Errorf("any_of cannot be combined with subject/resource/action/scope fields")
	}
	for i := range a.AnyOf {
		branch := &a.AnyOf[i]
		if branch.IsComposite() {
			return fmt.Errorf("any_of[%d]: nested any_of is not supported", i)
		}
		if err := branch.validateTerminal(); err != nil {
			return fmt.Errorf("any_of[%d] (%s): %w", i, branch.PolicyName, err)
		}
	}
	return nil
}

func (a *AuthzRouteConfig) validateTerminal() error {
	if a.Subject == "" {
		return fmt.Errorf("subject is required")
	}
	if a.Resource == "" {
		return fmt.Errorf("resource is required")
	}
	if a.Action == "" {
		return fmt.Errorf("action is required")
	}
	switch a.ScopeType {
	case AuthzScopePlatform:
		if a.ScopeID != "" {
			return fmt.Errorf("scope_id must be empty when scope_type is %q", AuthzScopePlatform)
		}
	case AuthzScopeTenant:
		if a.ScopeID == "" {
			return fmt.Errorf("scope_id is required when scope_type is %q", AuthzScopeTenant)
		}
	case "":
		return fmt.Errorf("scope_type is required (%q or %q)", AuthzScopePlatform, AuthzScopeTenant)
	default:
		return fmt.Errorf("scope_type must be %q or %q, got %q", AuthzScopePlatform, AuthzScopeTenant, a.ScopeType)
	}
	return nil
}
