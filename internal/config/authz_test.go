package config

import "testing"

func TestResolveAuthzPolicies_BareRef(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		AuthzPolicies: map[string]AuthzRouteConfig{
			"audit-admin-read": {
				Subject:   "{header.X-Gateway-Subject}",
				Resource:  "admin",
				Action:    "admin.audit.read",
				ScopeType: "platform",
			},
		},
		Paths: map[string]PathConfig{
			"/admin/audit": {
				"get": RouteConfig{
					Backend: BackendConfig{TargetURL: "https://audit:8083"},
					Authz:   &AuthzRouteConfig{Use: "audit-admin-read"},
				},
			},
		},
	}

	if err := cfg.ResolveAuthzPolicies(); err != nil {
		t.Fatalf("ResolveAuthzPolicies() error: %v", err)
	}

	authz := cfg.Paths["/admin/audit"]["get"].Authz
	if authz.Subject != "{header.X-Gateway-Subject}" {
		t.Errorf("Subject = %q, want {header.X-Gateway-Subject}", authz.Subject)
	}
	if authz.Resource != "admin" {
		t.Errorf("Resource = %q, want admin", authz.Resource)
	}
	if authz.Action != "admin.audit.read" {
		t.Errorf("Action = %q, want admin.audit.read", authz.Action)
	}
	if authz.ScopeType != "platform" {
		t.Errorf("ScopeType = %q, want platform", authz.ScopeType)
	}
	if authz.Use != "" {
		t.Errorf("Use = %q, should be empty after resolution", authz.Use)
	}
}

func TestResolveAuthzPolicies_InlineOverride(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		AuthzPolicies: map[string]AuthzRouteConfig{
			"base": {
				Subject:   "{header.X-Gateway-Subject}",
				Resource:  "campaign",
				Action:    "read",
				ScopeType: "tenant",
				ScopeID:   "{path.id}",
			},
		},
		Paths: map[string]PathConfig{
			"/campaigns/{id}": {
				"delete": RouteConfig{
					Backend: BackendConfig{TargetURL: "https://campaigns:8080"},
					Authz: &AuthzRouteConfig{
						Use:    "base",
						Action: "archive",
					},
				},
			},
		},
	}

	if err := cfg.ResolveAuthzPolicies(); err != nil {
		t.Fatalf("ResolveAuthzPolicies() error: %v", err)
	}

	authz := cfg.Paths["/campaigns/{id}"]["delete"].Authz
	if authz.Action != "archive" {
		t.Errorf("Action = %q, want archive (inline override)", authz.Action)
	}
	if authz.Subject != "{header.X-Gateway-Subject}" {
		t.Errorf("Subject = %q, want {header.X-Gateway-Subject} (from policy)", authz.Subject)
	}
	if authz.Resource != "campaign" {
		t.Errorf("Resource = %q, want campaign (from policy)", authz.Resource)
	}
}

func TestResolveAuthzPolicies_NotFound(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Paths: map[string]PathConfig{
			"/test": {
				"get": RouteConfig{
					Backend: BackendConfig{TargetURL: "https://test:8080"},
					Authz:   &AuthzRouteConfig{Use: "nonexistent"},
				},
			},
		},
	}

	if err := cfg.ResolveAuthzPolicies(); err == nil {
		t.Fatal("expected error for missing authz policy, got nil")
	}
}

func TestResolveAuthzPolicies_SetsPolicyName(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		AuthzPolicies: map[string]AuthzRouteConfig{
			"campaign-tenant-read": {
				Subject:   "{header.X-Gateway-Subject}",
				Resource:  "campaign",
				Action:    "read",
				ScopeType: "tenant",
				ScopeID:   "{path.marketplace}:{path.external_id}",
			},
		},
		Paths: map[string]PathConfig{
			"/campaigns/{marketplace}/{external_id}": {
				"get": RouteConfig{
					Backend: BackendConfig{TargetURL: "https://campaigns:8082"},
					Authz:   &AuthzRouteConfig{Use: "campaign-tenant-read"},
				},
				"post": RouteConfig{
					Backend: BackendConfig{TargetURL: "https://campaigns:8082"},
					Authz: &AuthzRouteConfig{
						Subject:   "{header.X-Gateway-Subject}",
						Resource:  "campaign",
						Action:    "write",
						ScopeType: "platform",
					},
				},
			},
		},
	}

	if err := cfg.ResolveAuthzPolicies(); err != nil {
		t.Fatalf("ResolveAuthzPolicies() error: %v", err)
	}
	if got := cfg.Paths["/campaigns/{marketplace}/{external_id}"]["get"].Authz.PolicyName; got != "campaign-tenant-read" {
		t.Errorf("PolicyName = %q, want campaign-tenant-read", got)
	}
	if got := cfg.Paths["/campaigns/{marketplace}/{external_id}"]["post"].Authz.PolicyName; got != "inline" {
		t.Errorf("inline PolicyName = %q, want inline", got)
	}
}

func compositeFixture() *Config {
	return &Config{
		ListenAddr: ":8080",
		AuthzPolicies: map[string]AuthzRouteConfig{
			"campaign-tenant-read": {
				Subject:   "{header.X-Gateway-Subject}",
				Resource:  "campaign",
				Action:    "read",
				ScopeType: "tenant",
				ScopeID:   "{path.marketplace}:{path.external_id}",
			},
			"campaign-platform-read": {
				Subject:   "{header.X-Gateway-Subject}",
				Resource:  "campaign",
				Action:    "read",
				ScopeType: "platform",
			},
			"campaign-read": {
				AnyOf: []AuthzRouteConfig{
					{Use: "campaign-tenant-read"},
					{Use: "campaign-platform-read"},
				},
			},
		},
		Paths: map[string]PathConfig{},
	}
}

func TestResolveAuthzPolicies_CompositePolicyRef(t *testing.T) {
	cfg := compositeFixture()
	cfg.Paths["/campaigns/{marketplace}/{external_id}"] = PathConfig{
		"get": RouteConfig{
			Backend: BackendConfig{TargetURL: "https://campaigns:8082"},
			Authz:   &AuthzRouteConfig{Use: "campaign-read", StripHeaders: []string{"X-User-Roles"}},
		},
	}

	if err := cfg.ResolveAuthzPolicies(); err != nil {
		t.Fatalf("ResolveAuthzPolicies() error: %v", err)
	}
	route := cfg.Paths["/campaigns/{marketplace}/{external_id}"]["get"]
	authz := route.Authz
	if !authz.IsComposite() {
		t.Fatal("expected composite authz config")
	}
	if authz.Use != "" || authz.hasTerminalFields() {
		t.Errorf("composite config must not carry use/terminal fields: %+v", authz)
	}
	if authz.PolicyName != "campaign-read" {
		t.Errorf("PolicyName = %q, want campaign-read", authz.PolicyName)
	}
	if len(authz.AnyOf) != 2 {
		t.Fatalf("len(AnyOf) = %d, want 2", len(authz.AnyOf))
	}
	tenant, platform := authz.AnyOf[0], authz.AnyOf[1]
	if tenant.PolicyName != "campaign-tenant-read" || tenant.ScopeType != "tenant" || tenant.ScopeID == "" || tenant.Use != "" {
		t.Errorf("branch 0 not resolved from campaign-tenant-read: %+v", tenant)
	}
	if platform.PolicyName != "campaign-platform-read" || platform.ScopeType != "platform" || platform.Use != "" {
		t.Errorf("branch 1 not resolved from campaign-platform-read: %+v", platform)
	}
	if len(authz.StripHeaders) != 1 || authz.StripHeaders[0] != "X-User-Roles" {
		t.Errorf("StripHeaders = %v, want route-level override kept", authz.StripHeaders)
	}
	if route.SourceInfo["x-csar-authz"].Policy != "campaign-read" {
		t.Errorf("SourceInfo policy = %q, want campaign-read", route.SourceInfo["x-csar-authz"].Policy)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error: %v", err)
	}
}

func TestResolveAuthzPolicies_InlineAnyOf(t *testing.T) {
	cfg := compositeFixture()
	cfg.Paths["/arts/{marketplace}/{external_id}"] = PathConfig{
		"get": RouteConfig{
			Backend: BackendConfig{TargetURL: "https://arts:8080"},
			Authz: &AuthzRouteConfig{
				AnyOf: []AuthzRouteConfig{
					{Use: "campaign-tenant-read", Resource: "arts"},
					{
						Subject:   "{header.X-Gateway-Subject}",
						Resource:  "arts",
						Action:    "read",
						ScopeType: "platform",
					},
				},
			},
		},
	}

	if err := cfg.ResolveAuthzPolicies(); err != nil {
		t.Fatalf("ResolveAuthzPolicies() error: %v", err)
	}
	route := cfg.Paths["/arts/{marketplace}/{external_id}"]["get"]
	authz := route.Authz
	if len(authz.AnyOf) != 2 {
		t.Fatalf("len(AnyOf) = %d, want 2", len(authz.AnyOf))
	}
	if authz.AnyOf[0].Resource != "arts" || authz.AnyOf[0].ScopeType != "tenant" {
		t.Errorf("branch 0 should inherit the tenant policy with the resource override: %+v", authz.AnyOf[0])
	}
	if authz.AnyOf[0].PolicyName != "campaign-tenant-read" {
		t.Errorf("branch 0 PolicyName = %q, want campaign-tenant-read", authz.AnyOf[0].PolicyName)
	}
	if authz.AnyOf[1].PolicyName != "inline[1]" {
		t.Errorf("branch 1 PolicyName = %q, want inline[1]", authz.AnyOf[1].PolicyName)
	}
	if route.SourceInfo["x-csar-authz"].Policy != "campaign-tenant-read|inline[1]" {
		t.Errorf("SourceInfo policy = %q", route.SourceInfo["x-csar-authz"].Policy)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error: %v", err)
	}
}

func TestResolveAuthzPolicies_CompositeRejectsFieldOverrides(t *testing.T) {
	cfg := compositeFixture()
	cfg.Paths["/x"] = PathConfig{
		"get": RouteConfig{
			Backend: BackendConfig{TargetURL: "https://x"},
			Authz:   &AuthzRouteConfig{Use: "campaign-read", Action: "write"},
		},
	}
	if err := cfg.ResolveAuthzPolicies(); err == nil {
		t.Fatal("expected error when overriding terminal fields of a composite policy")
	}
}

func TestResolveAuthzPolicies_NestedCompositeRejected(t *testing.T) {
	cfg := compositeFixture()
	cfg.AuthzPolicies["campaign-any"] = AuthzRouteConfig{
		AnyOf: []AuthzRouteConfig{{Use: "campaign-read"}},
	}
	cfg.Paths["/x"] = PathConfig{
		"get": RouteConfig{
			Backend: BackendConfig{TargetURL: "https://x"},
			Authz:   &AuthzRouteConfig{Use: "campaign-any"},
		},
	}
	if err := cfg.ResolveAuthzPolicies(); err == nil {
		t.Fatal("expected error for composite policy referencing another composite")
	}

	cfg = compositeFixture()
	cfg.Paths["/y"] = PathConfig{
		"get": RouteConfig{
			Backend: BackendConfig{TargetURL: "https://y"},
			Authz: &AuthzRouteConfig{AnyOf: []AuthzRouteConfig{
				{AnyOf: []AuthzRouteConfig{{Use: "campaign-tenant-read"}}},
			}},
		},
	}
	if err := cfg.ResolveAuthzPolicies(); err == nil {
		t.Fatal("expected error for inline nested any_of")
	}
}

func TestResolveAuthzPolicies_AnyOfWithTerminalFieldsRejected(t *testing.T) {
	cfg := compositeFixture()
	cfg.Paths["/x"] = PathConfig{
		"get": RouteConfig{
			Backend: BackendConfig{TargetURL: "https://x"},
			Authz: &AuthzRouteConfig{
				Action: "read",
				AnyOf:  []AuthzRouteConfig{{Use: "campaign-tenant-read"}},
			},
		},
	}
	if err := cfg.ResolveAuthzPolicies(); err == nil {
		t.Fatal("expected error when any_of is combined with terminal fields")
	}
}

func TestValidate_AuthzScopeType(t *testing.T) {
	base := func(scopeType, scopeID string) *Config {
		return &Config{
			ListenAddr: ":8080",
			Paths: map[string]PathConfig{
				"/x": {
					"get": RouteConfig{
						Backend: BackendConfig{TargetURL: "https://x"},
						Authz: &AuthzRouteConfig{
							Subject:   "{header.X-Gateway-Subject}",
							Resource:  "billing",
							Action:    "admin",
							ScopeType: scopeType,
							ScopeID:   scopeID,
						},
					},
				},
			},
		}
	}

	cases := []struct {
		name      string
		scopeType string
		scopeID   string
		wantErr   bool
	}{
		{"platform", "platform", "", false},
		{"tenant with id", "tenant", "{path.id}", false},
		{"unknown scope", "global", "", true},
		{"missing scope", "", "", true},
		{"tenant without id", "tenant", "", true},
		{"platform with id", "platform", "{path.id}", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base(tc.scopeType, tc.scopeID)
			err := cfg.ResolveAuthzPolicies()
			if tc.wantErr && err == nil {
				t.Fatal("expected ResolveAuthzPolicies() to reject the scope")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected ResolveAuthzPolicies() error: %v", err)
			}
			if err != nil {
				return
			}
			if err := cfg.Validate(); err != nil {
				t.Fatalf("unexpected validation error: %v", err)
			}
		})
	}
}

func TestValidate_AuthzMissingRequiredFields(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Paths: map[string]PathConfig{
			"/x": {
				"get": RouteConfig{
					Backend: BackendConfig{TargetURL: "https://x"},
					Authz:   &AuthzRouteConfig{Subject: "{header.X-Gateway-Subject}", ScopeType: "platform"},
				},
			},
		},
	}
	if err := cfg.ResolveAuthzPolicies(); err == nil {
		t.Fatal("expected ResolveAuthzPolicies() to reject a check without resource/action")
	}
}

func TestParseBytes_AnyOfYAML(t *testing.T) {
	yamlCfg := `
listen_addr: ":8080"
authz_policies:
  campaign-tenant-read:
    subject: "{header.X-Gateway-Subject}"
    resource: "campaign"
    action: "read"
    scope_type: "tenant"
    scope_id: "{path.marketplace}:{path.external_id}"
  campaign-platform-read:
    subject: "{header.X-Gateway-Subject}"
    resource: "campaign"
    action: "read"
    scope_type: "platform"
  campaign-read:
    any_of: ["campaign-tenant-read", "campaign-platform-read"]
paths:
  /campaigns/{marketplace}/{external_id}:
    get:
      x-csar-backend:
        target_url: "https://campaigns:8082"
      x-csar-authz: "campaign-read"
    patch:
      x-csar-backend:
        target_url: "https://campaigns:8082"
      x-csar-authz:
        any_of:
          - use: "campaign-tenant-read"
            action: "write"
          - "campaign-platform-read"
`
	cfg, err := ParseBytes([]byte(yamlCfg))
	if err != nil {
		t.Fatalf("ParseBytes() error: %v", err)
	}
	get := cfg.Paths["/campaigns/{marketplace}/{external_id}"]["get"].Authz
	if !get.IsComposite() || len(get.AnyOf) != 2 || get.PolicyName != "campaign-read" {
		t.Fatalf("get authz not resolved as composite campaign-read: %+v", get)
	}
	patch := cfg.Paths["/campaigns/{marketplace}/{external_id}"]["patch"].Authz
	if !patch.IsComposite() || len(patch.AnyOf) != 2 {
		t.Fatalf("patch authz not resolved as inline composite: %+v", patch)
	}
	if patch.AnyOf[0].Action != "write" || patch.AnyOf[0].ScopeType != "tenant" {
		t.Errorf("patch branch 0 = %+v, want tenant branch with action override", patch.AnyOf[0])
	}
	if patch.AnyOf[1].PolicyName != "campaign-platform-read" {
		t.Errorf("patch branch 1 PolicyName = %q", patch.AnyOf[1].PolicyName)
	}
}
