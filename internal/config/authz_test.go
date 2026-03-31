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
