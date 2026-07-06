package config

import (
	"strings"
	"testing"
)

func TestValidate_IssueTokensDefaultsAndCanonicalizes(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Paths: map[string]PathConfig{
			"/webapp": {
				"get": RouteConfig{
					Backend: BackendConfig{TargetURL: "https://backend.example.com"},
					AuthValidate: &AuthValidateConfig{
						Mode:            "session",
						SessionEndpoint: "https://authn.example.com/auth/validate",
						CookieName:      "session",
						IssueTokens: []IssueTokenConfig{{
							Profile:      "telegram-webapp",
							InjectHeader: "authorization",
						}},
					},
				},
			},
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	token := cfg.Paths["/webapp"]["get"].AuthValidate.IssueTokens[0]
	if token.InjectHeader != "Authorization" {
		t.Fatalf("InjectHeader = %q, want Authorization", token.InjectHeader)
	}
	if token.InjectFormat != "Bearer {token}" {
		t.Fatalf("InjectFormat = %q, want default", token.InjectFormat)
	}
	if token.OnMissingClaim != "fail_closed" {
		t.Fatalf("OnMissingClaim = %q, want fail_closed", token.OnMissingClaim)
	}
}

func TestValidate_IssueTokensRejectsJWTMode(t *testing.T) {
	cfg := &Config{
		ListenAddr: ":8080",
		Paths: map[string]PathConfig{
			"/webapp": {
				"get": RouteConfig{
					Backend: BackendConfig{TargetURL: "https://backend.example.com"},
					AuthValidate: &AuthValidateConfig{
						Mode:    "jwt",
						JWKSURL: "https://authn.example.com/.well-known/jwks.json",
						IssueTokens: []IssueTokenConfig{{
							Profile:      "telegram-webapp",
							InjectHeader: "Authorization",
						}},
					},
				},
			},
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected issue_tokens session-mode validation error")
	}
	if !strings.Contains(err.Error(), "requires mode \"session\"") {
		t.Fatalf("error = %v", err)
	}
}

func TestResolveAuthValidatePolicies_InheritsIssueTokens(t *testing.T) {
	cfg := &Config{
		AuthValidatePolicies: map[string]AuthValidateConfig{
			"authn-session": {
				Mode:            "session",
				SessionEndpoint: "https://authn.example.com/auth/validate",
				CookieName:      "session",
				IssueTokens: []IssueTokenConfig{{
					Profile:      "telegram-webapp",
					InjectHeader: "Authorization",
				}},
			},
		},
		Paths: map[string]PathConfig{
			"/webapp": {
				"get": RouteConfig{
					Backend:      BackendConfig{TargetURL: "https://backend.example.com"},
					AuthValidate: &AuthValidateConfig{Use: "authn-session"},
				},
			},
		},
	}

	if err := cfg.ResolveAuthValidatePolicies(); err != nil {
		t.Fatalf("ResolveAuthValidatePolicies() error = %v", err)
	}
	tokens := cfg.Paths["/webapp"]["get"].AuthValidate.IssueTokens
	if len(tokens) != 1 || tokens[0].Profile != "telegram-webapp" {
		t.Fatalf("IssueTokens = %#v", tokens)
	}
}
