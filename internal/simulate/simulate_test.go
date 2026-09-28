package simulate

import (
	"testing"

	"github.com/ledatu/csar/internal/config"
)

func TestSimulate_RegexBeatsPrefix(t *testing.T) {
	cfg := &config.Config{
		Paths: map[string]config.PathConfig{
			"/admin": {
				"post": config.RouteConfig{
					Backend: config.BackendConfig{TargetURL: "http://authz-backend"},
				},
			},
			"/admin/sessions/{session_id}/revoke": {
				"post": config.RouteConfig{
					Backend: config.BackendConfig{TargetURL: "http://authn-backend"},
				},
			},
		},
	}

	result := Simulate(cfg, Request{
		Method: "POST",
		Path:   "/admin/sessions/abc123/revoke",
	})

	if !result.Matched {
		t.Fatal("expected a match, got none")
	}
	if result.MatchType != "regex" {
		t.Errorf("match type = %q, want %q", result.MatchType, "regex")
	}
	if result.TargetURL != "http://authn-backend" {
		t.Errorf("target = %q, want %q", result.TargetURL, "http://authn-backend")
	}
}

func TestSimulate_PrefixFallbackWhenNoRegex(t *testing.T) {
	cfg := &config.Config{
		Paths: map[string]config.PathConfig{
			"/admin": {
				"post": config.RouteConfig{
					Backend: config.BackendConfig{TargetURL: "http://authz-backend"},
				},
			},
		},
	}

	result := Simulate(cfg, Request{
		Method: "POST",
		Path:   "/admin/some/other/path",
	})

	if !result.Matched {
		t.Fatal("expected a prefix match, got none")
	}
	if result.MatchType != "prefix" {
		t.Errorf("match type = %q, want %q", result.MatchType, "prefix")
	}
	if result.TargetURL != "http://authz-backend" {
		t.Errorf("target = %q, want %q", result.TargetURL, "http://authz-backend")
	}
}

func TestSimulate_ExactBeatsRegex(t *testing.T) {
	cfg := &config.Config{
		Paths: map[string]config.PathConfig{
			"/admin/sessions/special/revoke": {
				"post": config.RouteConfig{
					Backend: config.BackendConfig{TargetURL: "http://exact-backend"},
				},
			},
			"/admin/sessions/{session_id}/revoke": {
				"post": config.RouteConfig{
					Backend: config.BackendConfig{TargetURL: "http://regex-backend"},
				},
			},
		},
	}

	result := Simulate(cfg, Request{
		Method: "POST",
		Path:   "/admin/sessions/special/revoke",
	})

	if !result.Matched {
		t.Fatal("expected a match, got none")
	}
	if result.MatchType != "exact" {
		t.Errorf("match type = %q, want %q", result.MatchType, "exact")
	}
	if result.TargetURL != "http://exact-backend" {
		t.Errorf("target = %q, want %q", result.TargetURL, "http://exact-backend")
	}
}

func TestSimulate_MostPreciseRegexRouteWins(t *testing.T) {
	cfg := &config.Config{Paths: map[string]config.PathConfig{
		"/svc/wb/{marketplace}/{external_id}/finance/{rest:.*}": {
			"post": config.RouteConfig{Backend: config.BackendConfig{TargetURL: "https://wide.example.com"}},
		},
		"/svc/wb/{marketplace}/{external_id}/finance/api/finance/v1/sales-reports/list": {
			"post": config.RouteConfig{Backend: config.BackendConfig{TargetURL: "https://narrow.example.com"}},
		},
	}}

	res := Simulate(cfg, Request{Method: "POST", Path: "/svc/wb/wb/4242/finance/api/finance/v1/sales-reports/list"})
	if res.TargetURL != "https://narrow.example.com" {
		t.Fatalf("matched %s (%s), want the sales-reports/list route", res.RoutePath, res.TargetURL)
	}
	res = Simulate(cfg, Request{Method: "POST", Path: "/svc/wb/wb/4242/finance/api/v1/balance"})
	if res.TargetURL != "https://wide.example.com" {
		t.Fatalf("matched %s (%s), want the finance/{rest:.*} route", res.RoutePath, res.TargetURL)
	}
}

func TestSimulate_LiteralDotIsNotAWildcard(t *testing.T) {
	cfg := &config.Config{Paths: map[string]config.PathConfig{
		"/files/{name}.json": {
			"get": config.RouteConfig{Backend: config.BackendConfig{TargetURL: "https://files.example.com"}},
		},
	}}
	if res := Simulate(cfg, Request{Method: "GET", Path: "/files/reportXjson"}); res.Matched {
		t.Fatalf("matched %s; a literal '.' must not match any character, as in the router", res.RoutePath)
	}
	if res := Simulate(cfg, Request{Method: "GET", Path: "/files/report.json"}); !res.Matched {
		t.Fatal("expected /files/report.json to match")
	}
}
