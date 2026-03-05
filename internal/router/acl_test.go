package router

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ledatu/csar/internal/config"
)

func TestRouter_SecurityConfig_FailsWithoutInjector(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := newTestConfig(map[string]config.PathConfig{
		"/secure": {
			"get": config.RouteConfig{
				Backend: config.BackendConfig{TargetURL: upstream.URL},
				Security: config.SecurityConfigs{
					{
						KMSKeyID:     "test-key",
						TokenRef:     "test_token",
						InjectHeader: "Authorization",
						InjectFormat: "Bearer {token}",
					},
				},
			},
		},
	})

	// Creating a router WITHOUT WithAuthInjector should fail
	_, err := New(cfg, newTestLogger())
	if err == nil {
		t.Fatal("New() should fail when route has x-csar-security but no AuthInjector is provided")
	}

	errMsg := err.Error()
	if !containsSubstr(errMsg, "no AuthInjector") {
		t.Errorf("error should mention missing AuthInjector, got: %v", err)
	}
}

func TestRouter_NoSecurityConfig_WorksWithoutInjector(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := newTestConfig(map[string]config.PathConfig{
		"/nosecurity": {
			"get": config.RouteConfig{
				Backend: config.BackendConfig{TargetURL: upstream.URL},
			},
		},
	})

	// No security config, no injector — should succeed
	r, err := New(cfg, newTestLogger())
	if err != nil {
		t.Fatalf("New() should succeed without security config: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/nosecurity", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

// ---------- IP Access Control Tests ----------

func TestRouter_GlobalIPAllowlist_AllowsMatchingIP(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	cfg := &config.Config{
		ListenAddr: ":8080",
		AccessControl: &config.AccessControlConfig{
			AllowCIDRs: []string{"192.168.1.0/24", "10.0.0.5"},
		},
		Paths: map[string]config.PathConfig{
			"/api": {
				"get": config.RouteConfig{
					Backend: config.BackendConfig{TargetURL: upstream.URL},
				},
			},
		},
	}

	r, err := New(cfg, newTestLogger())
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	// Allowed IP in CIDR range
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.RemoteAddr = "192.168.1.42:12345"
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("allowed CIDR: status = %d, want 200", rec.Code)
	}

	// Allowed exact IP
	req = httptest.NewRequest(http.MethodGet, "/api", nil)
	req.RemoteAddr = "10.0.0.5:9999"
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("allowed exact IP: status = %d, want 200", rec.Code)
	}
}

func TestRouter_GlobalIPAllowlist_DeniesNonMatchingIP(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := &config.Config{
		ListenAddr: ":8080",
		AccessControl: &config.AccessControlConfig{
			AllowCIDRs: []string{"192.168.1.0/24"},
		},
		Paths: map[string]config.PathConfig{
			"/api": {
				"get": config.RouteConfig{
					Backend: config.BackendConfig{TargetURL: upstream.URL},
				},
			},
		},
	}

	r, err := New(cfg, newTestLogger())
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.RemoteAddr = "10.0.0.99:12345"
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("denied IP: status = %d, want 403", rec.Code)
	}
}

func TestRouter_PerRouteIPAllowlist_OverridesGlobal(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	cfg := &config.Config{
		ListenAddr: ":8080",
		// Global: allow only 10.0.0.0/8
		AccessControl: &config.AccessControlConfig{
			AllowCIDRs: []string{"10.0.0.0/8"},
		},
		Paths: map[string]config.PathConfig{
			"/admin": {
				"get": config.RouteConfig{
					Backend: config.BackendConfig{TargetURL: upstream.URL},
					// Per-route: restrict to a single IP
					Access: &config.AccessControlConfig{
						AllowCIDRs: []string{"172.16.0.1"},
					},
				},
			},
			"/public": {
				"get": config.RouteConfig{
					Backend: config.BackendConfig{TargetURL: upstream.URL},
					// No per-route ACL — uses global
				},
			},
		},
	}

	r, err := New(cfg, newTestLogger())
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	// /admin: per-route allows 172.16.0.1 only
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.RemoteAddr = "172.16.0.1:5555"
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("/admin with 172.16.0.1: status = %d, want 200", rec.Code)
	}

	// /admin: 10.0.0.1 is in global but NOT in per-route — should be denied
	req = httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.RemoteAddr = "10.0.0.1:5555"
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("/admin with 10.0.0.1 (global only): status = %d, want 403", rec.Code)
	}

	// /public: uses global, so 10.0.0.1 should be allowed
	req = httptest.NewRequest(http.MethodGet, "/public", nil)
	req.RemoteAddr = "10.0.0.1:5555"
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("/public with 10.0.0.1: status = %d, want 200", rec.Code)
	}
}

func TestRouter_NoACL_AllowsEveryone(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := newTestConfig(map[string]config.PathConfig{
		"/open": {
			"get": config.RouteConfig{
				Backend: config.BackendConfig{TargetURL: upstream.URL},
			},
		},
	})

	r, err := New(cfg, newTestLogger())
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	// Any IP should be allowed when no ACL is configured
	req := httptest.NewRequest(http.MethodGet, "/open", nil)
	req.RemoteAddr = "99.99.99.99:1234"
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("no ACL: status = %d, want 200", rec.Code)
	}
}

func TestRouter_IPv6_Allowlist(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := &config.Config{
		ListenAddr: ":8080",
		AccessControl: &config.AccessControlConfig{
			AllowCIDRs: []string{"::1", "fd00::/8"},
		},
		Paths: map[string]config.PathConfig{
			"/api": {
				"get": config.RouteConfig{
					Backend: config.BackendConfig{TargetURL: upstream.URL},
				},
			},
		},
	}

	r, err := New(cfg, newTestLogger())
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	// IPv6 loopback
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.RemoteAddr = "[::1]:12345"
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("IPv6 ::1: status = %d, want 200", rec.Code)
	}

	// IPv6 in fd00::/8 range
	req = httptest.NewRequest(http.MethodGet, "/api", nil)
	req.RemoteAddr = "[fd12:3456::1]:12345"
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("IPv6 fd12:: in fd00::/8: status = %d, want 200", rec.Code)
	}

	// IPv6 NOT in allowlist
	req = httptest.NewRequest(http.MethodGet, "/api", nil)
	req.RemoteAddr = "[2001:db8::1]:12345"
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("IPv6 2001:db8::1: status = %d, want 403", rec.Code)
	}
}
