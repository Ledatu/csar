package router

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ledatu/csar/internal/config"
)

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newTestConfig(routes map[string]config.PathConfig) *config.Config {
	return &config.Config{
		ListenAddr: ":8080",
		Paths:      routes,
	}
}

func TestRouter_ExactMatch(t *testing.T) {
	// Start a test upstream
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"upstream":"ok"}`))
	}))
	defer upstream.Close()

	cfg := newTestConfig(map[string]config.PathConfig{
		"/api/v1": {
			"get": config.RouteConfig{
				Backend: config.BackendConfig{TargetURL: upstream.URL},
			},
		},
	})

	r, err := New(cfg, newTestLogger())
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	body, _ := io.ReadAll(rec.Result().Body)
	if string(body) != `{"upstream":"ok"}` {
		t.Errorf("body = %q, want upstream response", string(body))
	}
}

func TestRouter_PrefixMatch(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := newTestConfig(map[string]config.PathConfig{
		"/api/v1": {
			"get": config.RouteConfig{
				Backend: config.BackendConfig{TargetURL: upstream.URL},
			},
		},
	})

	r, err := New(cfg, newTestLogger())
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	// /api/v1/sub should match /api/v1 prefix
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sub/path", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("prefix match: status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestRouter_NoMatch_Returns404(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := newTestConfig(map[string]config.PathConfig{
		"/api/v1": {
			"get": config.RouteConfig{
				Backend: config.BackendConfig{TargetURL: upstream.URL},
			},
		},
	})

	r, err := New(cfg, newTestLogger())
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/completely/different", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}

	var resp map[string]string
	json.NewDecoder(rec.Result().Body).Decode(&resp)
	if resp["error"] != "no route matched" {
		t.Errorf("error = %q, want %q", resp["error"], "no route matched")
	}
}

func TestRouter_MethodMismatch_Returns404(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := newTestConfig(map[string]config.PathConfig{
		"/api/v1": {
			"get": config.RouteConfig{
				Backend: config.BackendConfig{TargetURL: upstream.URL},
			},
		},
	})

	r, err := New(cfg, newTestLogger())
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	// POST to a GET-only route
	req := httptest.NewRequest(http.MethodPost, "/api/v1", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d for method mismatch", rec.Code, http.StatusNotFound)
	}
}

func TestRouter_WithThrottle_Passes(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	cfg := newTestConfig(map[string]config.PathConfig{
		"/throttled": {
			"get": config.RouteConfig{
				Backend: config.BackendConfig{TargetURL: upstream.URL},
				Traffic: &config.TrafficConfig{
					RPS:     100,
					Burst:   10,
					MaxWait: config.Duration{Duration: 5 * time.Second},
				},
			},
		},
	})

	r, err := New(cfg, newTestLogger())
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/throttled", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestRouter_WithThrottle_Timeout(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := newTestConfig(map[string]config.PathConfig{
		"/slow": {
			"get": config.RouteConfig{
				Backend: config.BackendConfig{TargetURL: upstream.URL},
				Traffic: &config.TrafficConfig{
					RPS:     1,
					Burst:   1,
					MaxWait: config.Duration{Duration: 50 * time.Millisecond},
				},
			},
		},
	})

	r, err := New(cfg, newTestLogger())
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	// Consume burst
	req := httptest.NewRequest(http.MethodGet, "/slow", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("first request failed: %d", rec.Code)
	}

	// Second request should timeout and get 503 (not 429!)
	req = httptest.NewRequest(http.MethodGet, "/slow", nil)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d (503, not 429)", rec.Code, http.StatusServiceUnavailable)
	}

	// Verify Retry-After header
	if rec.Header().Get("Retry-After") == "" {
		t.Error("missing Retry-After header")
	}
}

func TestRouter_LongestPrefixWins(t *testing.T) {
	shortUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("short"))
	}))
	defer shortUpstream.Close()

	longUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("long"))
	}))
	defer longUpstream.Close()

	cfg := newTestConfig(map[string]config.PathConfig{
		"/api": {
			"get": config.RouteConfig{
				Backend: config.BackendConfig{TargetURL: shortUpstream.URL},
			},
		},
		"/api/v1": {
			"get": config.RouteConfig{
				Backend: config.BackendConfig{TargetURL: longUpstream.URL},
			},
		},
	})

	r, err := New(cfg, newTestLogger())
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/products", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	body, _ := io.ReadAll(rec.Result().Body)
	if string(body) != "long" {
		t.Errorf("body = %q, want %q (longest prefix should win)", string(body), "long")
	}
}

func TestRouter_GetThrottler(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := newTestConfig(map[string]config.PathConfig{
		"/throttled": {
			"get": config.RouteConfig{
				Backend: config.BackendConfig{TargetURL: upstream.URL},
				Traffic: &config.TrafficConfig{
					RPS:     10,
					Burst:   5,
					MaxWait: config.Duration{Duration: time.Second},
				},
			},
		},
		"/unthrottled": {
			"get": config.RouteConfig{
				Backend: config.BackendConfig{TargetURL: upstream.URL},
			},
		},
	})

	r, err := New(cfg, newTestLogger())
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	if th := r.GetThrottler("GET", "/throttled"); th == nil {
		t.Error("GetThrottler(/throttled) returned nil, want non-nil")
	}
	if th := r.GetThrottler("GET", "/unthrottled"); th != nil {
		t.Error("GetThrottler(/unthrottled) returned non-nil, want nil")
	}
	if th := r.GetThrottler("GET", "/nonexistent"); th != nil {
		t.Error("GetThrottler(/nonexistent) returned non-nil, want nil")
	}
}

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

func containsSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
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

func TestRouter_TrustProxy_XForwardedFor(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := &config.Config{
		ListenAddr: ":8080",
		AccessControl: &config.AccessControlConfig{
			AllowCIDRs: []string{"203.0.113.50"},
			TrustProxy: true,
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

	// RemoteAddr is a proxy, but X-Forwarded-For contains the real client IP.
	// The rightmost entry is the one appended by the proxy (the real client IP).
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.RemoteAddr = "127.0.0.1:9999"
	req.Header.Set("X-Forwarded-For", "10.0.0.1, 203.0.113.50")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("trust_proxy XFF: status = %d, want 200", rec.Code)
	}

	// Without the header, the RemoteAddr (127.0.0.1) is not in the allowlist
	req = httptest.NewRequest(http.MethodGet, "/api", nil)
	req.RemoteAddr = "127.0.0.1:9999"
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("trust_proxy no header: status = %d, want 403", rec.Code)
	}
}

func TestRouter_TrustProxy_XRealIP(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := &config.Config{
		ListenAddr: ":8080",
		AccessControl: &config.AccessControlConfig{
			AllowCIDRs: []string{"203.0.113.50"},
			TrustProxy: true,
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
	req.RemoteAddr = "127.0.0.1:9999"
	req.Header.Set("X-Real-IP", "203.0.113.50")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("trust_proxy X-Real-IP: status = %d, want 200", rec.Code)
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

func TestRouter_TrustProxy_RouteIsolation(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := &config.Config{
		ListenAddr: ":8080",
		// No global ACL — each route defines its own
		Paths: map[string]config.PathConfig{
			"/trusted": {
				"get": config.RouteConfig{
					Backend: config.BackendConfig{TargetURL: upstream.URL},
					Access: &config.AccessControlConfig{
						AllowCIDRs: []string{"203.0.113.0/24"},
						TrustProxy: true, // trusts X-Forwarded-For
					},
				},
			},
			"/untrusted": {
				"get": config.RouteConfig{
					Backend: config.BackendConfig{TargetURL: upstream.URL},
					Access: &config.AccessControlConfig{
						AllowCIDRs: []string{"203.0.113.0/24"},
						TrustProxy: false, // does NOT trust X-Forwarded-For
					},
				},
			},
		},
	}

	r, err := New(cfg, newTestLogger())
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	// /trusted: X-Forwarded-For=203.0.113.1 should be trusted → allowed
	req := httptest.NewRequest(http.MethodGet, "/trusted", nil)
	req.RemoteAddr = "127.0.0.1:9999"
	req.Header.Set("X-Forwarded-For", "203.0.113.1")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("/trusted with XFF 203.0.113.1: status = %d, want 200", rec.Code)
	}

	// /untrusted: X-Forwarded-For=203.0.113.1 should NOT be trusted → uses RemoteAddr 127.0.0.1 → denied
	req = httptest.NewRequest(http.MethodGet, "/untrusted", nil)
	req.RemoteAddr = "127.0.0.1:9999"
	req.Header.Set("X-Forwarded-For", "203.0.113.1")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("/untrusted with XFF (should be ignored): status = %d, want 403", rec.Code)
	}

	// Verify the /trusted route's trust_proxy doesn't leak to /untrusted
	// (this was the original bug — one route enabling trust for all)
	req = httptest.NewRequest(http.MethodGet, "/untrusted", nil)
	req.RemoteAddr = "203.0.113.50:9999" // actual RemoteAddr is in allowlist
	req.Header.Set("X-Forwarded-For", "10.0.0.1") // spoofed XFF (not in allowlist)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("/untrusted with real IP in allowlist: status = %d, want 200 (RemoteAddr used, not XFF)", rec.Code)
	}
}

func TestRouter_TrustProxy_XFF_Spoofing_Prevention(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := &config.Config{
		ListenAddr: ":8080",
		AccessControl: &config.AccessControlConfig{
			AllowCIDRs: []string{"203.0.113.50"},
			TrustProxy: true,
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

	// Spoofing attempt: attacker sends "X-Forwarded-For: 203.0.113.50"
	// hoping we'll trust it as the client IP. The proxy appends the real
	// attacker IP (10.99.99.99). We must take the RIGHTMOST entry
	// (the one the proxy appended), which is the real IP — not in the allowlist.
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.RemoteAddr = "10.0.0.1:9999" // proxy's own IP
	req.Header.Set("X-Forwarded-For", "203.0.113.50, 10.99.99.99")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("XFF spoofing: status = %d, want 403 (rightmost IP 10.99.99.99 is not in allowlist)", rec.Code)
	}

	// Legitimate request: proxy appends the real allowed IP as rightmost.
	req = httptest.NewRequest(http.MethodGet, "/api", nil)
	req.RemoteAddr = "10.0.0.1:9999"
	req.Header.Set("X-Forwarded-For", "192.168.1.1, 203.0.113.50")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("XFF legitimate: status = %d, want 200 (rightmost IP 203.0.113.50 is in allowlist)", rec.Code)
	}
}

func TestRouter_PrefixBoundary(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	cfg := newTestConfig(map[string]config.PathConfig{
		"/api/v1": {
			"get": config.RouteConfig{
				Backend: config.BackendConfig{TargetURL: upstream.URL},
			},
		},
	})

	r, err := New(cfg, newTestLogger())
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	// /api/v1evil must NOT match /api/v1 (no path boundary)
	req := httptest.NewRequest(http.MethodGet, "/api/v1evil", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("/api/v1evil: status = %d, want 404 (must not match /api/v1)", rec.Code)
	}

	// /api/v1/foo SHOULD still match /api/v1 (path boundary '/')
	req = httptest.NewRequest(http.MethodGet, "/api/v1/foo", nil)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("/api/v1/foo: status = %d, want 200 (should match /api/v1)", rec.Code)
	}

	// /api/v1 exact match should still work
	req = httptest.NewRequest(http.MethodGet, "/api/v1", nil)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("/api/v1: status = %d, want 200 (exact match)", rec.Code)
	}
}
