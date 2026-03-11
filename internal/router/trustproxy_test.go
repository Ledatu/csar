package router

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ledatu/csar/internal/config"
)

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
	req = httptest.NewRequest(http.MethodGet, "/untrusted", nil)
	req.RemoteAddr = "203.0.113.50:9999"          // actual RemoteAddr is in allowlist
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
