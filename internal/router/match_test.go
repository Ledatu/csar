package router

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ledatu/csar/internal/config"
)

func TestRouter_ExactMatch(t *testing.T) {
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

	var resp map[string]interface{}
	json.NewDecoder(rec.Result().Body).Decode(&resp)
	if resp["message"] != "no route matched" {
		t.Errorf("message = %q, want %q", resp["message"], "no route matched")
	}
	if resp["code"] != "route_not_found" {
		t.Errorf("code = %q, want %q", resp["code"], "route_not_found")
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
