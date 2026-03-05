package router

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ledatu/csar/internal/config"
)

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
