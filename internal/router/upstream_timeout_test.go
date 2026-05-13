package router

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ledatu/csar/internal/config"
)

func TestRouter_UpstreamTimeout_Returns504(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := newTestConfig(map[string]config.PathConfig{
		"/slow": {
			"get": config.RouteConfig{
				Backend: config.BackendConfig{
					TargetURL: upstream.URL,
					Timeout:   config.Duration{Duration: 10 * time.Millisecond},
				},
			},
		},
	})
	r, err := New(cfg, newTestLogger())
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/slow", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want 504; body=%s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("X-CSAR-Upstream-Timeout-MS") != "10" {
		t.Errorf("X-CSAR-Upstream-Timeout-MS = %q, want 10", rec.Header().Get("X-CSAR-Upstream-Timeout-MS"))
	}
}

func TestRouter_UpstreamTimeout_SkipsStreamingRequests(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(20 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := newTestConfig(map[string]config.PathConfig{
		"/events": {
			"get": config.RouteConfig{
				Backend: config.BackendConfig{
					TargetURL: upstream.URL,
					Timeout:   config.Duration{Duration: time.Millisecond},
				},
			},
		},
	})
	r, err := New(cfg, newTestLogger())
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/events", nil)
	req.Header.Set("Accept", "text/event-stream")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("X-CSAR-Upstream-Timeout-MS"); got != "" {
		t.Errorf("X-CSAR-Upstream-Timeout-MS = %q, want empty for streaming request", got)
	}
}
