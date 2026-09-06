package router

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ledatu/csar-core/gatewayctx"
	"github.com/ledatu/csar/internal/config"
)

func TestRouter_StripsClientSuppliedGatewayHeaders(t *testing.T) {
	received := http.Header{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := newTestConfig(map[string]config.PathConfig{
		"/public/ping": {
			"get": config.RouteConfig{
				Backend: config.BackendConfig{TargetURL: upstream.URL, PathMode: "append"},
			},
		},
	})
	router, err := New(cfg, newTestLogger())
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/public/ping", nil)
	for _, name := range gatewayctx.TrustedHeaders {
		req.Header.Set(name, "spoofed")
	}
	req.Header.Set("X-User-Email", "keep@example.com")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	for _, name := range gatewayctx.TrustedHeaders {
		if got := received.Get(name); got != "" {
			t.Errorf("upstream received %s=%q; client-supplied gateway identity headers must be stripped", name, got)
		}
	}
	if got := received.Get("X-User-Email"); got != "keep@example.com" {
		t.Errorf("X-User-Email = %q, want passthrough of non-gateway headers", got)
	}
}
