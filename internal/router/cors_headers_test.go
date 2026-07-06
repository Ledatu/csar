package router

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ledatu/csar/internal/config"
)

func TestRouter_CORSStripsUpstreamAccessControlHeaders(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "false")
		w.Header().Set("Access-Control-Expose-Headers", "X-Upstream-Only")
		w.Header().Set("X-Upstream", "ok")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := newTestConfig(map[string]config.PathConfig{
		"/seller/adverts/{path:.*}": {
			"get": config.RouteConfig{
				Backend: config.BackendConfig{
					TargetURL: upstream.URL,
					PathMode:  "append",
				},
				CORS: &config.CORSConfig{
					AllowedOrigins:   []string{"https://dev-seller.aurum-sky.net:3005"},
					AllowedMethods:   []string{http.MethodGet, http.MethodOptions},
					AllowedHeaders:   []string{"Authorization", "Content-Type"},
					ExposedHeaders:   []string{"X-CSAR-Status"},
					AllowCredentials: true,
					MaxAge:           3600,
				},
			},
		},
	})

	router, err := New(cfg, newTestLogger())
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/seller/adverts/api/v1/list", nil)
	req.Header.Set("Origin", "https://dev-seller.aurum-sky.net:3005")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Values("Access-Control-Allow-Origin"); len(got) != 1 || got[0] != "https://dev-seller.aurum-sky.net:3005" {
		t.Fatalf("Access-Control-Allow-Origin = %#v, want single CSAR origin", got)
	}
	if got := rec.Header().Values("Access-Control-Allow-Credentials"); len(got) != 1 || got[0] != "true" {
		t.Fatalf("Access-Control-Allow-Credentials = %#v, want [true]", got)
	}
	if got := rec.Header().Values("Access-Control-Expose-Headers"); len(got) != 1 || got[0] == "X-Upstream-Only" {
		t.Fatalf("Access-Control-Expose-Headers = %#v, want only CSAR-managed exposed headers", got)
	}
	if got := rec.Header().Get("X-Upstream"); got != "ok" {
		t.Fatalf("X-Upstream = %q, want ok", got)
	}
}
