package router

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ledatu/csar/internal/config"
	"github.com/ledatu/csar/internal/kms"
	"github.com/ledatu/csar/pkg/middleware"
)

func TestRouter_WBProxy_RewritesPathAndInjectsTokenFromPathVars(t *testing.T) {
	var (
		receivedPath  string
		receivedQuery string
		receivedAuth  string
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		receivedQuery = r.URL.RawQuery
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	provider, err := kms.NewLocalProvider(map[string]string{"k": "pass"})
	if err != nil {
		t.Fatalf("NewLocalProvider() error: %v", err)
	}
	encrypted, err := provider.Encrypt(context.Background(), "k", []byte("wb-secret"))
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}

	fetcher := middleware.NewStaticTokenFetcher()
	fetcher.Add("accounts/wildberries/s1/api_token", encrypted, "k")
	injector := middleware.NewAuthInjector(fetcher, provider, newTestLogger())

	cfg := newTestConfig(map[string]config.PathConfig{
		"/svc/wb/{marketplace}/{external_id}/{rest:.*}": {
			"get": config.RouteConfig{
				Backend: config.BackendConfig{
					TargetURL:   upstream.URL,
					PathRewrite: "/$3",
					PathMode:    "append",
				},
				Security: config.SecurityConfigs{{
					KMSKeyID:         "k",
					TokenRef:         "accounts/{path.marketplace}/{path.external_id}/api_token",
					InjectHeader:     "Authorization",
					InjectFormat:     "Bearer {token}",
					StripTokenParams: boolPtr(false),
				}},
			},
		},
	})

	router, err := New(cfg, newTestLogger(), WithAuthInjector(injector))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/svc/wb/wildberries/s1/api/v1/stats?limit=10", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if receivedPath != "/api/v1/stats" {
		t.Fatalf("upstream path = %q, want %q", receivedPath, "/api/v1/stats")
	}
	if receivedQuery != "limit=10" {
		t.Fatalf("upstream query = %q, want %q", receivedQuery, "limit=10")
	}
	if receivedAuth != "Bearer wb-secret" {
		t.Fatalf("Authorization = %q, want %q", receivedAuth, "Bearer wb-secret")
	}
}

func boolPtr(v bool) *bool { return &v }
