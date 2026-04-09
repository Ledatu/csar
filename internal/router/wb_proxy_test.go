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

func TestRouter_WBProxy_RewritesPathAndInjectsReadTokenFromPathVars(t *testing.T) {
	var (
		receivedPath   string
		receivedQuery  string
		receivedAuth   string
		receivedSecret string
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		receivedQuery = r.URL.RawQuery
		receivedAuth = r.Header.Get("Authorization")
		receivedSecret = r.Header.Get("X-Client-Secret")
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
	fetcher.Add("accounts/wildberries/s1/content/read", encrypted, "k")
	fetcher.Add("shared/wildberries/client_secret", encrypted, "k")
	injector := middleware.NewAuthInjector(fetcher, provider, newTestLogger())

	cfg := newTestConfig(map[string]config.PathConfig{
		"/svc/wb/{marketplace}/{external_id}/content/{rest:.*}": {
			"get": config.RouteConfig{
				Backend: config.BackendConfig{
					TargetURL:   upstream.URL,
					PathRewrite: "/$3",
					PathMode:    "append",
				},
				Security: config.SecurityConfigs{
					{
						KMSKeyID:         "k",
						TokenRef:         "accounts/{path.marketplace}/{path.external_id}/content/read",
						InjectHeader:     "Authorization",
						InjectFormat:     "Bearer {token}",
						StripTokenParams: boolPtr(false),
					},
					{
						KMSKeyID:         "k",
						TokenRef:         "shared/wildberries/client_secret",
						InjectHeader:     "X-Client-Secret",
						StripTokenParams: boolPtr(false),
					},
				},
			},
		},
	})

	router, err := New(cfg, newTestLogger(), WithAuthInjector(injector))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/svc/wb/wildberries/s1/content/api/v1/stats?limit=10", nil)
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
	if receivedSecret != "wb-secret" {
		t.Fatalf("X-Client-Secret = %q, want %q", receivedSecret, "wb-secret")
	}
}

func TestRouter_WBProxy_UsesWriteAliasForMutatingMethods(t *testing.T) {
	var receivedAuth string
	var receivedSecret string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		receivedSecret = r.Header.Get("X-Client-Secret")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	provider, err := kms.NewLocalProvider(map[string]string{"k": "pass"})
	if err != nil {
		t.Fatalf("NewLocalProvider() error: %v", err)
	}
	encrypted, err := provider.Encrypt(context.Background(), "k", []byte("wb-write-secret"))
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}

	fetcher := middleware.NewStaticTokenFetcher()
	fetcher.Add("accounts/wildberries/s1/content/write", encrypted, "k")
	fetcher.Add("shared/wildberries/client_secret", encrypted, "k")
	injector := middleware.NewAuthInjector(fetcher, provider, newTestLogger())

	cfg := newTestConfig(map[string]config.PathConfig{
		"/svc/wb/{marketplace}/{external_id}/content/{rest:.*}": {
			"post": config.RouteConfig{
				Backend: config.BackendConfig{
					TargetURL:   upstream.URL,
					PathRewrite: "/$3",
					PathMode:    "append",
				},
				Security: config.SecurityConfigs{
					{
						KMSKeyID:         "k",
						TokenRef:         "accounts/{path.marketplace}/{path.external_id}/content/write",
						InjectHeader:     "Authorization",
						InjectFormat:     "Bearer {token}",
						StripTokenParams: boolPtr(false),
					},
					{
						KMSKeyID:         "k",
						TokenRef:         "shared/wildberries/client_secret",
						InjectHeader:     "X-Client-Secret",
						StripTokenParams: boolPtr(false),
					},
				},
			},
		},
	})

	router, err := New(cfg, newTestLogger(), WithAuthInjector(injector))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/svc/wb/wildberries/s1/content/api/v2/cards/upload", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if receivedAuth != "Bearer wb-write-secret" {
		t.Fatalf("Authorization = %q, want %q", receivedAuth, "Bearer wb-write-secret")
	}
	if receivedSecret != "wb-write-secret" {
		t.Fatalf("X-Client-Secret = %q, want %q", receivedSecret, "wb-write-secret")
	}
}

func boolPtr(v bool) *bool { return &v }
