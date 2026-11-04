package router

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/ledatu/csar-core/gatewayctx"
	"github.com/ledatu/csar/internal/config"
	"github.com/redis/go-redis/v9"
)

func TestRouter_POSTCacheNamedPolicy(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer client.Close()
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/upstream/stocks" {
			t.Errorf("upstream path = %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		io.Copy(w, r.Body)
	}))
	defer upstream.Close()
	authn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session")
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set(gatewayctx.HeaderSubject, cookie.Value)
	}))
	defer authn.Close()
	cfg := &config.Config{
		ListenAddr: ":0",
		Redis:      &config.RedisConfig{Address: mr.Addr()},
		CachePolicies: map[string]config.CacheConfig{
			"stocks": {
				Store: "redis", Methods: []string{"POST"}, MaxRequestBodySize: 64,
				Key: "stocks:{subject}:{path.seller}", KeyQuery: &config.CacheKeyQueryConfig{Sort: true},
			},
		},
		Paths: map[string]config.PathConfig{
			"/stocks/{seller}": {"post": {
				Backend: config.BackendConfig{TargetURL: upstream.URL, PathRewrite: "/upstream/stocks", PathMode: "append"},
				AuthValidate: &config.AuthValidateConfig{
					Mode: "session", SessionEndpoint: authn.URL, CookieName: "session",
					ForwardHeaders: []string{gatewayctx.HeaderSubject},
				},
				Cache: &config.CacheConfig{Use: "stocks"},
			}},
		},
	}
	if err := cfg.ResolveCachePolicies(); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	first, err := New(cfg, slog.Default(), WithRedisClient(client))
	if err != nil {
		t.Fatal(err)
	}
	second, err := New(cfg, slog.Default(), WithRedisClient(client))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		router                    *Router
		path, subject, body, want string
		status                    int
	}{
		{first, "/stocks/seller1", "user1", `{"nmIds":[1]}`, "MISS", 200},
		{first, "/stocks/seller1", "user1", `{"nmIds":[2]}`, "MISS", 200},
		{second, "/stocks/seller1", "user1", `{"nmIds":[1]}`, "HIT", 200},
		{second, "/stocks/seller2", "user1", `{"nmIds":[1]}`, "MISS", 200},
		{second, "/stocks/seller1", "user2", `{"nmIds":[1]}`, "MISS", 200},
		{second, "/stocks/seller1?limit=2", "user1", `{"nmIds":[1]}`, "MISS", 200},
		{second, "/stocks/seller1", "user1", strings.Repeat("x", 65), "BYPASS", 200},
		{second, "/stocks/seller1", "", `{"nmIds":[1]}`, "", 401},
	} {
		req := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(gatewayctx.HeaderSubject, "spoofed")
		if tc.subject != "" {
			req.AddCookie(&http.Cookie{Name: "session", Value: tc.subject})
		}
		rec := httptest.NewRecorder()
		tc.router.ServeHTTP(rec, req)
		if rec.Code != tc.status || rec.Header().Get("X-CSAR-Cache") != tc.want {
			t.Fatalf("%s/%s: status=%d cache=%s body=%q", tc.path, tc.subject, rec.Code, rec.Header().Get("X-CSAR-Cache"), rec.Body.String())
		}
		if rec.Code == 200 && rec.Body.String() != tc.body {
			t.Fatalf("wrong response body %q, want %q", rec.Body.String(), tc.body)
		}
	}
	if calls.Load() != 6 {
		t.Fatalf("upstream calls = %d, want 6", calls.Load())
	}
}

func TestRouter_ResponseCacheInvalidationByTag(t *testing.T) {
	var analyticsCalls atomic.Int64

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			call := analyticsCalls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"call":` + string(rune('0'+call)) + `}`))
		case http.MethodPatch:
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer upstream.Close()

	// The {tenant} placeholder reads the trusted X-Gateway-Tenant header, which
	// only a validator may set: the router strips client-supplied copies.
	authnServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("csar_session"); err != nil || c.Value != "sess-1" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set(gatewayctx.HeaderTenant, "tenant-1")
		w.WriteHeader(http.StatusOK)
	}))
	defer authnServer.Close()

	sessionAuth := &config.AuthValidateConfig{
		Mode:            "session",
		SessionEndpoint: authnServer.URL,
		CookieName:      "csar_session",
		ForwardHeaders:  []string{gatewayctx.HeaderTenant},
	}

	cfg := &config.Config{
		ListenAddr: ":0",
		Paths: map[string]config.PathConfig{
			"/analytics/skus": {
				"get": {
					Backend:      config.BackendConfig{TargetURL: upstream.URL},
					AuthValidate: sessionAuth,
					Cache: &config.CacheConfig{
						Key:     "analytics:skus:{tenant}:{query.marketplace}",
						TTL:     config.Duration{Duration: 5 * time.Second},
						Tags:    []string{"analytics:skus:{tenant}"},
						Methods: []string{http.MethodGet},
					},
				},
			},
			"/skus/{sku_id}": {
				"patch": {
					Backend:      config.BackendConfig{TargetURL: upstream.URL},
					AuthValidate: sessionAuth,
					CacheInvalidate: &config.CacheInvalidationConfig{
						Tags: []string{"analytics:skus:{tenant}"},
					},
				},
			},
		},
	}
	r, err := New(cfg, slog.Default())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	get := func() string {
		req := httptest.NewRequest(http.MethodGet, "/analytics/skus?marketplace=wb", nil)
		req.AddCookie(&http.Cookie{Name: "csar_session", Value: "sess-1"})
		req.Header.Set(gatewayctx.HeaderTenant, "spoofed-tenant")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET status = %d, want 200", rec.Code)
		}
		return rec.Header().Get("X-CSAR-Cache")
	}

	if got := get(); got != "MISS" {
		t.Fatalf("first GET cache = %q, want MISS", got)
	}
	if got := get(); got != "HIT" {
		t.Fatalf("second GET cache = %q, want HIT", got)
	}
	if analyticsCalls.Load() != 1 {
		t.Fatalf("analyticsCalls before invalidation = %d, want 1", analyticsCalls.Load())
	}

	req := httptest.NewRequest(http.MethodPatch, "/skus/sku-1", nil)
	req.AddCookie(&http.Cookie{Name: "csar_session", Value: "sess-1"})
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("PATCH status = %d, want 204", rec.Code)
	}

	if got := get(); got != "MISS" {
		t.Fatalf("GET after invalidation cache = %q, want MISS", got)
	}
	if analyticsCalls.Load() != 2 {
		t.Fatalf("analyticsCalls after invalidation = %d, want 2", analyticsCalls.Load())
	}
}
