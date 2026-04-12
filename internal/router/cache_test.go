package router

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ledatu/csar-core/gatewayctx"
	"github.com/ledatu/csar/internal/config"
)

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

	cfg := &config.Config{
		ListenAddr: ":0",
		Paths: map[string]config.PathConfig{
			"/analytics/skus": {
				"get": {
					Backend: config.BackendConfig{TargetURL: upstream.URL},
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
					Backend: config.BackendConfig{TargetURL: upstream.URL},
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
		req.Header.Set(gatewayctx.HeaderTenant, "tenant-1")
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
	req.Header.Set(gatewayctx.HeaderTenant, "tenant-1")
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
