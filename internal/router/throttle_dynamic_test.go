package router

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/ledatu/csar/internal/config"
)

func TestRouter_PathKeyedThrottle_PausesOnlyTheTenantThatGot429(t *testing.T) {
	var hits = map[string]*atomic.Int32{"a": {}, "b": {}}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenant := r.URL.Query().Get("t")
		hits[tenant].Add(1)
		if tenant == "a" {
			w.Header().Set("X-Ratelimit-Retry", "30")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer client.Close()

	cfg := newTestConfig(map[string]config.PathConfig{
		"/ext/{tenant}/items": {
			"get": config.RouteConfig{
				Backend: config.BackendConfig{TargetURL: upstream.URL},
				Traffic: &config.TrafficConfig{
					RPS:     100,
					Burst:   10,
					MaxWait: config.Duration{Duration: 50 * time.Millisecond},
					Backend: "redis",
					Key:     "items:{path.tenant}",
					AdaptiveBackpressure: &config.AdaptiveBackpressureConfig{
						Enabled:        true,
						RespectHeaders: []string{"X-Ratelimit-Retry"},
						SuspendBucket:  true,
					},
				},
			},
		},
	})
	cfg.Redis = &config.RedisConfig{Address: mr.Addr()}

	r, err := New(cfg, newTestLogger(), WithRedisClient(client))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	get := func(tenant string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ext/"+tenant+"/items?t="+tenant, nil))
		return rec
	}

	if rec := get("a"); rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") != "30" {
		t.Fatalf("first a: %d Retry-After=%q, want 503 / 30", rec.Code, rec.Header().Get("Retry-After"))
	}

	rec := get("a")
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("X-CSAR-Status") != "throttled" {
		t.Fatalf("second a: %d %q, want 503 throttled", rec.Code, rec.Header().Get("X-CSAR-Status"))
	}
	if ra, _ := strconv.Atoi(rec.Header().Get("Retry-After")); ra < 29 || ra > 30 {
		t.Errorf("Retry-After = %q, want the remaining suspension (~30s)", rec.Header().Get("Retry-After"))
	}
	var body struct {
		RetryAfterMS int64 `json:"retry_after_ms"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.RetryAfterMS < 29000 || body.RetryAfterMS > 30000 {
		t.Errorf("retry_after_ms = %d (%v), want ~30000", body.RetryAfterMS, err)
	}
	if hits["a"].Load() != 1 {
		t.Errorf("upstream saw %d requests for a, want 1", hits["a"].Load())
	}

	if rec := get("b"); rec.Code != http.StatusOK {
		t.Fatalf("b: %d, want 200 — the 429 for a must not pause b", rec.Code)
	}
}
