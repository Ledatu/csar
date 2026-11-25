package router

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/ledatu/csar/internal/config"
	"github.com/redis/go-redis/v9"
)

func TestRequestQuotaAcrossRouterAliasesAndReload(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(200) }))
	defer upstream.Close()
	mr := miniredis.RunT(t)
	now := time.Now().UTC()
	mr.SetTime(now)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer client.Close()
	cfg := newTestConfig(map[string]config.PathConfig{})
	for _, path := range []string{"/a/{cabinet}", "/b/{cabinet}"} {
		cfg.Paths[path] = config.PathConfig{"get": config.RouteConfig{Backend: config.BackendConfig{TargetURL: upstream.URL}, Traffic: &config.TrafficConfig{
			RPS: 10000, Burst: 100, Backend: "redis", Key: "read:{path.cabinet}",
			Quotas: []config.RequestQuota{{Name: "daily", Key: "method:{path.cabinet}", Requests: 2, Window: config.Duration{Duration: 24 * time.Hour}}},
		}}}
	}
	build := func() *Router {
		r, err := New(cfg, newTestLogger(), WithRedisClient(client))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(r.Close)
		return r
	}
	first, second := build(), build()
	call := func(r *Router, path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		return w
	}
	if w := call(first, "/a/dd"); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := call(second, "/b/dd"); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	w := call(build(), "/a/dd")
	wait, err := strconv.ParseInt(w.Header().Get("X-CSAR-Wait-MS"), 10, 64)
	if err != nil || wait != (24*time.Hour).Milliseconds() || w.Code != 503 || w.Header().Get("X-CSAR-Status") != "throttled" || calls.Load() != 2 {
		t.Fatal("quota not surfaced to worker", w.Code, w.Header(), calls.Load())
	}
	if w := call(second, "/b/other"); w.Code != 200 {
		t.Fatal("other cabinet blocked", w.Code)
	}
	mr.Close()
	if w := call(first, "/a/dd"); w.Code != 503 {
		t.Fatal("Redis outage reached upstream", w.Code)
	}
}

func TestRequestQuotaWithoutRedisReturnsConfigurationError(t *testing.T) {
	cfg := newTestConfig(map[string]config.PathConfig{"/x": {"get": {Backend: config.BackendConfig{TargetURL: "http://127.0.0.1:1"}, Traffic: &config.TrafficConfig{Backend: "redis", Key: "reads", Quotas: []config.RequestQuota{{Name: "daily", Key: "global", Requests: 20, Window: config.Duration{Duration: 24 * time.Hour}}}}}}})
	if _, err := New(cfg, newTestLogger()); err == nil {
		t.Fatal("quota accepted without Redis")
	}
}
