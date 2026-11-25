package router

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
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

func TestQuotaRoutesRejectReplayBeforeForwarding(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(200) }))
	defer upstream.Close()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer client.Close()
	yes := true
	for _, tc := range []struct {
		name     string
		retry    *config.RetryConfig
		protocol *config.ProtocolPolicy
	}{
		{name: "ordinary", retry: &config.RetryConfig{MaxAttempts: 2}},
		{name: "transparent429", retry: &config.RetryConfig{MaxAttempts: 1, AutoRetry429: true}},
		{name: "protocol_override", retry: &config.RetryConfig{MaxAttempts: 1}, protocol: &config.ProtocolPolicy{TransparentRetry: &yes}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := newTestConfig(map[string]config.PathConfig{"/reports": {"get": {Backend: config.BackendConfig{TargetURL: upstream.URL}, Traffic: &config.TrafficConfig{RPS: 1000, Burst: 100, Backend: "redis", Key: "reads", Quotas: []config.RequestQuota{{Name: "day", Key: "global", Requests: 1, Window: config.Duration{Duration: 24 * time.Hour}}}}, Retry: tc.retry, Protocol: tc.protocol}}})
			if r, err := New(cfg, newTestLogger(), WithRedisClient(client)); err == nil {
				r.Close()
				t.Fatal("replay-enabled quota route accepted")
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatal("invalid policy reached upstream", calls.Load())
	}
}

func TestUnquotaedRoutesRetainOrdinaryRetry(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(200)
	}))
	defer upstream.Close()
	cfg := newTestConfig(map[string]config.PathConfig{"/x": {"get": {Backend: config.BackendConfig{TargetURL: upstream.URL}, Retry: &config.RetryConfig{MaxAttempts: 2, Backoff: config.Duration{Duration: time.Millisecond}, MaxBackoff: config.Duration{Duration: time.Millisecond}}}}})
	r, err := New(cfg, newTestLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/x", nil))
	if w.Code != 200 || calls.Load() != 2 {
		t.Fatal("legacy retry changed", w.Code, calls.Load())
	}
}

func TestClosedGlobalQuotaBlocksReportGenerationAcrossReplicas(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(200) }))
	defer upstream.Close()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer client.Close()
	cfg := newTestConfig(map[string]config.PathConfig{"/reports/{cabinet}": {"post": {Backend: config.BackendConfig{TargetURL: upstream.URL}, Traffic: &config.TrafficConfig{RPS: 1000, Burst: 100, Backend: "redis", Key: "report-submit-global", Quotas: []config.RequestQuota{{Name: "report-day", Key: "reports:global", Requests: 0, Window: config.Duration{Duration: 24 * time.Hour}}}}, Retry: &config.RetryConfig{MaxAttempts: 1}}}})
	for range 2 {
		r, err := New(cfg, newTestLogger(), WithRedisClient(client))
		if err != nil {
			t.Fatal(err)
		}
		for _, cab := range []string{"dd", "other"} {
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest("POST", "/reports/"+cab, nil))
			if w.Code != 503 || w.Header().Get("X-CSAR-Status") != "throttled" || w.Header().Get("X-CSAR-Wait-MS") != "86400000" {
				t.Fatal("unverified report budget did not fail closed", w.Code, w.Header())
			}
		}
		r.Close()
	}
	if calls.Load() != 0 {
		t.Fatal("closed budget generated reports", calls.Load())
	}
}

func TestQuotaCauseIsLoggedWithoutLeakingToClient(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	defer upstream.Close()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer client.Close()
	cfg := newTestConfig(map[string]config.PathConfig{"/x": {"get": {Backend: config.BackendConfig{TargetURL: upstream.URL}, Traffic: &config.TrafficConfig{RPS: 1000, Burst: 100, Backend: "redis", Key: "reads", Quotas: []config.RequestQuota{{Name: "day", Key: "reports:global", Requests: 1, Window: config.Duration{Duration: 24 * time.Hour}}}}}}})
	var logs bytes.Buffer
	r, err := New(cfg, slog.New(slog.NewTextHandler(&logs, nil)), WithRedisClient(client))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/x", nil))
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	for _, key := range mr.Keys() {
		if strings.Contains(key, "{request-quota:") {
			mr.Del(key)
			if err := mr.Set(key, "corrupt"); err != nil {
				t.Fatal(err)
			}
		}
	}
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/x", nil))
	if w.Code != 503 || w.Header().Get("X-CSAR-Status") != "throttle_unavailable" {
		t.Fatal(w.Code, w.Header())
	}
	const cause = "invalid request quota state"
	if !strings.Contains(logs.String(), cause) || strings.Contains(w.Body.String(), cause) {
		t.Fatal("diagnostic missing or exposed", logs.String(), w.Body.String())
	}
}
