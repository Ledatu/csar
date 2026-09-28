package router

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/ledatu/csar/internal/apierror"
	"github.com/ledatu/csar/internal/config"
	"github.com/ledatu/csar/internal/throttle"
)

func TestRouter_WithThrottle_Passes(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	cfg := newTestConfig(map[string]config.PathConfig{
		"/throttled": {
			"get": config.RouteConfig{
				Backend: config.BackendConfig{TargetURL: upstream.URL},
				Traffic: &config.TrafficConfig{
					RPS:     100,
					Burst:   10,
					MaxWait: config.Duration{Duration: 5 * time.Second},
				},
			},
		},
	})

	r, err := New(cfg, newTestLogger())
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/throttled", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestRouter_WithThrottle_Timeout(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := newTestConfig(map[string]config.PathConfig{
		"/slow": {
			"get": config.RouteConfig{
				Backend: config.BackendConfig{TargetURL: upstream.URL},
				Traffic: &config.TrafficConfig{
					RPS:     1,
					Burst:   1,
					MaxWait: config.Duration{Duration: 50 * time.Millisecond},
				},
			},
		},
	})

	r, err := New(cfg, newTestLogger())
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	// Consume burst
	req := httptest.NewRequest(http.MethodGet, "/slow", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("first request failed: %d", rec.Code)
	}

	// Second request should timeout and get 503 (not 429!)
	req = httptest.NewRequest(http.MethodGet, "/slow", nil)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d (503, not 429)", rec.Code, http.StatusServiceUnavailable)
	}

	// Verify Retry-After header
	if rec.Header().Get("Retry-After") == "" {
		t.Error("missing Retry-After header")
	}
}

func newRedisThrottledRouter(t *testing.T, redisPassword string, upstreamCalls *int) *Router {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*upstreamCalls++
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	mr := miniredis.RunT(t)
	mr.RequireAuth("secret")
	client := throttle.NewRedisClient(throttle.RedisConfig{Address: mr.Addr(), Password: redisPassword})
	t.Cleanup(func() { _ = client.Close() })

	cfg := newTestConfig(map[string]config.PathConfig{
		"/finance": {
			"get": config.RouteConfig{
				Backend: config.BackendConfig{TargetURL: upstream.URL},
				Traffic: &config.TrafficConfig{
					Backend: "redis",
					RPS:     10,
					Burst:   10,
					MaxWait: config.Duration{Duration: 65 * time.Second},
				},
			},
		},
	})

	r, err := New(cfg, newTestLogger(), WithRedisClient(client))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	return r
}

func TestRouter_RedisThrottle_Passes(t *testing.T) {
	upstreamCalls := 0
	r := newRedisThrottledRouter(t, "secret", &upstreamCalls)

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/finance", nil))

	if rec.Code != http.StatusOK || upstreamCalls != 1 {
		t.Fatalf("status = %d, upstreamCalls = %d, want 200 and 1", rec.Code, upstreamCalls)
	}
}

func TestRouter_RedisThrottle_BackendFailureIsNotReportedAsRateLimit(t *testing.T) {
	upstreamCalls := 0
	r := newRedisThrottledRouter(t, "", &upstreamCalls)

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/finance", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if upstreamCalls != 0 {
		t.Fatalf("upstreamCalls = %d, want 0 (fail-closed)", upstreamCalls)
	}
	if got := rec.Header().Get("X-CSAR-Status"); got != "throttle_unavailable" {
		t.Errorf("X-CSAR-Status = %q, want throttle_unavailable", got)
	}
	for _, h := range []string{"Retry-After", "X-CSAR-Wait-MS"} {
		if got := rec.Header().Get(h); got != "" {
			t.Errorf("%s = %q, want absent", h, got)
		}
	}

	var body apierror.Response
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Code != apierror.CodeThrottleUnavailable {
		t.Errorf("code = %q, want %q", body.Code, apierror.CodeThrottleUnavailable)
	}
	if body.RetryAfterMS != nil {
		t.Errorf("retry_after_ms = %d, want absent", *body.RetryAfterMS)
	}
	if containsSubstr(rec.Body.String(), "NOAUTH") {
		t.Errorf("body leaks the Redis error: %s", rec.Body.String())
	}
}
