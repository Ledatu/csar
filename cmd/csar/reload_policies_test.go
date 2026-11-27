package main

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/ledatu/csar/internal/config"
	"github.com/ledatu/csar/internal/logging"
	"github.com/ledatu/csar/internal/protoconv"
	"github.com/ledatu/csar/internal/router"
	"github.com/ledatu/csar/internal/throttle"
	csarv1 "github.com/ledatu/csar/proto/csar/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
)

func decodeReloadSnapshot(t *testing.T, snap *csarv1.FullConfigSnapshot) *config.Config {
	t.Helper()
	wire, err := proto.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	var decoded csarv1.FullConfigSnapshot
	if err := proto.Unmarshal(wire, &decoded); err != nil {
		t.Fatal(err)
	}
	cfg := protoconv.FullSnapshotToConfig(&decoded)
	if err := cfg.ResolvePolicies(); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestReloadRedisPrefix(t *testing.T) {
	for _, dynamic := range []bool{false, true} {
		t.Run(map[bool]string{false: "static", true: "dynamic"}[dynamic], func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"value":1}`))
			}))
			defer upstream.Close()
			mr := miniredis.RunT(t)
			client := throttle.NewRedisClient(throttle.RedisConfig{Address: mr.Addr()})
			defer client.Close()
			cfg := reloadTestConfig(upstream.URL, &config.SSRFConfig{AllowedInternalHosts: []string{"127.0.0.1"}})
			cfg.Redis = &config.RedisConfig{Address: mr.Addr(), KeyPrefix: "original:"}
			rl := newTestReloader(t, cfg, router.WithRedisClient(client))
			key := ""
			if dynamic {
				key = "preferences:{method}"
			}
			snap := &csarv1.FullConfigSnapshot{Routes: []*csarv1.RouteConfig{{
				Path: "/preferences", Method: "GET", TargetUrl: upstream.URL,
				TrafficConfig: &csarv1.TrafficConfigProto{Backend: "redis", Rps: 100, Burst: 100, Key: key},
				Cache:         &csarv1.CacheConfigProto{Store: "redis", Key: "preferences", Ttl: durationpb.New(time.Minute)},
			}}}
			for _, tc := range []struct {
				name   string
				prefix *string
				want   string
			}{
				{"legacy keeps startup prefix", nil, "original:"},
				{"new prefix", proto.String("updated:"), "updated:"},
				{"legacy keeps updated prefix", nil, "updated:"},
				{"explicit empty resets defaults", proto.String(""), ""},
				{"legacy keeps defaults", nil, ""},
			} {
				t.Run(tc.name, func(t *testing.T) {
					mr.FlushAll()
					snap.RedisKeyPrefix = tc.prefix
					incoming := decodeReloadSnapshot(t, snap)
					if err := rl.Apply(incoming); err != nil {
						t.Fatal(err)
					}
					if tc.prefix == nil && incoming.Redis != nil {
						t.Fatal("reload mutated the caller's legacy snapshot")
					}
					checkReloadStatus(t, rl.reloadHandler, http.StatusOK)
					throttlePrefix, cachePrefix := tc.want, tc.want+"cache:"
					if tc.want == "" {
						throttlePrefix, cachePrefix = "csar:rl:", "csar:cache:"
					}
					var sawThrottle, sawCache bool
					for _, key := range mr.Keys() {
						switch {
						case strings.HasPrefix(key, cachePrefix):
							sawCache = true
						case strings.HasPrefix(key, throttlePrefix):
							sawThrottle = true
						default:
							t.Fatalf("unexpected Redis namespace in key %q", key)
						}
					}
					if !sawThrottle || !sawCache {
						t.Fatalf("throttle=%v cache=%v, keys=%v", sawThrottle, sawCache, mr.Keys())
					}
				})
			}

			// Failed builds must not install a prefix for a later legacy replay.
			snap.RedisKeyPrefix = proto.String("failed:")
			invalid := decodeReloadSnapshot(t, snap)
			invalid.AccessControl = &config.AccessControlConfig{AllowCIDRs: []string{"invalid"}}
			if err := rl.Apply(invalid); err == nil || rl.redisKeyPrefix != "" {
				t.Fatal("failed reload changed the active prefix")
			}
			if err := rl.Reload(cfg); err != nil || rl.redisKeyPrefix != "original:" {
				t.Fatal("local YAML reload did not restore its prefix")
			}
			cfg.Redis = nil
			if err := rl.Reload(cfg); err != nil || rl.redisKeyPrefix != "" {
				t.Fatal("omitted local Redis block did not reset the prefix")
			}
		})
	}
}

func TestReloadGlobalThrottleRemoval(t *testing.T) {
	for _, source := range []string{"yaml", "coordinator"} {
		t.Run(source, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			}))
			defer upstream.Close()
			cfg := reloadTestConfig(upstream.URL, &config.SSRFConfig{AllowedInternalHosts: []string{"127.0.0.1"}})
			// Refill takes 1000s, so a 1s budget still rejects the second request
			// immediately. Avoid a 1ms deadline expiring while CI schedules the
			// first request even though the initial burst token is available.
			cfg.GlobalThrottle = &config.GlobalThrottleConfig{RPS: 0.001, Burst: 1, MaxWait: config.Duration{Duration: time.Second}}
			rl := newTestReloader(t, cfg)
			old := rl.currentRouter
			checkReloadStatus(t, rl.reloadHandler, http.StatusNoContent)
			checkReloadStatus(t, rl.reloadHandler, http.StatusServiceUnavailable)

			// This build reaches global-throttle setup, then fails on the ACL.
			invalid := reloadTestConfig(upstream.URL, cfg.SSRF)
			invalid.GlobalThrottle = &config.GlobalThrottleConfig{RPS: 1000, Burst: 1000}
			invalid.AccessControl = &config.AccessControlConfig{AllowCIDRs: []string{"invalid"}}
			if err := rl.Reload(invalid); err == nil {
				t.Fatal("invalid reload succeeded")
			}
			checkReloadStatus(t, rl.reloadHandler, http.StatusServiceUnavailable)

			removed := reloadTestConfig(upstream.URL, cfg.SSRF)
			apply := rl.Reload
			if source == "coordinator" {
				apply = rl.Apply
				removed = decodeReloadSnapshot(t, &csarv1.FullConfigSnapshot{Routes: []*csarv1.RouteConfig{{
					Path: "/preferences", Method: "GET", TargetUrl: upstream.URL,
				}}})
			}
			if err := apply(removed); err != nil {
				t.Fatal(err)
			}
			for range 3 {
				checkReloadStatus(t, rl.reloadHandler, http.StatusNoContent)
			}
			checkReloadStatus(t, old, http.StatusServiceUnavailable)
		})
	}
}

func TestGlobalThrottleConcurrentReload(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer upstream.Close()
	newCfg := func(enabled bool) *config.Config {
		cfg := reloadTestConfig(upstream.URL, &config.SSRFConfig{AllowedInternalHosts: []string{"127.0.0.1"}})
		if enabled {
			cfg.GlobalThrottle = &config.GlobalThrottleConfig{RPS: 0.001, Burst: 1, MaxWait: config.Duration{Duration: time.Millisecond}}
		}
		return cfg
	}
	rl := newTestReloader(t, newCfg(true))
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 80 {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			rr := httptest.NewRecorder()
			rl.reloadHandler.ServeHTTP(rr, httptest.NewRequestWithContext(ctx, http.MethodGet, "/preferences", nil))
			cancel()
			if rr.Code != http.StatusNoContent && rr.Code != http.StatusServiceUnavailable {
				t.Errorf("concurrent status = %d", rr.Code)
			}
		}
	}()
	defer wg.Wait()
	for i := range 20 {
		if err := rl.Reload(newCfg(i%2 == 0)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestReloadRestartWarningsDoNotExposeValues(t *testing.T) {
	cfg := reloadTestConfig("https://upstream.example", nil)
	cfg.Redis = &config.RedisConfig{Address: "old-host:6379", Password: logging.NewSecret("old-secret")}
	rl := newTestReloader(t, cfg)
	var logs bytes.Buffer
	rl.logger = slog.New(slog.NewTextHandler(&logs, nil))
	updated := reloadTestConfig("https://upstream.example", nil)
	updated.Redis = &config.RedisConfig{Address: "new-host:6379", Password: logging.NewSecret("new-secret")}
	if err := rl.Reload(updated); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"redis.address", "redis.password"} {
		if !strings.Contains(logs.String(), "field="+field) {
			t.Fatalf("missing warning for %s", field)
		}
	}
	for _, value := range []string{"old-host", "new-host", "old-secret", "new-secret"} {
		if strings.Contains(logs.String(), value) {
			t.Fatal("restart warning exposed a configuration value")
		}
	}
	logs.Reset()
	if err := rl.Apply(reloadTestConfig("https://upstream.example", nil)); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(logs.String(), "restart required") {
		t.Fatal("missing bootstrap fields in a gRPC snapshot triggered a restart warning")
	}
}
