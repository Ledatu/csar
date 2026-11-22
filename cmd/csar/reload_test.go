package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ledatu/csar/internal/config"
	"github.com/ledatu/csar/internal/protoconv"
	"github.com/ledatu/csar/internal/router"
	"github.com/ledatu/csar/internal/telemetry"
	"github.com/ledatu/csar/internal/throttle"
	csarv1 "github.com/ledatu/csar/proto/csar/v1"
	"google.golang.org/protobuf/proto"
)

func reloadTestConfig(target string, ssrf *config.SSRFConfig) *config.Config {
	return &config.Config{
		SSRF: ssrf,
		Paths: map[string]config.PathConfig{
			"/preferences": {"get": {Backend: config.BackendConfig{TargetURL: target}}},
		},
	}
}

func newTestReloader(t *testing.T, cfg *config.Config, extraOpts ...router.Option) *routerReloader {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tp, err := telemetry.Init(context.Background(), telemetry.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tp.Close() })
	tm := throttle.NewManager()
	ssrf := buildSSRFProtection(cfg.SSRF)
	opts := []router.Option{router.WithThrottleManager(tm)}
	opts = append(opts, extraOpts...)
	initialOpts := append([]router.Option{router.WithSSRFProtection(ssrf)}, opts...)
	r, err := router.New(cfg, logger, initialOpts...)
	if err != nil {
		t.Fatal(err)
	}
	rl := &routerReloader{
		logger: logger, routerOpts: opts, tp: tp, sharedTM: tm,
		currentRouter: r, ssrfProtection: ssrf,
		originReceivers: cfg.HasOriginReceivers(),
		restartSnapshot: config.SnapshotRestartRequired(cfg),
		reloadHandler:   newReloadableHandler(tp.HTTPMiddleware("csar", r)),
	}
	if cfg.Redis != nil {
		rl.redisKeyPrefix = cfg.Redis.KeyPrefix
	}
	t.Cleanup(func() { rl.currentRouter.Close() })
	return rl
}

func checkReloadStatus(t *testing.T, handler http.Handler, want int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequestWithContext(ctx, http.MethodGet, "/preferences", nil))
	if rr.Code != want {
		t.Fatalf("status = %d, want %d; body: %s", rr.Code, want, rr.Body.String())
	}
}

func TestReloadRejectsIncompatibleOriginPolicySnapshot(t *testing.T) {
	rl := newTestReloader(t, reloadTestConfig("http://example.com", nil))
	prior := rl.currentRouter
	rl.originReceivers = true
	cfg := reloadTestConfig("http://other.example", nil)
	if err := rl.Apply(cfg); err == nil || rl.currentRouter != prior || !rl.originReceivers {
		t.Fatal("legacy snapshot replaced an active origin policy")
	}
	cfg.OriginPolicyVersion = config.OriginPolicyVersion + 1
	if err := rl.Apply(cfg); err == nil || rl.currentRouter != prior {
		t.Fatal("unknown policy version replaced the live router")
	}
	cfg.OriginPolicyVersion = config.OriginPolicyVersion
	if err := rl.Apply(cfg); err != nil || rl.originReceivers {
		t.Fatal("explicit current-version policy removal failed", err)
	}
	// Legacy snapshots remain compatible after a deliberate removal.
	cfg.OriginPolicyVersion = 0
	if err := rl.Apply(cfg); err != nil {
		t.Fatal(err)
	}
}

func TestReloadSSRFAllowAndRevoke(t *testing.T) {
	for _, source := range []string{"yaml", "coordinator"} {
		t.Run(source, func(t *testing.T) {
			var hits atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				hits.Add(1)
				w.WriteHeader(http.StatusNoContent)
			}))
			defer upstream.Close()
			rl := newTestReloader(t, reloadTestConfig(upstream.URL, nil))
			checkReloadStatus(t, rl.reloadHandler, http.StatusBadGateway)
			if hits.Load() != 0 {
				t.Fatal("blocked request reached upstream")
			}

			apply := rl.Reload
			if source == "coordinator" {
				apply = func(cfg *config.Config) error {
					// Exercise wire serialization and the actual router-side conversion.
					snap := &csarv1.FullConfigSnapshot{
						Routes: []*csarv1.RouteConfig{{Path: "/preferences", Method: "GET", TargetUrl: upstream.URL}},
						SsrfProtection: &csarv1.SSRFProtectionProto{
							AllowedInternalHosts: cfg.SSRF.AllowedInternalHosts,
						},
					}
					wire, err := proto.Marshal(snap)
					if err != nil {
						return err
					}
					var received csarv1.FullConfigSnapshot
					if err := proto.Unmarshal(wire, &received); err != nil {
						return err
					}
					return rl.Apply(protoconv.FullSnapshotToConfig(&received))
				}
			}

			allowed := &config.SSRFConfig{AllowedInternalHosts: []string{"127.0.0.1"}}
			if err := apply(reloadTestConfig(upstream.URL, allowed)); err != nil {
				t.Fatal(err)
			}
			checkReloadStatus(t, rl.reloadHandler, http.StatusNoContent)
			oldPolicy := rl.ssrfProtection
			if err := apply(reloadTestConfig(upstream.URL, &config.SSRFConfig{})); err != nil {
				t.Fatal(err)
			}
			checkReloadStatus(t, rl.reloadHandler, http.StatusBadGateway)
			if hits.Load() != 1 {
				t.Fatalf("upstream hits = %d, want 1", hits.Load())
			}
			if !oldPolicy.AllowedHosts["127.0.0.1"] {
				t.Fatal("reload mutated the previous router's policy")
			}
		})
	}
}

func TestReloadSSRFLegacyAndFailedApply(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	allowed := &config.SSRFConfig{AllowedInternalHosts: []string{"127.0.0.1"}}
	rl := newTestReloader(t, reloadTestConfig(upstream.URL, allowed))

	if err := rl.Apply(reloadTestConfig(upstream.URL, nil)); err != nil {
		t.Fatal(err)
	}
	checkReloadStatus(t, rl.reloadHandler, http.StatusNoContent)

	invalid := reloadTestConfig(upstream.URL, &config.SSRFConfig{})
	invalid.AccessControl = &config.AccessControlConfig{AllowCIDRs: []string{"invalid"}}
	before := rl.currentRouter
	if err := rl.Apply(invalid); err == nil {
		t.Fatal("invalid reload succeeded")
	}
	if rl.currentRouter != before || !rl.ssrfProtection.AllowedHosts["127.0.0.1"] {
		t.Fatal("failed reload replaced the active router or policy")
	}
	checkReloadStatus(t, rl.reloadHandler, http.StatusNoContent)

	// A complete local YAML reload removes grants when the block is omitted.
	if err := rl.Reload(reloadTestConfig(upstream.URL, nil)); err != nil {
		t.Fatal(err)
	}
	checkReloadStatus(t, rl.reloadHandler, http.StatusBadGateway)
	if err := rl.Apply(reloadTestConfig(upstream.URL, nil)); err != nil {
		t.Fatal(err)
	}
	checkReloadStatus(t, rl.reloadHandler, http.StatusBadGateway)
}

func TestReloadSSRFPreservesInFlightRequest(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	defer close(release)
	rl := newTestReloader(t, reloadTestConfig(upstream.URL, &config.SSRFConfig{AllowedInternalHosts: []string{"127.0.0.1"}}))
	done := make(chan int, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		rr := httptest.NewRecorder()
		rl.reloadHandler.ServeHTTP(rr, httptest.NewRequestWithContext(ctx, http.MethodGet, "/preferences", nil))
		done <- rr.Code
	}()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("request did not reach upstream")
	}
	if err := rl.Reload(reloadTestConfig(upstream.URL, nil)); err != nil {
		t.Fatal(err)
	}
	checkReloadStatus(t, rl.reloadHandler, http.StatusBadGateway)
	// Release the old request without closing the channel twice on cleanup.
	release <- struct{}{}
	select {
	case status := <-done:
		if status != http.StatusNoContent {
			t.Fatalf("in-flight status = %d", status)
		}
	case <-ctx.Done():
		t.Fatal("in-flight request was not completed")
	}
}

func TestReloadSSRFBlockSwitch(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	rl := newTestReloader(t, reloadTestConfig(upstream.URL, nil))
	for _, block := range []bool{false, true} {
		if err := rl.Reload(reloadTestConfig(upstream.URL, &config.SSRFConfig{BlockLoopback: &block})); err != nil {
			t.Fatal(err)
		}
		want := http.StatusNoContent
		if block {
			want = http.StatusBadGateway
		}
		checkReloadStatus(t, rl.reloadHandler, want)
	}
}
