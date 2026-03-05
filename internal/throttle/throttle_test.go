package throttle

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestThrottler_AllowsBurst(t *testing.T) {
	// 1 RPS with burst of 5 should allow 5 immediate requests
	th := New(1, 5, 10*time.Second)

	for i := 0; i < 5; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		err := th.Wait(ctx)
		cancel()
		if err != nil {
			t.Fatalf("request %d should be allowed within burst: %v", i, err)
		}
	}
}

func TestThrottler_SmoothsInsteadOfRejecting(t *testing.T) {
	// 10 RPS, burst 1, max_wait 2s
	// After burst is consumed, next request should wait ~100ms, not fail
	th := New(10, 1, 2*time.Second)

	// Consume the burst
	ctx := context.Background()
	if err := th.Wait(ctx); err != nil {
		t.Fatalf("burst request failed: %v", err)
	}

	// Next request should wait but succeed (smoothing)
	start := time.Now()
	if err := th.Wait(ctx); err != nil {
		t.Fatalf("smoothed request should succeed: %v", err)
	}
	elapsed := time.Since(start)

	// Should have waited roughly 100ms (1/10 RPS)
	if elapsed < 50*time.Millisecond {
		t.Errorf("expected wait ~100ms, got %v (too fast)", elapsed)
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("expected wait ~100ms, got %v (too slow)", elapsed)
	}
}

func TestThrottler_TimeoutExceeded(t *testing.T) {
	// 1 RPS, burst 1, max_wait 50ms
	th := New(1, 1, 50*time.Millisecond)

	ctx := context.Background()
	// Consume the burst
	if err := th.Wait(ctx); err != nil {
		t.Fatalf("burst request failed: %v", err)
	}

	// Next request: 1 RPS means ~1s wait, but max_wait is 50ms -> should fail
	err := th.Wait(ctx)
	if err == nil {
		t.Fatal("should fail when max_wait exceeded")
	}
}

func TestThrottler_ClientCancellation(t *testing.T) {
	// 1 RPS, burst 1, max_wait 10s
	th := New(1, 1, 10*time.Second)

	ctx := context.Background()
	if err := th.Wait(ctx); err != nil {
		t.Fatalf("burst failed: %v", err)
	}

	// Cancel the client context immediately
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := th.Wait(ctx)
	if err == nil {
		t.Fatal("should fail when client context is cancelled")
	}
}

func TestThrottler_WaitingCounter(t *testing.T) {
	// Test that the Waiting() counter reflects queued requests.
	// We test this indirectly: fire many concurrent requests at a slow limiter,
	// and verify at least some of them are waiting simultaneously.
	th := New(1, 1, 5*time.Second) // 1 RPS, burst 1

	// Consume burst
	if err := th.Wait(context.Background()); err != nil {
		t.Fatalf("burst failed: %v", err)
	}

	const n = 10
	var wg sync.WaitGroup
	var maxWaiting atomic.Int64

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Sample the counter while we're about to wait
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			th.Wait(ctx) //nolint: errcheck
		}()
	}

	// Poll the waiting counter — with 1 RPS and 10 goroutines, several should queue up
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			goto checkResult
		case <-ticker.C:
			w := th.Waiting()
			for {
				old := maxWaiting.Load()
				if w <= old || maxWaiting.CompareAndSwap(old, w) {
					break
				}
			}
		}
	}

checkResult:
	if maxWaiting.Load() < 2 {
		t.Errorf("max concurrent Waiting() = %d, want >= 2", maxWaiting.Load())
	}

	if th.Waiting() != 0 {
		t.Errorf("Waiting() = %d after completion, want 0", th.Waiting())
	}
}

func TestThrottler_UpdateLimit(t *testing.T) {
	// Start with very slow rate
	th := New(0.1, 1, 2*time.Second)
	// Consume burst
	if err := th.Wait(context.Background()); err != nil {
		t.Fatalf("burst failed: %v", err)
	}

	// Update to fast rate
	th.UpdateLimit(1000, 10)

	// Should now be fast
	start := time.Now()
	if err := th.Wait(context.Background()); err != nil {
		t.Fatalf("should succeed after update: %v", err)
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Errorf("should be fast after limit update, took %v", time.Since(start))
	}
}

func TestThrottler_ConcurrentAccess(t *testing.T) {
	// 100 RPS, burst 10, max_wait 5s
	th := New(100, 10, 5*time.Second)

	var wg sync.WaitGroup
	var succeeded atomic.Int64
	var failed atomic.Int64

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := th.Wait(ctx); err != nil {
				failed.Add(1)
			} else {
				succeeded.Add(1)
			}
		}()
	}

	wg.Wait()

	// With 100 RPS and 2s timeout, all 50 should succeed
	if succeeded.Load() != 50 {
		t.Errorf("succeeded = %d, failed = %d, want all 50 to succeed", succeeded.Load(), failed.Load())
	}
}

func TestThrottleManager_RegisterAndGet(t *testing.T) {
	m := NewManager()

	m.Register("GET:/api", 10, 5, time.Second)
	m.Register("POST:/api", 20, 10, 2*time.Second)

	th := m.Get("GET:/api")
	if th == nil {
		t.Fatal("Get(GET:/api) returned nil")
	}

	th = m.Get("POST:/api")
	if th == nil {
		t.Fatal("Get(POST:/api) returned nil")
	}

	th = m.Get("DELETE:/api")
	if th != nil {
		t.Fatal("Get(DELETE:/api) should return nil for unregistered key")
	}
}

func TestRouteKey(t *testing.T) {
	key := RouteKey("GET", "/api/v1")
	if key != "GET:/api/v1" {
		t.Errorf("RouteKey = %q, want %q", key, "GET:/api/v1")
	}
}

func TestThrottleManager_SyncKeys(t *testing.T) {
	m := NewManager()

	// Register several keys
	m.Register("GET:/api/v1", 10, 5, time.Second)
	m.Register("POST:/api/v1", 20, 10, time.Second)
	m.Register("GET:/api/v2", 30, 15, time.Second)
	m.Register("DELETE:/old-endpoint", 5, 2, time.Second)

	// Verify all exist
	if len(m.Keys()) != 4 {
		t.Fatalf("expected 4 keys, got %d", len(m.Keys()))
	}

	// Sync with only a subset of keys (simulate a config reload that removed some routes)
	activeKeys := []string{"GET:/api/v1", "GET:/api/v2"}
	pruned := m.SyncKeys(activeKeys)

	if pruned != 2 {
		t.Errorf("expected 2 pruned, got %d", pruned)
	}

	if len(m.Keys()) != 2 {
		t.Errorf("expected 2 keys remaining, got %d", len(m.Keys()))
	}

	// Active keys should still exist
	if m.Get("GET:/api/v1") == nil {
		t.Error("GET:/api/v1 should still exist")
	}
	if m.Get("GET:/api/v2") == nil {
		t.Error("GET:/api/v2 should still exist")
	}

	// Pruned keys should be gone
	if m.Get("POST:/api/v1") != nil {
		t.Error("POST:/api/v1 should have been pruned")
	}
	if m.Get("DELETE:/old-endpoint") != nil {
		t.Error("DELETE:/old-endpoint should have been pruned")
	}
}

func TestThrottleManager_SyncKeys_EmptyActive(t *testing.T) {
	m := NewManager()
	m.Register("GET:/api", 10, 5, time.Second)
	m.Register("POST:/api", 20, 10, time.Second)

	pruned := m.SyncKeys(nil)
	if pruned != 2 {
		t.Errorf("expected 2 pruned, got %d", pruned)
	}
	if len(m.Keys()) != 0 {
		t.Errorf("expected 0 keys, got %d", len(m.Keys()))
	}
}

func TestThrottleManager_SyncKeys_AllActive(t *testing.T) {
	m := NewManager()
	m.Register("GET:/api", 10, 5, time.Second)
	m.Register("POST:/api", 20, 10, time.Second)

	pruned := m.SyncKeys([]string{"GET:/api", "POST:/api"})
	if pruned != 0 {
		t.Errorf("expected 0 pruned, got %d", pruned)
	}
	if len(m.Keys()) != 2 {
		t.Errorf("expected 2 keys, got %d", len(m.Keys()))
	}
}

func TestWaiterInterface_ThrottlerSatisfies(t *testing.T) {
	var w Waiter = New(10, 5, time.Second)
	if w == nil {
		t.Fatal("Throttler should satisfy Waiter interface")
	}
	if w.Waiting() != 0 {
		t.Errorf("Waiting() = %d, want 0", w.Waiting())
	}
}

func TestThrottleManager_RegisterWaiter(t *testing.T) {
	m := NewManager()
	th := New(10, 5, time.Second)
	m.RegisterWaiter("custom:key", th)

	got := m.Get("custom:key")
	if got == nil {
		t.Fatal("RegisterWaiter should store the waiter")
	}
	if got != th {
		t.Error("Get should return the same waiter instance")
	}
}

func TestThrottleManager_GlobalThrottle(t *testing.T) {
	m := NewManager()

	// Before setting
	if m.GetGlobal() != nil {
		t.Error("GetGlobal should return nil before setting")
	}

	// After setting
	m.SetGlobal(1000, 2000, 0)
	g := m.GetGlobal()
	if g == nil {
		t.Fatal("GetGlobal should return non-nil after setting")
	}

	// Should be usable
	ctx := context.Background()
	if err := g.Wait(ctx); err != nil {
		t.Fatalf("global throttle Wait failed: %v", err)
	}
}

func TestThrottleManager_UpdateQuota_Waiter(t *testing.T) {
	m := NewManager()
	th := New(1, 1, time.Second)
	m.RegisterWaiter("key", th)

	// UpdateQuota should work with Waiter
	ok := m.UpdateQuota("key", 100, 50)
	if !ok {
		t.Error("UpdateQuota should return true for existing key")
	}

	// Verify the update took effect by testing we can make many fast requests
	for i := 0; i < 10; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		err := th.Wait(ctx)
		cancel()
		if err != nil {
			t.Fatalf("request %d should succeed after quota update: %v", i, err)
		}
	}
}

func TestThrottleManager_SyncKeys_WithWaiters(t *testing.T) {
	m := NewManager()
	m.Register("key1", 10, 5, time.Second)
	m.RegisterWaiter("key2", New(20, 10, time.Second))

	if len(m.Keys()) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(m.Keys()))
	}

	pruned := m.SyncKeys([]string{"key1"})
	if pruned != 1 {
		t.Errorf("expected 1 pruned, got %d", pruned)
	}

	if m.Get("key1") == nil {
		t.Error("key1 should still exist")
	}
	if m.Get("key2") != nil {
		t.Error("key2 should have been pruned")
	}
}
