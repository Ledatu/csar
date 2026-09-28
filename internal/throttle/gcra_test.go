package throttle

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/ledatu/csar/pkg/middleware/authzmw"
)

func newMiniRedis(t *testing.T) *redis.Client {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func requestFor(tenant string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/ext/"+tenant+"/items", nil)
	return req.WithContext(authzmw.WithPathVars(req.Context(), map[string]string{"tenant": tenant}))
}

func waitFor(dt *DynamicThrottler, req *http.Request) error {
	return dt.Wait(WithRequest(context.Background(), req))
}

func requireNextSlot(t *testing.T, err error, lo, hi time.Duration) *RetryAfterError {
	t.Helper()
	var next *RetryAfterError
	if !errors.As(err, &next) {
		t.Fatalf("err = %v, want *RetryAfterError", err)
	}
	if next.Wait < lo || next.Wait > hi {
		t.Fatalf("next slot in %s, want within [%s, %s]", next.Wait, lo, hi)
	}
	return next
}

func TestResolveKey_PathVar(t *testing.T) {
	dt := NewDynamicThrottler(nil, "csar:rl:", "wbx:{path.tenant}:{header.X-Missing}", 10, 20, 0)
	if got := dt.resolveKey(requestFor("s777")); got != "wbx:s777:_unknown_" {
		t.Errorf("resolveKey() = %q", got)
	}
	bare := httptest.NewRequest(http.MethodGet, "/ext/x/items", nil)
	if got := dt.resolveKey(bare); got != "wbx:_unknown_:_unknown_" {
		t.Errorf("resolveKey() without path vars = %q", got)
	}
}

func TestDynamicThrottler_RejectsWithDistanceToNextSlot(t *testing.T) {
	dt := NewDynamicThrottler(newMiniRedis(t), "t:", "k:{path.tenant}", 1.0/20, 1, 100*time.Millisecond)
	if err := waitFor(dt, requestFor("a")); err != nil {
		t.Fatalf("first request: %v", err)
	}
	next := requireNextSlot(t, waitFor(dt, requestFor("a")), 19*time.Second, 20*time.Second)
	if next.Key != "k:a" {
		t.Errorf("Key = %q, want k:a", next.Key)
	}
	if err := waitFor(dt, requestFor("b")); err != nil {
		t.Fatalf("other key must have its own bucket: %v", err)
	}
}

func TestDynamicThrottler_ParksWithinMaxWait(t *testing.T) {
	dt := NewDynamicThrottler(newMiniRedis(t), "t:", "k:{path.tenant}", 20, 1, time.Second)
	if err := waitFor(dt, requestFor("a")); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := waitFor(dt, requestFor("a")); err != nil {
		t.Fatalf("second request should park, got %v", err)
	}
	if waited := time.Since(start); waited < 30*time.Millisecond {
		t.Errorf("parked %s, want about one emission interval (50ms)", waited)
	}
}

func TestDynamicThrottler_SuspensionIsPerKey(t *testing.T) {
	dt := NewDynamicThrottler(newMiniRedis(t), "t:", "k:{path.tenant}", 100, 10, 50*time.Millisecond)
	if err := dt.SuspendRequestFor(requestFor("a"), 30*time.Second); err != nil {
		t.Fatal(err)
	}
	requireNextSlot(t, waitFor(dt, requestFor("a")), 29*time.Second, 30*time.Second)
	if err := waitFor(dt, requestFor("b")); err != nil {
		t.Fatalf("suspension leaked to another key: %v", err)
	}
}

func TestDynamicThrottler_SuspensionNeverShrinks(t *testing.T) {
	dt := NewDynamicThrottler(newMiniRedis(t), "t:", "k:{path.tenant}", 100, 10, 0)
	req := requestFor("a")
	if err := dt.SuspendRequestFor(req, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := dt.SuspendRequestFor(req, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	requireNextSlot(t, waitFor(dt, req), 29*time.Second, 30*time.Second)
}

func TestDynamicThrottler_AdmitsOneThenPacesAfterSuspension(t *testing.T) {
	dt := NewDynamicThrottler(newMiniRedis(t), "t:", "k:{path.tenant}", 10, 5, 0)
	req := requestFor("a")
	if err := dt.SuspendRequestFor(req, 150*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	requireNextSlot(t, waitFor(dt, req), 100*time.Millisecond, 150*time.Millisecond)
	time.Sleep(170 * time.Millisecond)
	if err := waitFor(dt, req); err != nil {
		t.Fatalf("first request after suspension: %v", err)
	}
	requireNextSlot(t, waitFor(dt, req), 50*time.Millisecond, 100*time.Millisecond)
}

func TestRedisThrottler_SuspendsWholeRoute(t *testing.T) {
	rt := NewRedisThrottler(newMiniRedis(t), "t:", "GET:/x", 100, 10, 0)
	if err := rt.SuspendRequestFor(nil, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	next := requireNextSlot(t, rt.Wait(context.Background()), 4*time.Second, 5*time.Second)
	if next.Key != "GET:/x" {
		t.Errorf("Key = %q, want the route key", next.Key)
	}
}
