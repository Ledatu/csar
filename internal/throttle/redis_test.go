package throttle

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newTestRedisClient(t *testing.T, mr *miniredis.Miniredis, password string) *redis.Client {
	t.Helper()
	client := NewRedisClient(RedisConfig{Address: mr.Addr(), Password: password})
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestRedisThrottler_OverLimitIsNotBackendError(t *testing.T) {
	mr := miniredis.RunT(t)
	rt := NewRedisThrottler(newTestRedisClient(t, mr, ""), "", "GET:/finance", 1, 1, 0)

	if err := rt.Wait(context.Background()); err != nil {
		t.Fatalf("first Wait: %v", err)
	}
	err := rt.Wait(context.Background())
	if err == nil {
		t.Fatal("second Wait: expected rate-limit rejection")
	}
	if errors.Is(err, ErrBackendUnavailable) {
		t.Fatalf("over-limit rejection must not be ErrBackendUnavailable: %v", err)
	}
}

func TestRedisThrottler_AuthFailureIsBackendError(t *testing.T) {
	mr := miniredis.RunT(t)
	mr.RequireAuth("secret")
	rt := NewRedisThrottler(newTestRedisClient(t, mr, ""), "", "GET:/finance", 10, 10, 65*time.Second)

	err := rt.Wait(context.Background())
	if !errors.Is(err, ErrBackendUnavailable) {
		t.Fatalf("Wait error = %v, want ErrBackendUnavailable", err)
	}
}

func TestRedisThrottler_UnreachableIsBackendError(t *testing.T) {
	mr := miniredis.RunT(t)
	rt := NewRedisThrottler(newTestRedisClient(t, mr, ""), "", "GET:/finance", 10, 10, time.Second)
	mr.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := rt.Wait(ctx)
	if !errors.Is(err, ErrBackendUnavailable) {
		t.Fatalf("Wait error = %v, want ErrBackendUnavailable", err)
	}
}

func TestRedisThrottler_RequestDeadlineDuringRedisCallIsNotBackendError(t *testing.T) {
	mr := miniredis.RunT(t)
	rt := NewRedisThrottler(newTestRedisClient(t, mr, ""), "", "GET:/finance", 10, 10, time.Second)
	mr.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err := rt.Wait(ctx)
	if err == nil || errors.Is(err, ErrBackendUnavailable) {
		t.Fatalf("Wait error = %v, want client cancellation", err)
	}
}

func TestDynamicThrottler_AuthFailureIsBackendError(t *testing.T) {
	mr := miniredis.RunT(t)
	mr.RequireAuth("secret")
	dt := NewDynamicThrottler(newTestRedisClient(t, mr, ""), "", "seller:{query.seller_id}", 10, 10, 65*time.Second)

	req := httptest.NewRequest("GET", "/finance?seller_id=42", nil)
	err := dt.Wait(WithRequest(context.Background(), req))
	if !errors.Is(err, ErrBackendUnavailable) {
		t.Fatalf("Wait error = %v, want ErrBackendUnavailable", err)
	}
}

func TestDynamicThrottler_OverLimitIsNotBackendError(t *testing.T) {
	mr := miniredis.RunT(t)
	mr.RequireAuth("secret")
	dt := NewDynamicThrottler(newTestRedisClient(t, mr, "secret"), "", "seller:{query.seller_id}", 1, 1, 0)

	req := httptest.NewRequest("GET", "/finance?seller_id=42", nil)
	ctx := WithRequest(context.Background(), req)
	if err := dt.Wait(ctx); err != nil {
		t.Fatalf("first Wait: %v", err)
	}
	err := dt.Wait(ctx)
	if err == nil || errors.Is(err, ErrBackendUnavailable) {
		t.Fatalf("second Wait error = %v, want rate-limit rejection", err)
	}
}
