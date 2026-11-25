package throttle

import (
	"context"
	"errors"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

func TestRollingQuotasShareReplicasAndSurviveTightening(t *testing.T) {
	mr := miniredis.RunT(t)
	now := time.Now().UTC()
	mr.SetTime(now)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr(), ContextTimeoutEnabled: true, MaxRetries: -1})
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Error(err)
		}
	})
	build := func(limit int) *DynamicThrottler {
		d := NewDynamicThrottler(client, "test:", "read:{query.cabinet}", 1000, 100, 0)
		if err := d.SetQuotas(client, []RequestQuota{{Name: "daily", Key: "method:{query.cabinet}", Requests: limit, Window: 24 * time.Hour}}); err != nil {
			t.Fatal(err)
		}
		return d
	}
	first, second := build(20), build(20)
	ctx := WithRequest(context.Background(), httptest.NewRequest("GET", "/x?cabinet=dd", nil))
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			d := first
			if i%2 == 0 {
				d = second
			}
			err := d.admitQuotas(ctx)
			var blocked *RetryAfterError
			if err == nil {
				accepted.Add(1)
			} else if !errors.As(err, &blocked) || blocked.Wait != 24*time.Hour {
				t.Errorf("bad shared denial: %v", err)
			}
		}(i)
	}
	wg.Wait()
	if accepted.Load() != 20 {
		t.Fatal("quota overspent", accepted.Load())
	}
	var blocked *RetryAfterError
	if err := build(10).admitQuotas(ctx); !errors.As(err, &blocked) || blocked.Wait != 24*time.Hour {
		t.Fatal("tightening reset ledger", err)
	}
	other := WithRequest(context.Background(), httptest.NewRequest("GET", "/x?cabinet=other", nil))
	if err := first.admitQuotas(other); err != nil {
		t.Fatal("other cabinet blocked", err)
	}
	mr.SetTime(now.Add(24*time.Hour - time.Millisecond))
	if err := first.admitQuotas(ctx); !errors.As(err, &blocked) || blocked.Wait != time.Millisecond {
		t.Fatal("early rollover", err)
	}
	mr.SetTime(now.Add(24 * time.Hour))
	if err := first.admitQuotas(ctx); err != nil {
		t.Fatal("rolling boundary failed", err)
	}
}
func TestQuotaWindowsAreAtomicAndUseRedisClock(t *testing.T) {
	mr := miniredis.RunT(t)
	now := time.Now().UTC()
	mr.SetTime(now)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr(), ContextTimeoutEnabled: true, MaxRetries: -1})
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Error(err)
		}
	})
	d := NewDynamicThrottler(client, "test:", "read:{query.cabinet}", 1000, 100, 0)
	if err := d.SetQuotas(client, []RequestQuota{
		{Name: "minute", Key: "method:{query.cabinet}", Requests: 1, Window: time.Minute},
		{Name: "daily", Key: "method:{query.cabinet}", Requests: 2, Window: 24 * time.Hour},
	}); err != nil {
		t.Fatal(err)
	}
	ctx := WithRequest(context.Background(), httptest.NewRequest("GET", "/x?cabinet=dd", nil))
	if err := d.admitQuotas(ctx); err != nil {
		t.Fatal(err)
	}
	var blocked *RetryAfterError
	for range 4 {
		if err := d.admitQuotas(ctx); !errors.As(err, &blocked) || blocked.Wait != time.Minute {
			t.Fatal(err)
		}
	}
	mr.SetTime(now.Add(time.Minute))
	if err := d.admitQuotas(ctx); err != nil {
		t.Fatal("minute denials charged daily quota", err)
	}
	mr.SetTime(now.Add(2 * time.Minute))
	if err := d.admitQuotas(ctx); !errors.As(err, &blocked) || blocked.Wait != 24*time.Hour-2*time.Minute {
		t.Fatal("daily constraint lost", err)
	}
	mr.SetTime(now)
	if err := d.admitQuotas(ctx); !errors.Is(err, ErrBackendUnavailable) {
		t.Fatal("clock reversal allowed", err)
	}
	mr.Close()
	if err := d.admitQuotas(ctx); !errors.Is(err, ErrBackendUnavailable) {
		t.Fatal("outage allowed", err)
	}
}

func TestRequestQuotaWindowChangeFailsClosed(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr(), ContextTimeoutEnabled: true, MaxRetries: -1})
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Error(err)
		}
	})
	d := NewDynamicThrottler(client, "test:", "read:{query.cabinet}", 1000, 100, 0)
	quota := RequestQuota{Name: "minute", Key: "method:{query.cabinet}", Requests: 1, Window: time.Minute}
	if err := d.SetQuotas(client, []RequestQuota{quota}); err != nil {
		t.Fatal(err)
	}
	ctx := WithRequest(context.Background(), httptest.NewRequest("GET", "/x?cabinet=dd", nil))
	if err := d.admitQuotas(ctx); err != nil {
		t.Fatal(err)
	}
	quota.Window = time.Hour
	if err := d.SetQuotas(client, []RequestQuota{quota}); err != nil {
		t.Fatal(err)
	}
	if err := d.admitQuotas(ctx); !errors.Is(err, ErrBackendUnavailable) {
		t.Fatal("changed window forgot earlier attempts", err)
	}
	mr.FastForward(24 * time.Hour)
	if err := d.admitQuotas(ctx); err != nil {
		t.Fatal("expired history blocked new window", err)
	}
}

func TestRequestQuotaNativeRedisAtomicity(t *testing.T) {
	addr := os.Getenv("CSAR_REQUEST_QUOTA_TEST_REDIS")
	if addr == "" {
		t.Skip("isolated loopback Redis required")
	}
	if !strings.HasPrefix(addr, "127.0.0.1:") {
		t.Fatal("loopback Redis required")
	}
	client := redis.NewClient(&redis.Options{Addr: addr, ContextTimeoutEnabled: true, MaxRetries: -1})
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Error(err)
		}
	})
	prefix := "quota-test:" + uuid.NewString() + ":"
	d := NewDynamicThrottler(client, prefix, "read:{query.cabinet}", 1000, 100, 0)
	if err := d.SetQuotas(client, []RequestQuota{{Name: "day", Key: "method:{query.cabinet}", Requests: 20, Window: 24 * time.Hour}}); err != nil {
		t.Fatal(err)
	}
	ctx := WithRequest(context.Background(), httptest.NewRequest("GET", "/x?cabinet=dd", nil))
	var wg sync.WaitGroup
	var admitted atomic.Int32
	for range 40 {
		wg.Go(func() {
			err := d.admitQuotas(ctx)
			var wait *RetryAfterError
			if err == nil {
				admitted.Add(1)
			} else if !errors.As(err, &wait) || wait.Wait < 23*time.Hour {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if admitted.Load() != 20 {
		t.Fatal("native Redis overspent", admitted.Load())
	}
	if err := d.SetQuotas(client, []RequestQuota{{Name: "report-day", Key: "report:global", Requests: 0, Window: 24 * time.Hour}}); err != nil {
		t.Fatal(err)
	}
	var blocked *RetryAfterError
	if err := d.admitQuotas(ctx); !errors.As(err, &blocked) || blocked.Wait != 24*time.Hour {
		t.Fatal("native Redis did not close unverified report budget", err)
	}
}

func TestClosedQuotaCannotSpendOtherWindowsOrForgetAttempts(t *testing.T) {
	mr := miniredis.RunT(t)
	mr.SetTime(time.Now().UTC())
	client := redis.NewClient(&redis.Options{Addr: mr.Addr(), ContextTimeoutEnabled: true, MaxRetries: -1})
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Error(err)
		}
	})
	d := NewDynamicThrottler(client, "test:", "read:{query.cabinet}", 1000, 100, 0)
	quotas := []RequestQuota{{Name: "minute", Key: "reports:global", Requests: 2, Window: time.Minute}, {Name: "daily", Key: "reports:global", Requests: 0, Window: 24 * time.Hour}}
	if err := d.SetQuotas(client, quotas); err != nil {
		t.Fatal(err)
	}
	ctx := WithRequest(context.Background(), httptest.NewRequest("POST", "/reports", nil))
	for range 3 {
		var denied *RetryAfterError
		if err := d.admitQuotas(ctx); !errors.As(err, &denied) || denied.Wait != 24*time.Hour {
			t.Fatal("closed quota did not deny", err)
		}
	}
	quotas[1].Requests = 2
	if err := d.SetQuotas(client, quotas); err != nil {
		t.Fatal(err)
	}
	if err := d.admitQuotas(ctx); err != nil {
		t.Fatal("closed quota charged another window", err)
	}
	quotas[1].Requests = 0
	if err := d.SetQuotas(client, quotas); err != nil {
		t.Fatal(err)
	}
	var denied *RetryAfterError
	if err := d.admitQuotas(ctx); !errors.As(err, &denied) {
		t.Fatal(err)
	}
	quotas[1].Requests = 2
	if err := d.SetQuotas(client, quotas); err != nil {
		t.Fatal(err)
	}
	if err := d.admitQuotas(ctx); err != nil {
		t.Fatal(err)
	}
	if err := d.admitQuotas(ctx); !errors.As(err, &denied) || denied.Wait != 24*time.Hour {
		t.Fatal("reopening forgot spent attempts", err)
	}
}

func TestRuntimeQuotaValidationUsesFullPolicyShape(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr(), ContextTimeoutEnabled: true, MaxRetries: -1})
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Error(err)
		}
	})
	d := NewDynamicThrottler(client, "test:", "reads", 1000, 100, 0)
	good := RequestQuota{Name: "daily", Key: "reports:global", Requests: 1, Window: 24 * time.Hour}
	bad := good
	bad.Name = "has space"
	if d.SetQuotas(client, []RequestQuota{bad}) == nil {
		t.Fatal("runtime accepted invalid name")
	}
	if d.SetQuotas(client, []RequestQuota{good, good}) == nil {
		t.Fatal("runtime accepted duplicate quotas")
	}
	bad = good
	bad.Key = strings.Repeat("x", 257)
	if d.SetQuotas(client, []RequestQuota{bad}) == nil {
		t.Fatal("runtime accepted oversized key")
	}
	if d.SetQuotas(nil, []RequestQuota{good}) == nil {
		t.Fatal("missing Redis accepted")
	}
}

func TestQuotaBackendErrorRetainsCause(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr(), ContextTimeoutEnabled: true, MaxRetries: -1})
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Error(err)
		}
	})
	d := NewDynamicThrottler(client, "test:", "reads", 1000, 100, 0)
	if err := d.SetQuotas(client, []RequestQuota{{Name: "daily", Key: "reports:global", Requests: 1, Window: 24 * time.Hour}}); err != nil {
		t.Fatal(err)
	}
	mr.SetError("ERR local quota diagnostic")
	err := d.admitQuotas(WithRequest(context.Background(), httptest.NewRequest("POST", "/reports", nil)))
	var cause redis.Error
	if !errors.Is(err, ErrBackendUnavailable) || !errors.As(err, &cause) || !strings.Contains(err.Error(), "local quota diagnostic") {
		t.Fatal("quota error cause lost", err)
	}
}
