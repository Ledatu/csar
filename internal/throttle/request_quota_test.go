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
}
