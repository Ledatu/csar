package throttle

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestExhaustedMethodQuotaCannotStarveSharedRead(t *testing.T) {
	mr := miniredis.RunT(t)
	mr.SetTime(time.Now().UTC())
	client := redis.NewClient(&redis.Options{Addr: mr.Addr(), ContextTimeoutEnabled: true, MaxRetries: -1})
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Error(err)
		}
	})
	ctx := WithRequest(context.Background(), httptest.NewRequest("POST", "/x?cabinet=dd", nil))
	stocks := NewDynamicThrottler(client, "test:", "shared:{query.cabinet}", 0.5, 1, 0)
	if err := stocks.SetQuotas(client, []RequestQuota{{Name: "minute", Key: "stocks:{query.cabinet}", Requests: 1, Window: time.Minute}}); err != nil {
		t.Fatal(err)
	}
	if err := stocks.admitQuotas(ctx); err != nil {
		t.Fatal(err)
	}
	for range 10 {
		var denied *RetryAfterError
		if err := stocks.Wait(ctx); !errors.As(err, &denied) || denied.Key != "request-quota" || denied.Wait != time.Minute {
			t.Fatalf("method hold lost to shared pacing: %v", err)
		}
	}
	analytics := NewDynamicThrottler(client, "test:", "shared:{query.cabinet}", 0.5, 1, 0)
	if err := analytics.SetQuotas(client, []RequestQuota{{Name: "day", Key: "analytics:{query.cabinet}", Requests: 128, Window: 24 * time.Hour}}); err != nil {
		t.Fatal(err)
	}
	if err := analytics.Wait(ctx); err != nil {
		t.Fatalf("quota-denied Stocks attempts consumed common slot needed by Analytics: %v", err)
	}
}

func TestCommonRejectionDoesNotChargeMethodQuota(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr(), ContextTimeoutEnabled: true, MaxRetries: -1})
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Error(err)
		}
	})
	ctx := WithRequest(context.Background(), httptest.NewRequest("POST", "/x?cabinet=dd", nil))
	common := NewDynamicThrottler(client, "test:", "shared:{query.cabinet}", 0.5, 1, 0)
	if err := common.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	quota := NewDynamicThrottler(client, "test:", "shared:{query.cabinet}", 0.5, 1, 0)
	if err := quota.SetQuotas(client, []RequestQuota{{Name: "day", Key: "analytics:{query.cabinet}", Requests: 1, Window: 24 * time.Hour}}); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		var denied *RetryAfterError
		if err := quota.Wait(ctx); !errors.As(err, &denied) || denied.Key == "request-quota" {
			t.Fatalf("expected common throttle denial: %v", err)
		}
	}
	if len(mr.Keys()) != 1 {
		t.Fatal("non-admitted request created quota ledger", mr.Keys())
	}
	// A later admissible request still has its method allowance.
	mr.Del("test:shared:dd")
	if err := quota.Wait(ctx); err != nil {
		t.Fatal("common denials reserved method quota", err)
	}
}

func TestClosedQuotaKeepsRetryClockAndNeverConsumesCommonSlot(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr(), ContextTimeoutEnabled: true, MaxRetries: -1})
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Error(err)
		}
	})
	ctx := WithRequest(context.Background(), httptest.NewRequest("POST", "/x?cabinet=dd", nil))
	d := NewDynamicThrottler(client, "test:", "shared:{query.cabinet}", 0.5, 1, 0)
	if err := d.SetQuotas(client, []RequestQuota{{Name: "day", Key: "closed:{query.cabinet}", Requests: 0, Window: 24 * time.Hour}}); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		var denied *RetryAfterError
		if err := d.Wait(ctx); !errors.As(err, &denied) || denied.Wait != 24*time.Hour || denied.Key != "request-quota" {
			t.Fatalf("closed method lost long retry clock: %v", err)
		}
	}
	if len(mr.Keys()) != 0 {
		t.Fatal("closed method consumed common capacity", mr.Keys())
	}
}

func TestQuotaEligibilityCheckGrantsNothingAndCommitRechecks(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr(), ContextTimeoutEnabled: true, MaxRetries: -1})
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Error(err)
		}
	})
	ctx := WithRequest(context.Background(), httptest.NewRequest("POST", "/x?cabinet=dd", nil))
	d := NewDynamicThrottler(client, "test:", "shared:{query.cabinet}", 0.5, 1, 0)
	if err := d.SetQuotas(client, []RequestQuota{{Name: "day", Key: "method:{query.cabinet}", Requests: 1, Window: 24 * time.Hour}}); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := d.checkQuotas(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if len(mr.Keys()) != 0 {
		t.Fatal("eligibility check created quota state")
	}
	// Another replica uses the allowance after our precheck.
	if err := d.admitQuotas(ctx); err != nil {
		t.Fatal(err)
	}
	var denied *RetryAfterError
	if err := d.admitQuotas(ctx); !errors.As(err, &denied) || denied.Key != "request-quota" {
		t.Fatalf("stale eligibility check granted another admission: %v", err)
	}
}

func TestQuotaParkingRechecksAllowanceBeforeAdmission(t *testing.T) {
	for _, mode := range []string{"exhausted", "cancelled", "redis_lost", "available"} {
		t.Run(mode, func(t *testing.T) {
			mr := miniredis.RunT(t)
			client := redis.NewClient(&redis.Options{Addr: mr.Addr(), ContextTimeoutEnabled: true, MaxRetries: -1})
			t.Cleanup(func() {
				if err := client.Close(); err != nil {
					t.Error(err)
				}
			})
			parked := make(chan struct{}, 1)
			client.AddHook(&quotaParkingHook{seen: parked})
			d := NewDynamicThrottler(client, "park:", "shared:{query.cabinet}", 100, 1, time.Second)
			if err := d.SetQuotas(client, []RequestQuota{{Name: "day", Key: "method:{query.cabinet}", Requests: 1, Window: 24 * time.Hour}}); err != nil {
				t.Fatal(err)
			}
			// An existing reader occupies the common slot. The next request must park,
			// without spending any of its rolling allowance in the preliminary check.
			mustSet := mr.Set("park:shared:dd", fmt.Sprint(time.Now().Add(400*time.Millisecond).UnixMilli()))
			if mustSet != nil {
				t.Fatal(mustSet)
			}
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx := WithRequest(parent, httptest.NewRequest("GET", "/read?cabinet=dd", nil))
			done := make(chan error, 1)
			go func() { done <- d.Wait(ctx) }()
			select {
			case <-parked:
			case <-time.After(2 * time.Second):
				t.Fatal("request never tried the shared slot")
			}
			if len(mr.Keys()) != 1 {
				t.Fatal("precheck charged quota", mr.Keys())
			}
			switch mode {
			case "exhausted":
				// Another replica consumes the method allowance after our precheck.
				if err := d.admitQuotas(ctx); err != nil {
					t.Fatal(err)
				}
			case "cancelled":
				cancel()
			case "redis_lost":
				mr.Close()
			}
			var err error
			select {
			case err = <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("unbounded parking")
			}
			var denied *RetryAfterError
			switch mode {
			case "exhausted":
				if !errors.As(err, &denied) || denied.Key != "request-quota" {
					t.Fatalf("stale precheck admitted request: %v", err)
				}
			case "cancelled":
				if !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			case "redis_lost":
				if !errors.Is(err, ErrBackendUnavailable) {
					t.Fatal(err)
				}
			case "available":
				if err != nil {
					t.Fatal(err)
				}
				if e := d.admitQuotas(ctx); !errors.As(e, &denied) {
					t.Fatalf("admission not charged: %v", e)
				}
			}
			if mode == "cancelled" && len(mr.Keys()) != 1 {
				t.Fatal("cancelled wait charged quota")
			}
		})
	}
}

type quotaParkingHook struct{ seen chan struct{} }

func (h *quotaParkingHook) DialHook(next redis.DialHook) redis.DialHook { return next }
func (h *quotaParkingHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}
func (h *quotaParkingHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		err := next(ctx, cmd)
		if len(cmd.Args()) > 1 && err == nil && ((cmd.Name() == "evalsha" && cmd.Args()[1] == redis.NewScript(gcraScript).Hash()) || (cmd.Name() == "eval" && cmd.Args()[1] == gcraScript)) {
			select {
			case h.seen <- struct{}{}:
			default:
			}
		}
		return err
	}
}
