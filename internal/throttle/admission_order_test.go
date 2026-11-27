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
