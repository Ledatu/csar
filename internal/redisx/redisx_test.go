package redisx

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

type recordedError struct {
	subsystem string
	command   string
}

type errorLog struct {
	mu     sync.Mutex
	errors []recordedError
}

func (l *errorLog) record(subsystem, command string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.errors = append(l.errors, recordedError{subsystem: subsystem, command: command})
}

func (l *errorLog) snapshot() []recordedError {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]recordedError(nil), l.errors...)
}

func newHookedClient(t *testing.T, mr *miniredis.Miniredis, password string) (*redis.Client, *errorLog) {
	t.Helper()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr(), Password: password})
	t.Cleanup(func() { _ = client.Close() })
	log := &errorLog{}
	client.AddHook(NewErrorHook(log.record))
	return client, log
}

func TestErrorHook_RecordsAuthFailureWithSubsystem(t *testing.T) {
	mr := miniredis.RunT(t)
	mr.RequireAuth("secret")
	client, log := newHookedClient(t, mr, "")

	ctx := WithSubsystem(context.Background(), SubsystemThrottle)
	if err := client.Get(ctx, "k").Err(); err == nil {
		t.Fatal("expected NOAUTH error")
	}

	got := log.snapshot()
	want := []recordedError{{subsystem: SubsystemThrottle, command: "get"}}
	if len(got) != 1 || got[0] != want[0] {
		t.Fatalf("recorded = %+v, want %+v", got, want)
	}
}

func TestErrorHook_UntaggedContextIsUnknown(t *testing.T) {
	mr := miniredis.RunT(t)
	mr.RequireAuth("secret")
	client, log := newHookedClient(t, mr, "")

	_ = client.Ping(context.Background()).Err()

	got := log.snapshot()
	if len(got) != 1 || got[0].subsystem != SubsystemUnknown || got[0].command != "ping" {
		t.Fatalf("recorded = %+v, want one unknown/ping", got)
	}
}

func TestErrorHook_IgnoresNormalOutcomes(t *testing.T) {
	mr := miniredis.RunT(t)
	client, log := newHookedClient(t, mr, "")
	ctx := WithSubsystem(context.Background(), SubsystemCache)

	if err := client.Get(ctx, "missing").Err(); !errors.Is(err, redis.Nil) {
		t.Fatalf("Get missing: err = %v, want redis.Nil", err)
	}

	pipe := client.Pipeline()
	pipe.Get(ctx, "missing-a")
	pipe.Get(ctx, "missing-b")
	if _, err := pipe.Exec(ctx); !errors.Is(err, redis.Nil) {
		t.Fatalf("pipeline of misses: err = %v, want redis.Nil", err)
	}

	script := redis.NewScript(`return 1`)
	if err := script.Run(ctx, client, nil).Err(); err != nil {
		t.Fatalf("first script run (NOSCRIPT fallback): %v", err)
	}

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := client.Get(cancelled, "k").Err(); !errors.Is(err, context.Canceled) {
		t.Fatalf("Get with cancelled ctx: err = %v, want context.Canceled", err)
	}

	if got := log.snapshot(); len(got) != 0 {
		t.Fatalf("recorded = %+v, want none", got)
	}
}

func TestErrorHook_RecordsFailedPipelineOnce(t *testing.T) {
	mr := miniredis.RunT(t)
	mr.RequireAuth("secret")
	client, log := newHookedClient(t, mr, "")
	ctx := WithSubsystem(context.Background(), SubsystemCache)

	pipe := client.Pipeline()
	pipe.Get(ctx, "a")
	pipe.Get(ctx, "b")
	if _, err := pipe.Exec(ctx); err == nil {
		t.Fatal("expected pipeline error")
	}

	got := log.snapshot()
	want := recordedError{subsystem: SubsystemCache, command: "pipeline"}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("recorded = %+v, want [%+v]", got, want)
	}
}

func TestErrorHook_RecordsUnreachableServer(t *testing.T) {
	mr := miniredis.RunT(t)
	client, log := newHookedClient(t, mr, "")
	mr.Close()

	ctx, cancel := context.WithTimeout(WithSubsystem(context.Background(), SubsystemStartup), 100*time.Millisecond)
	defer cancel()
	if err := client.Ping(ctx).Err(); err == nil {
		t.Fatal("expected dial error")
	}

	got := log.snapshot()
	if len(got) != 1 || got[0].subsystem != SubsystemStartup {
		t.Fatalf("recorded = %+v, want one startup error", got)
	}
}
