package statestore

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testTokenStates(t *testing.T, store TokenStates) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	const ref = "accounts/wb/seller/promotion/read"
	state, err := store.GetTokenState(ctx, ref)
	if err != nil || state.Revision != 0 {
		t.Fatalf("initial state %v %v", state, err)
	}
	var winners atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rev, casErr := store.CASTokenState(ctx, ref, 0, TokenState{Pending: "mutation"})
			if casErr != nil {
				t.Error(casErr)
			}
			if rev != 0 {
				winners.Add(1)
			}
		}()
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("concurrent mutation winners=%d", winners.Load())
	}
	state, err = store.GetTokenState(ctx, ref)
	if err != nil || state.Pending != "mutation" {
		t.Fatalf("pending fence %v %v", state, err)
	}
	previous := state.Revision
	state.Pending = ""
	state.Version = "opaque-version"
	if rev, casErr := store.CASTokenState(ctx, ref, previous, state); casErr != nil || rev <= previous {
		t.Fatalf("publish mutation %d %v", rev, casErr)
	}
	if rev, casErr := store.CASTokenState(ctx, ref, previous, TokenState{RejectedID: "old"}); casErr != nil || rev != 0 {
		t.Fatalf("stale compare-and-swap succeeded %d %v", rev, casErr)
	}
	// A dropped/restarted watch does not lose the durable exact-ref revision.
	read, err := store.GetTokenState(ctx, ref)
	if err != nil || read.Version != "opaque-version" || read.RejectedID != "" {
		t.Fatalf("missed-event reconciliation: %v %v", read, err)
	}
}
func TestMemoryTokenStatesCAS(t *testing.T) { testTokenStates(t, NewMemoryStore()) }
func TestEtcdTokenStatesCAS(t *testing.T)   { testTokenStates(t, newTestEtcdStore(t)) }

func testTokenStateWatch(t *testing.T, store TokenStates) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events, err := store.WatchTokenStates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.CASTokenState(ctx, "seller/a", 0, TokenState{Version: "v1"}); err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-events:
		if ev.Ref != "seller/a" {
			t.Fatal("wrong invalidation ref")
		}
	case <-time.After(time.Second):
		t.Fatal("missing event")
	}
}

func TestMemoryTokenStateWatchIsExactRef(t *testing.T) { testTokenStateWatch(t, NewMemoryStore()) }
func TestEtcdTokenStateWatchIsExactRef(t *testing.T)   { testTokenStateWatch(t, newTestEtcdStore(t)) }
