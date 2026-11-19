package coordinator

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type demandStore struct {
	TokenStore
	calls atomic.Int32
	fetch func(context.Context, string) (TokenEntry, error)
}

func (s *demandStore) FetchOne(ctx context.Context, ref string) (TokenEntry, error) {
	s.calls.Add(1)
	if s.fetch != nil {
		return s.fetch(ctx, ref)
	}
	return s.TokenStore.FetchOne(ctx, ref)
}

func storedEntry(version string) TokenEntry {
	return TokenEntry{EncryptedToken: []byte("fixture-" + version), KMSKeyID: "fixture-key", Version: version}
}

func demandService(store TokenStore) (*AuthServiceImpl, *atomic.Int64) {
	clock := &atomic.Int64{}
	clock.Store(time.Now().UnixNano())
	svc := NewAuthService(testLogger())
	svc.SetClock(func() time.Time { return time.Unix(0, clock.Load()) })
	svc.SetBackend(store)
	return svc, clock
}

func TestStoredTokenRefreshOnlyOnDemandAndOnlyRequestedRef(t *testing.T) {
	backend := &mockTokenStore{tokens: map[string]TokenEntry{"seller/a": storedEntry("old"), "seller/b": storedEntry("other")}}
	store := &demandStore{TokenStore: backend}
	svc, clock := demandService(store)
	svc.LoadTokens(backend.tokens)
	if _, err := svc.GetEncryptedToken(context.Background(), tokenReq("seller/a")); err != nil || store.calls.Load() != 0 {
		t.Fatalf("fresh cache unexpectedly fetched: %v", err)
	}
	backend.tokens["seller/a"] = storedEntry("new")
	clock.Add(int64(61 * time.Minute))
	if store.calls.Load() != 0 {
		t.Fatal("elapsed time alone caused a backend read")
	}
	resp, err := svc.GetEncryptedToken(context.Background(), tokenReq("seller/a"))
	if err != nil || resp.Version != "new" || store.calls.Load() != 1 {
		t.Fatalf("first demand did not validate changed token: %+v, %v", resp, err)
	}
	if svc.tokens["seller/b"].Version != "other" {
		t.Fatal("another seller was refreshed")
	}
	_, err = svc.GetEncryptedToken(context.Background(), tokenReq("seller/a"))
	if err != nil || store.calls.Load() != 1 {
		t.Fatal("fresh requests repeated the backend read")
	}
}

func TestStoredTokenRefreshCoalescesConcurrentRequests(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	store := &demandStore{fetch: func(context.Context, string) (TokenEntry, error) {
		close(started)
		<-release
		return storedEntry("new"), nil
	}}
	svc, clock := demandService(store)
	svc.LoadToken("seller/a", storedEntry("old"))
	clock.Add(int64(time.Minute))
	var group sync.WaitGroup
	for range 32 {
		group.Add(1)
		go func() {
			defer group.Done()
			resp, err := svc.GetEncryptedToken(context.Background(), tokenReq("seller/a"))
			if err != nil || resp.Version != "new" {
				t.Errorf("wrong concurrent refresh result: %+v, %v", resp, err)
			}
		}()
	}
	<-started
	close(release)
	group.Wait()
	if store.calls.Load() != 1 {
		t.Fatalf("backend calls = %d, want 1", store.calls.Load())
	}
}

func TestStoredTokenRefreshFailureFailsClosedAndBoundsRetry(t *testing.T) {
	for _, mode := range []string{"outage", "removed", "invalid"} {
		t.Run(mode, func(t *testing.T) {
			store := &demandStore{fetch: func(context.Context, string) (TokenEntry, error) {
				switch mode {
				case "outage":
					return TokenEntry{}, errors.New("fixture backend outage")
				case "removed":
					return TokenEntry{}, ErrTokenNotFound
				default:
					return TokenEntry{}, nil
				}
			}}
			svc, clock := demandService(store)
			svc.LoadToken("seller/a", storedEntry("old"))
			clock.Add(int64(time.Minute))
			for range 2 {
				resp, err := svc.GetEncryptedToken(context.Background(), tokenReq("seller/a"))
				want := codes.NotFound
				if mode == "outage" {
					want = codes.Unavailable
				}
				if resp != nil || status.Code(err) != want {
					t.Fatalf("stale token served or wrong failure: %+v, %v", resp, err)
				}
			}
			if store.calls.Load() != 1 {
				t.Fatal("backend failure was retried without cooldown")
			}
			store.fetch = func(context.Context, string) (TokenEntry, error) { return storedEntry("recovered"), nil }
			clock.Add(int64(storedRefreshRetry))
			resp, err := svc.GetEncryptedToken(context.Background(), tokenReq("seller/a"))
			if err != nil || resp.Version != "recovered" || store.calls.Load() != 2 {
				t.Fatalf("demand did not recover after cooldown: %+v, %v", resp, err)
			}
		})
	}
}

func TestStoredTokenRefreshNeverOverwritesConcurrentMutation(t *testing.T) {
	for _, remove := range []bool{false, true} {
		t.Run(map[bool]string{false: "rotate", true: "delete"}[remove], func(t *testing.T) {
			started, release := make(chan struct{}), make(chan struct{})
			store := &demandStore{fetch: func(context.Context, string) (TokenEntry, error) {
				close(started)
				<-release
				return storedEntry("old"), nil
			}}
			svc, clock := demandService(store)
			svc.LoadToken("seller/a", storedEntry("old"))
			clock.Add(int64(time.Minute))
			done := make(chan struct{})
			go func() {
				defer close(done)
				resp, err := svc.GetEncryptedToken(context.Background(), tokenReq("seller/a"))
				if remove {
					if resp != nil || status.Code(err) != codes.NotFound {
						t.Errorf("deleted token resurrected: %+v, %v", resp, err)
					}
				} else if err != nil || resp.Version != "local-new" {
					t.Errorf("local rotation overwritten: %+v, %v", resp, err)
				}
			}()
			<-started
			if remove {
				svc.RemoveToken("seller/a")
			} else {
				svc.LoadToken("seller/a", storedEntry("local-new"))
			}
			close(release)
			<-done
		})
	}
}

func TestStoredTokenRefreshDoesNotChangeMintedLifetime(t *testing.T) {
	store := &demandStore{}
	svc, clock := demandService(store)
	entry := storedEntry("minted")
	now := svc.clock()
	entry.Mint = &MintInfo{RefreshAfter: now.Add(time.Hour), HardExpiry: now.Add(2 * time.Hour)}
	svc.LoadToken("seller/a", entry)
	clock.Add(int64(2 * time.Minute))
	resp, err := svc.GetEncryptedToken(context.Background(), tokenReq("seller/a"))
	if err != nil || resp.Version != "minted" || store.calls.Load() != 0 {
		t.Fatalf("stored-token interval changed minted-token behavior: %+v, %v", resp, err)
	}
}
