package coordinator

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ledatu/csar-core/s3store"
	credentialv1 "github.com/ledatu/csar-proto/csar/credential/v1"
	"github.com/ledatu/csar/internal/statestore"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type lifetimeStore struct {
	mu       sync.Mutex
	entries  map[string]TokenEntry
	reads    atomic.Int32
	version  int
	readHook func(context.Context, string, TokenEntry) (TokenEntry, error)
	writeErr error
}

func (s *lifetimeStore) FetchOne(ctx context.Context, ref string) (TokenEntry, error) {
	s.reads.Add(1)
	s.mu.Lock()
	entry, ok := s.entries[ref]
	hook := s.readHook
	s.mu.Unlock()
	if !ok {
		return TokenEntry{}, ErrTokenNotFound
	}
	if hook != nil {
		return hook(ctx, ref, entry)
	}
	return entry, nil
}
func (s *lifetimeStore) LoadAll(context.Context) (map[string]TokenEntry, error) {
	panic("lifetime path must not list tokens")
}
func (s *lifetimeStore) Close() error { return nil }
func (s *lifetimeStore) UpsertToken(_ context.Context, ref string, entry TokenEntry, _ TokenMetadata) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.writeErr != nil {
		return "", s.writeErr
	}
	s.version++
	entry.Version = fmt.Sprint(s.version)
	if s.entries == nil {
		s.entries = make(map[string]TokenEntry)
	}
	s.entries[ref] = entry
	return entry.Version, nil
}
func (s *lifetimeStore) DeleteToken(_ context.Context, ref string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, ref)
	return nil
}

func lifetimeEntry(value string, expiry *time.Time) TokenEntry {
	return TokenEntry{EncryptedToken: []byte(value), CredentialID: s3store.CredentialFingerprint([]byte(value)), Passthrough: true, ExpiresAt: expiry}
}

type lifetimeEnv struct {
	states  *statestore.MemoryStore
	raw     *lifetimeStore
	store   *CoherentTokenStore
	auth    [2]*AuthServiceImpl
	clock   atomic.Int64
	reports *CredentialRejections
}

func newLifetimeEnv(t *testing.T) *lifetimeEnv {
	t.Helper()
	e := &lifetimeEnv{states: statestore.NewMemoryStore(), raw: &lifetimeStore{}}
	e.clock.Store(time.Now().UnixNano())
	e.store = NewCoherentTokenStore(e.raw, e.states)
	for i := range e.auth {
		e.auth[i] = NewAuthService(quietLogger())
		e.auth[i].SetClock(func() time.Time { return time.Unix(0, e.clock.Load()) })
		e.auth[i].SetTokenStates(e.states)
		e.auth[i].SetBackend(e.store)
	}
	e.reports = NewCredentialRejections(e.store, e.auth[0], New(e.states, quietLogger()))
	return e
}
func (e *lifetimeEnv) put(t *testing.T, ref, value string, expiry *time.Time) string {
	t.Helper()
	version, err := e.store.UpsertToken(context.Background(), ref, lifetimeEntry(value, expiry), TokenMetadata{})
	if err != nil {
		t.Fatal(err)
	}
	return version
}
func (e *lifetimeEnv) get(t *testing.T, node int, ref, want string) {
	t.Helper()
	resp, err := e.auth[node].GetEncryptedToken(context.Background(), tokenReq(ref))
	if err != nil || string(resp.GetEncryptedToken()) != want {
		t.Fatalf("node %d: got %v, %v; want %s", node, resp, err, want)
	}
}
func (e *lifetimeEnv) report(t *testing.T, ref, version, value string) {
	t.Helper()
	_, err := e.reports.ReportRejection(context.Background(), &credentialv1.ReportRejectionRequest{TokenRef: ref, Version: version, CredentialFingerprint: s3store.CredentialFingerprint([]byte(value))})
	if err != nil {
		t.Fatal(err)
	}
}

func TestLifetimeWarmTokensNeverReadEveryMinute(t *testing.T) {
	for _, known := range []bool{false, true} {
		t.Run(fmt.Sprint(known), func(t *testing.T) {
			e := newLifetimeEnv(t)
			var expiry *time.Time
			if known {
				deadline := time.Unix(0, e.clock.Load()).Add(72 * time.Hour)
				expiry = &deadline
			}
			e.put(t, "seller/a", "working", expiry)
			e.put(t, "seller/b", "idle", expiry)
			e.get(t, 0, "seller/a", "working")
			for range 180 {
				e.clock.Add(int64(time.Minute))
				e.get(t, 0, "seller/a", "working")
			}
			if n := e.raw.reads.Load(); n != 1 {
				t.Fatalf("%d S3 reads for unchanged working token, want exactly one", n)
			}
			if _, ok := e.auth[0].Entry("seller/b"); ok {
				t.Fatal("idle ref fetched")
			}
		})
	}
}

func TestLifetimeExpiryBoundsUnchangedReads(t *testing.T) {
	e := newLifetimeEnv(t)
	deadline := time.Unix(0, e.clock.Load()).Add(4 * time.Minute)
	e.put(t, "seller/a", "working", &deadline)
	e.get(t, 0, "seller/a", "working")
	e.clock.Add(int64(3*time.Minute + time.Second))
	e.get(t, 0, "seller/a", "working")
	if n := e.raw.reads.Load(); n != 2 {
		t.Fatalf("near-deadline reads=%d", n)
	}
	e.clock.Add(int64(30 * time.Second))
	for range 20 {
		resp, err := e.auth[0].GetEncryptedToken(context.Background(), tokenReq("seller/a"))
		if resp != nil || status.Code(err) != codes.Unauthenticated {
			t.Fatalf("expired credential served: %v %v", resp, err)
		}
	}
	if n := e.raw.reads.Load(); n != 3 {
		t.Fatalf("expired token retried without backoff: %d", n)
	}
	e.put(t, "seller/a", "replacement", nil)
	e.get(t, 0, "seller/a", "replacement")
}

func TestRejectionQuarantinesPeersAndIdenticalRewrite(t *testing.T) {
	e := newLifetimeEnv(t)
	version := e.put(t, "seller/a", "revoked", nil)
	for node := range e.auth {
		e.get(t, node, "seller/a", "revoked")
	}
	e.report(t, "seller/a", version, "revoked")
	before := e.raw.reads.Load()
	var wg sync.WaitGroup
	for i := range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := e.auth[i%2].GetEncryptedToken(context.Background(), tokenReq("seller/a"))
			if resp != nil || status.Code(err) != codes.Unauthenticated {
				t.Errorf("rejected credential served: %v %v", resp, err)
			}
		}()
	}
	wg.Wait()
	if reads := e.raw.reads.Load() - before; reads != 2 {
		t.Fatalf("concurrent peer rejection checks = %d, want one per coordinator", reads)
	}
	e.put(t, "seller/a", "revoked", nil)
	for node := range e.auth {
		resp, err := e.auth[node].GetEncryptedToken(context.Background(), tokenReq("seller/a"))
		if resp != nil || status.Code(err) != codes.Unauthenticated {
			t.Fatal("metadata-only rewrite revived rejected value")
		}
	}
	e.put(t, "seller/a", "new", nil)
	for node := range e.auth {
		e.get(t, node, "seller/a", "new")
	}
}

func TestLate401CannotInvalidateNewRotation(t *testing.T) {
	e := newLifetimeEnv(t)
	old := e.put(t, "seller/a", "old", nil)
	e.get(t, 0, "seller/a", "old")
	e.put(t, "seller/a", "new", nil)
	e.get(t, 1, "seller/a", "new")
	before, _ := e.states.GetTokenState(context.Background(), "seller/a")
	reads := e.raw.reads.Load()
	e.report(t, "seller/a", old, "old")
	after, _ := e.states.GetTokenState(context.Background(), "seller/a")
	if before.Revision != after.Revision || e.raw.reads.Load() != reads {
		t.Fatal("late old 401 changed new token state")
	}
	for node := range e.auth {
		e.get(t, node, "seller/a", "new")
	}
}

func TestCoherentReadCannotOverwriteRotationOrDeletion(t *testing.T) {
	for _, remove := range []bool{false, true} {
		t.Run(fmt.Sprint(remove), func(t *testing.T) {
			e := newLifetimeEnv(t)
			e.put(t, "seller/a", "old", nil)
			started, release := make(chan struct{}), make(chan struct{})
			e.raw.readHook = func(ctx context.Context, _ string, entry TokenEntry) (TokenEntry, error) {
				close(started)
				select {
				case <-ctx.Done():
					return TokenEntry{}, ctx.Err()
				case <-release:
					return entry, nil
				}
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				resp, err := e.auth[0].GetEncryptedToken(context.Background(), tokenReq("seller/a"))
				if err == nil || resp != nil {
					t.Errorf("older in-flight read authorized after mutation: %v", resp)
				}
			}()
			<-started
			if remove {
				if err := e.store.DeleteToken(context.Background(), "seller/a"); err != nil {
					t.Fatal(err)
				}
			} else {
				e.put(t, "seller/a", "new", nil)
			}
			close(release)
			<-done
			e.raw.mu.Lock()
			e.raw.readHook = nil
			e.raw.mu.Unlock()
			if remove {
				resp, err := e.auth[0].GetEncryptedToken(context.Background(), tokenReq("seller/a"))
				if resp != nil || status.Code(err) != codes.NotFound {
					t.Fatal("deletion lost")
				}
			} else {
				e.get(t, 0, "seller/a", "new")
			}
		})
	}
}

func TestUnknownWriteOutcomeFencesAllPeers(t *testing.T) {
	e := newLifetimeEnv(t)
	e.put(t, "seller/a", "old", nil)
	for node := range e.auth {
		e.get(t, node, "seller/a", "old")
	}
	e.raw.writeErr = errors.New("lost write receipt")
	if _, err := e.store.UpsertToken(context.Background(), "seller/a", lifetimeEntry("new", nil), TokenMetadata{}); err == nil {
		t.Fatal("reported unknown mutation as success")
	}
	before := e.raw.reads.Load()
	for node := range e.auth {
		resp, err := e.auth[node].GetEncryptedToken(context.Background(), tokenReq("seller/a"))
		if resp != nil || status.Code(err) != codes.Unavailable {
			t.Fatalf("unfenced cache: %v %v", resp, err)
		}
	}
	if e.raw.reads.Load() != before {
		t.Fatal("pending write performed unneeded value read")
	}
}

type rejectingCAS struct {
	statestore.TokenStates
	started chan struct{}
	release chan struct{}
}

func (s *rejectingCAS) CASTokenState(ctx context.Context, ref string, rev int64, state statestore.TokenState) (int64, error) {
	if state.RejectedID != "" && state.Pending == "" {
		close(s.started)
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-s.release:
		}
	}
	return s.TokenStates.CASTokenState(ctx, ref, rev, state)
}

func TestRejectionCASLosesToConcurrentRotation(t *testing.T) {
	e := newLifetimeEnv(t)
	old := e.put(t, "seller/a", "old", nil)
	fence := &rejectingCAS{TokenStates: e.states, started: make(chan struct{}), release: make(chan struct{})}
	reports := NewCredentialRejections(NewCoherentTokenStore(e.raw, fence), e.auth[0], New(e.states, quietLogger()))
	done := make(chan error, 1)
	go func() {
		_, err := reports.ReportRejection(context.Background(), &credentialv1.ReportRejectionRequest{TokenRef: "seller/a", Version: old, CredentialFingerprint: s3store.CredentialFingerprint([]byte("old"))})
		done <- err
	}()
	<-fence.started
	e.put(t, "seller/a", "new", nil)
	close(fence.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	for node := range e.auth {
		e.get(t, node, "seller/a", "new")
	}
}

type failPublication struct{ statestore.TokenStates }

func (s *failPublication) CASTokenState(ctx context.Context, ref string, rev int64, state statestore.TokenState) (int64, error) {
	if state.Pending == "" {
		return 0, errors.New("metadata publication unavailable")
	}
	return s.TokenStates.CASTokenState(ctx, ref, rev, state)
}
func TestPublicationFailureCannotReportMutationSuccess(t *testing.T) {
	e := newLifetimeEnv(t)
	e.put(t, "seller/a", "old", nil)
	e.get(t, 1, "seller/a", "old")
	writer := NewCoherentTokenStore(e.raw, &failPublication{TokenStates: e.states})
	if _, err := writer.UpsertToken(context.Background(), "seller/a", lifetimeEntry("new", nil), TokenMetadata{}); !errors.Is(err, ErrTokenMutationUnknown) {
		t.Fatalf("publication error lost unknown outcome: %v", err)
	}
	state, err := e.states.GetTokenState(context.Background(), "seller/a")
	if err != nil || state.Pending == "" {
		t.Fatal("publication failure cleared durable fence")
	}
	resp, err := e.auth[1].GetEncryptedToken(context.Background(), tokenReq("seller/a"))
	if resp != nil || status.Code(err) != codes.Unavailable {
		t.Fatalf("peer served stale/unknown write: %v %v", resp, err)
	}
}

func TestLate401ForIdenticalValueRewriteStillQuarantinesValue(t *testing.T) {
	e := newLifetimeEnv(t)
	old := e.put(t, "seller/a", "same-value", nil)
	e.put(t, "seller/a", "same-value", nil)
	e.report(t, "seller/a", old, "same-value")
	for node := range e.auth {
		resp, err := e.auth[node].GetEncryptedToken(context.Background(), tokenReq("seller/a"))
		if resp != nil || status.Code(err) != codes.Unauthenticated {
			t.Fatal("metadata rewrite bypassed value rejection")
		}
	}
}

type unavailableTokenStates struct {
	statestore.TokenStates
	fail     atomic.Bool
	failures atomic.Int32
}

func (s *unavailableTokenStates) GetTokenState(ctx context.Context, ref string) (statestore.TokenState, error) {
	if s.fail.Load() {
		s.failures.Add(1)
		return statestore.TokenState{}, errors.New("metadata temporarily unavailable")
	}
	return s.TokenStates.GetTokenState(ctx, ref)
}
func TestMetadataOutageFailsClosedAndWaitsBeforeRetry(t *testing.T) {
	e := newLifetimeEnv(t)
	e.put(t, "seller/a", "working", nil)
	states := &unavailableTokenStates{TokenStates: e.states}
	e.auth[0].SetTokenStates(states)
	e.get(t, 0, "seller/a", "working")
	states.fail.Store(true)
	var wg sync.WaitGroup
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := e.auth[0].GetEncryptedToken(context.Background(), tokenReq("seller/a"))
			if resp != nil || status.Code(err) != codes.Unavailable {
				t.Errorf("metadata outage served unvalidated value: %v %v", resp, err)
			}
		}()
	}
	wg.Wait()
	if states.failures.Load() != 1 || e.raw.reads.Load() != 1 {
		t.Fatal("metadata outage caused validation or S3 request storm")
	}
	e.clock.Add(int64(storedRefreshRetry))
	states.fail.Store(false)
	e.get(t, 0, "seller/a", "working")
	if e.raw.reads.Load() != 1 {
		t.Fatal("metadata recovery reread unchanged token value")
	}
}
