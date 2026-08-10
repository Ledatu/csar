package coordinator

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ledatu/csar-core/tokenmint"
	csarv1 "github.com/ledatu/csar/proto/csar/v1"
	"golang.org/x/sync/singleflight"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// defaultFetchTimeout is the maximum time allowed for a read-through
// backend fetch. Prevents singleflight lanes from being occupied
// indefinitely under degraded DB/network conditions (audit §4).
const defaultFetchTimeout = 5 * time.Second

// DefaultFetchTimeout exposes the default read-through deadline so callers can
// tell whether their own work (e.g. a token mint) would outlast it.
func DefaultFetchTimeout() time.Duration { return defaultFetchTimeout }

// TokenEntry holds an encrypted token and its associated KMS key.
type TokenEntry struct {
	EncryptedToken []byte
	KMSKeyID       string
	// Passthrough indicates the token is already plaintext (e.g. S3 SSE
	// handles encryption at rest). Routers skip KMS decryption when true.
	Passthrough bool
	// Version is an opaque string bumped on each token rotation.
	// Routers use it for cache invalidation.
	Version string

	// Descriptor is set by the raw store when the object describes a minted
	// credential rather than storing one. It is consumed by MintingTokenStore
	// and must never reach the cache: isValid rejects entries with no token
	// bytes, so a descriptor can never be served to a router by accident.
	Descriptor *tokenmint.Descriptor

	// Mint is set only on entries whose value was produced by a grant. It is
	// nil for stored tokens, which therefore never expire and behave exactly
	// as they did before minting existed.
	Mint *MintInfo
}

// MintInfo carries the two lifetime boundaries of a minted token.
//
// Between RefreshAfter and HardExpiry the entry is still served while a
// replacement is fetched in the background. That window is what keeps an
// upstream token-endpoint outage invisible to traffic for most of a token's
// life.
type MintInfo struct {
	RefreshAfter time.Time
	HardExpiry   time.Time
}

// Minted reports whether the entry's value came from a grant.
func (e TokenEntry) Minted() bool { return e.Mint != nil }

// NeedsRefresh reports whether a replacement should be fetched. Always false
// for stored tokens.
func (e TokenEntry) NeedsRefresh(now time.Time) bool {
	return e.Mint != nil && !e.Mint.RefreshAfter.IsZero() && !now.Before(e.Mint.RefreshAfter)
}

// Usable reports whether the entry may still be served. Always true for stored
// tokens, which have no expiry.
func (e TokenEntry) Usable(now time.Time) bool {
	return e.Mint == nil || e.Mint.HardExpiry.IsZero() || now.Before(e.Mint.HardExpiry)
}

// LogValue implements slog.LogValuer to prevent accidental logging of
// the encrypted token blob. Only the KMS key ID and version are shown.
func (e TokenEntry) LogValue() slog.Value {
	attrs := []slog.Attr{
		slog.String("kms_key_id", e.KMSKeyID),
		slog.String("version", e.Version),
		slog.String("encrypted_token", "[REDACTED]"),
	}
	if e.Mint != nil {
		attrs = append(attrs,
			slog.Bool("minted", true),
			slog.Time("refresh_after", e.Mint.RefreshAfter),
			slog.Time("hard_expiry", e.Mint.HardExpiry),
		)
	}
	if e.Descriptor != nil {
		attrs = append(attrs, slog.String("grant_profile", e.Descriptor.GrantProfile))
	}
	return slog.GroupValue(attrs...)
}

// AuthServiceImpl implements csarv1.AuthServiceServer.
// It serves encrypted tokens to routers via the GetEncryptedToken RPC.
// Tokens are loaded into the in-memory store at startup (from file, TokenStore, etc.).
//
// When a TokenStore is configured (via SetBackend), cache misses trigger a
// read-through query to the backing store. Successful fetches are cached
// in-memory so subsequent requests are served without hitting the backend.
// This is critical when the polling interval is long (e.g. 4h) and a new
// token_ref is added between polls.
type AuthServiceImpl struct {
	csarv1.UnimplementedAuthServiceServer

	mu           sync.RWMutex
	tokens       map[string]TokenEntry // token_ref -> entry
	logger       *slog.Logger
	backend      TokenStore // optional read-through backend (e.g. PostgresTokenStore)
	sf           singleflight.Group
	fetchTimeout time.Duration // max time for read-through backend queries (audit §4)

	// lastServed records when each minted ref was last handed to a router, so
	// the refresher can drop entries nobody is using. Kept off mu because it
	// is written on every request.
	lastServed sync.Map // token_ref -> *atomic.Int64 (unix nanos)

	// refreshing guards against piling up background refreshes for the same
	// ref while one is already in flight.
	refreshing sync.Map // token_ref -> struct{}

	// now is injectable so expiry behavior can be tested without sleeping.
	nowMu sync.RWMutex
	now   func() time.Time
}

// NewAuthService creates an AuthServiceImpl with an empty token store.
func NewAuthService(logger *slog.Logger) *AuthServiceImpl {
	return &AuthServiceImpl{
		tokens:       make(map[string]TokenEntry),
		logger:       logger,
		fetchTimeout: defaultFetchTimeout,
		now:          time.Now,
	}
}

// SetClock replaces the time source. Test-only.
func (s *AuthServiceImpl) SetClock(now func() time.Time) {
	s.nowMu.Lock()
	defer s.nowMu.Unlock()
	s.now = now
}

func (s *AuthServiceImpl) clock() time.Time {
	s.nowMu.RLock()
	defer s.nowMu.RUnlock()
	return s.now()
}

func (s *AuthServiceImpl) markServed(tokenRef string, at time.Time) {
	v, _ := s.lastServed.LoadOrStore(tokenRef, new(atomic.Int64))
	if ts, castOK := v.(*atomic.Int64); castOK {
		ts.Store(at.UnixNano())
	}
}

// LastServed reports when a ref was last handed to a router.
func (s *AuthServiceImpl) LastServed(tokenRef string) (time.Time, bool) {
	v, loaded := s.lastServed.Load(tokenRef)
	if !loaded {
		return time.Time{}, false
	}
	ts, castOK := v.(*atomic.Int64)
	if !castOK {
		return time.Time{}, false
	}
	return time.Unix(0, ts.Load()), true
}

// forgetServed drops the last-served record for a ref.
func (s *AuthServiceImpl) forgetServed(tokenRef string) {
	s.lastServed.Delete(tokenRef)
}

// MintedRefs returns the refs of every cached entry that was minted.
func (s *AuthServiceImpl) MintedRefs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	refs := make([]string, 0, len(s.tokens))
	for ref, entry := range s.tokens {
		if entry.Minted() {
			refs = append(refs, ref)
		}
	}
	return refs
}

// Entry returns a cached entry by ref.
func (s *AuthServiceImpl) Entry(tokenRef string) (TokenEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.tokens[tokenRef]
	return entry, ok
}

// Refresh re-fetches a ref through the backend and updates the cache. It is
// used both by the background path here and by the mint refresher.
func (s *AuthServiceImpl) Refresh(ctx context.Context, tokenRef string) error {
	s.mu.RLock()
	backend := s.backend
	s.mu.RUnlock()

	if backend == nil {
		return fmt.Errorf("no backend configured")
	}
	_, err := s.fetchThrough(ctx, backend, tokenRef)
	return err
}

// refreshInBackground replaces a still-usable but stale entry without making
// the current request wait for it.
func (s *AuthServiceImpl) refreshInBackground(tokenRef string) {
	if _, busy := s.refreshing.LoadOrStore(tokenRef, struct{}{}); busy {
		return
	}

	go func() {
		defer s.refreshing.Delete(tokenRef)

		// Detached from the triggering request: that caller already has a
		// usable token and must not be kept waiting or able to cancel this.
		ctx := context.Background()
		if err := s.Refresh(ctx, tokenRef); err != nil {
			s.logger.Warn("background token refresh failed; serving the existing token until it expires",
				"token_ref", tokenRef,
				"error", err,
			)
		}
	}()
}

// fetchThrough queries the backend for one ref and caches a valid result.
// Concurrent callers for the same ref collapse into a single backend query.
func (s *AuthServiceImpl) fetchThrough(ctx context.Context, backend TokenStore, tokenRef string) (TokenEntry, error) {
	res, err, _ := s.sf.Do(tokenRef, func() (interface{}, error) {
		// Use context.WithoutCancel to decouple the backend query from the
		// first caller's lifecycle. If that caller cancels or times out,
		// other goroutines waiting in the singleflight group are not affected.
		fetchCtx := context.WithoutCancel(ctx)

		// Apply a bounded timeout to prevent singleflight lanes from being
		// occupied indefinitely under degraded DB/network conditions (audit §4).
		if s.fetchTimeout > 0 {
			var cancel context.CancelFunc
			fetchCtx, cancel = context.WithTimeout(fetchCtx, s.fetchTimeout)
			defer cancel()
		}

		fetched, fetchErr := backend.FetchOne(fetchCtx, tokenRef)
		if fetchErr != nil {
			return nil, fetchErr
		}

		if !s.isValid(tokenRef, fetched) {
			return fetched, nil
		}

		// Cache inside the singleflight closure so only the leader goroutine
		// writes, eliminating redundant lock contention from shared waiters.
		s.mu.Lock()
		s.tokens[tokenRef] = fetched
		s.mu.Unlock()

		s.logger.Info("token fetched from backend and cached",
			"token_ref", tokenRef,
			"version", fetched.Version,
			"minted", fetched.Minted(),
		)

		return fetched, nil
	})
	if err != nil {
		return TokenEntry{}, err
	}

	entry, castOK := res.(TokenEntry)
	if !castOK {
		return TokenEntry{}, fmt.Errorf("unexpected cache result type %T", res)
	}
	return entry, nil
}

// statusForFetchError maps a backend failure onto a gRPC code.
//
// Routers collapse every one of these into a 502, so the distinction exists
// purely for coordinator-side observability and alerting — it is what makes
// "this seller's credentials were revoked" separable from "the token endpoint
// is having a bad afternoon" in metrics.
func statusForFetchError(tokenRef string, err error) error {
	switch {
	case errors.Is(err, tokenmint.ErrUnknownProfile), errors.Is(err, tokenmint.ErrUnknownKind):
		return status.Errorf(codes.FailedPrecondition,
			"token ref %q names an unusable mint configuration", tokenRef)

	case errors.Is(err, ErrDescriptorScopeViolation):
		return status.Errorf(codes.PermissionDenied,
			"token ref %q references credentials outside its own namespace", tokenRef)

	case errors.Is(err, tokenmint.ErrInvalidClient):
		return status.Errorf(codes.Unauthenticated,
			"stored credentials for token ref %q were rejected upstream", tokenRef)

	case errors.Is(err, tokenmint.ErrThrottled), errors.Is(err, tokenmint.ErrBackoff):
		return status.Errorf(codes.ResourceExhausted,
			"minting for token ref %q is rate limited or backing off", tokenRef)

	case errors.Is(err, tokenmint.ErrMalformedResponse), errors.Is(err, tokenmint.ErrHostNotAllowed):
		return status.Errorf(codes.Internal,
			"token endpoint response for ref %q could not be used", tokenRef)

	default:
		return status.Errorf(codes.Unavailable,
			"token store temporarily unavailable for ref %q", tokenRef)
	}
}

// SetFetchTimeout configures the maximum duration for read-through backend
// queries. Requests exceeding this timeout return codes.Unavailable.
// Set to 0 to disable (not recommended in production).
func (s *AuthServiceImpl) SetFetchTimeout(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fetchTimeout = d
}

// SetBackend configures an optional read-through backing store.
// When a token_ref is not found in the in-memory cache, the store is
// queried before returning NotFound. This is useful with long polling
// intervals — newly-added tokens are available immediately.
//
// Any TokenStore implementation (Postgres, YDB, Redis, …) works here.
func (s *AuthServiceImpl) SetBackend(store TokenStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.backend = store
}

// LoadToken adds or replaces a token entry in the store.
func (s *AuthServiceImpl) LoadToken(tokenRef string, entry TokenEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[tokenRef] = entry
}

// LoadTokens bulk-loads tokens into the store (replacing any existing ones with the same ref).
func (s *AuthServiceImpl) LoadTokens(entries map[string]TokenEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for ref, entry := range entries {
		s.tokens[ref] = entry
	}
}

// TokenCount returns the number of loaded tokens.
func (s *AuthServiceImpl) TokenCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.tokens)
}

// RemoveToken removes a token from the in-memory store (e.g. when the
// backing store no longer contains it after a refresh).
func (s *AuthServiceImpl) RemoveToken(tokenRef string) {
	s.mu.Lock()
	delete(s.tokens, tokenRef)
	s.mu.Unlock()

	s.forgetServed(tokenRef)
}

// GetEncryptedToken implements csarv1.AuthServiceServer.
//
// On cache miss, if a TokenBackend is configured, it performs a read-through
// query. This handles the case where a token was added to the backing store
// (e.g. PostgreSQL) between polling intervals.
func (s *AuthServiceImpl) GetEncryptedToken(ctx context.Context, req *csarv1.TokenRequest) (*csarv1.TokenResponse, error) {
	if req.TokenRef == "" {
		return nil, status.Error(codes.InvalidArgument, "token_ref is required")
	}

	now := s.clock()

	// Fast path: in-memory hit.
	s.mu.RLock()
	entry, ok := s.tokens[req.TokenRef]
	backend := s.backend
	s.mu.RUnlock()

	if ok && entry.Minted() {
		s.markServed(req.TokenRef, now)

		// Past hard expiry the cached value is worthless — treat it as a miss
		// so the blocking fetch below replaces it.
		if !entry.Usable(now) {
			ok = false
		} else if entry.NeedsRefresh(now) {
			// Still usable but due for replacement: serve it now and refresh
			// out of band. A failing token endpoint therefore costs nothing
			// until hard expiry.
			s.refreshInBackground(req.TokenRef)
		}
	}

	if !ok && backend != nil {
		// Read-through: query the backing store for this specific token_ref.
		// Use singleflight to prevent cache stampede (thundering herd) if multiple
		// concurrent requests arrive for the same missing token.
		s.logger.Info("token ref not in cache, trying backend read-through",
			"token_ref", req.TokenRef,
		)

		fetched, fetchErr := s.fetchThrough(ctx, backend, req.TokenRef)

		switch {
		case fetchErr == nil:
			if !s.isValid(req.TokenRef, fetched) {
				return nil, status.Errorf(codes.NotFound, "token ref %q not found (invalid)", req.TokenRef)
			}

			entry = fetched
			ok = true

		case errors.Is(fetchErr, ErrTokenNotFound):
			// Token genuinely doesn't exist in the backing store.
			s.logger.Warn("token ref not found in backend",
				"token_ref", req.TokenRef,
			)
			// Fall through to NotFound below.

		default:
			// Transient error (DB down, network, mint failure, etc.) — don't
			// cache the negative result. Log as error so operators notice.
			s.logger.Error("backend read-through failed (transient)",
				"token_ref", req.TokenRef,
				"error", fetchErr,
			)
			return nil, statusForFetchError(req.TokenRef, fetchErr)
		}
	}

	if !ok {
		s.logger.Warn("token ref not found", "token_ref", req.TokenRef)
		return nil, status.Errorf(codes.NotFound, "token ref %q not found", req.TokenRef)
	}

	s.logger.Debug("serving encrypted token", "token_ref", req.TokenRef)
	return &csarv1.TokenResponse{
		TokenRef:       req.TokenRef,
		EncryptedToken: entry.EncryptedToken,
		KmsKeyId:       entry.KMSKeyID,
		Version:        entry.Version,
	}, nil
}

// ListTokenRefs implements csarv1.AuthServiceServer.
func (s *AuthServiceImpl) ListTokenRefs(_ context.Context, _ *csarv1.ListTokenRefsRequest) (*csarv1.ListTokenRefsResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	refs := make([]*csarv1.TokenRefInfo, 0, len(s.tokens))
	for ref, entry := range s.tokens {
		refs = append(refs, &csarv1.TokenRefInfo{
			TokenRef: ref,
			KmsKeyId: entry.KMSKeyID,
		})
	}

	return &csarv1.ListTokenRefsResponse{Refs: refs}, nil
}

// LoadTokensFromFile loads tokens from a YAML file containing pre-encrypted token blobs.
// File format:
//
//	my_api_token:
//	  encrypted_token: <base64-encoded encrypted blob>
//	  kms_key_id: "key-1"
//
// This differs from the router's token file (which has plaintext) —
// the coordinator stores already-encrypted blobs.
type CoordinatorTokenFileEntry struct {
	EncryptedToken string `yaml:"encrypted_token"` // base64-encoded
	KMSKeyID       string `yaml:"kms_key_id"`
}

// LoadTokensFromMap loads tokens from a map (for programmatic use / testing).
// isValid checks if a token entry is structurally valid.
func (s *AuthServiceImpl) isValid(ref string, entry TokenEntry) bool {
	if len(entry.EncryptedToken) == 0 {
		s.logger.Warn("skipping token with empty encrypted_token", "token_ref", ref)
		return false
	}
	if entry.KMSKeyID == "" && !entry.Passthrough {
		s.logger.Warn("skipping token with empty kms_key_id (not passthrough)", "token_ref", ref)
		return false
	}
	return true
}

func (s *AuthServiceImpl) LoadTokensFromMap(m map[string]TokenEntry) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	loaded := 0
	for ref, entry := range m {
		if !s.isValid(ref, entry) {
			// If a previously valid token is updated to be invalid,
			// we must evict it so we don't serve a stale cached copy.
			delete(s.tokens, ref)
			continue
		}
		s.tokens[ref] = entry
		loaded++
	}
	return loaded
}

// Validate checks that the AuthService has at least one loaded token.
// Call after loading tokens to fail fast if the token store is empty.
func (s *AuthServiceImpl) Validate() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.tokens) == 0 {
		return fmt.Errorf("AuthService has no tokens loaded — " +
			"provide --coordinator-token-file or load tokens programmatically")
	}
	return nil
}
