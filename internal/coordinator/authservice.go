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
	"github.com/ledatu/csar/internal/statestore"
	csarv1 "github.com/ledatu/csar/proto/csar/v1"
	"golang.org/x/sync/singleflight"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// defaultFetchTimeout is the maximum time allowed for a read-through
// backend fetch. Prevents singleflight lanes from being occupied
// indefinitely under degraded DB/network conditions (audit §4).
const defaultFetchTimeout = 5 * time.Second

const storedRefreshRetry = 5 * time.Second

type tokenCacheState struct {
	validationFailure error
	validationRetryAt time.Time
	controlRevision   int64
	epoch             uint64
	checkedAt         time.Time
	retryAt           time.Time
	failure           error
}

// DefaultFetchTimeout exposes the default read-through deadline so callers can
// tell whether their own work (e.g. a token mint) would outlast it.
func DefaultFetchTimeout() time.Duration { return defaultFetchTimeout }

// TokenEntry holds an encrypted token and its associated KMS key.
type TokenEntry struct {
	ExpiresAt      *time.Time
	CredentialID   string
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
	// nil for stored tokens, whose lifetime/invalidation is independent.
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

// Usable enforces inspected stored expiry with clock skew. Minted entries retain
// their independent hard-expiry behavior.
func (e TokenEntry) Usable(now time.Time) bool {
	if e.Mint == nil {
		return e.ExpiresAt == nil || now.Add(storedExpirySkew).Before(*e.ExpiresAt)
	}
	return e.Mint.HardExpiry.IsZero() || now.Before(e.Mint.HardExpiry)
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
// A configured TokenStore is queried on misses and on the first request after
// the legacy freshness interval, or lifetime/invalidation in coherent mode.
// Idle refs cause no backend reads.
type AuthServiceImpl struct {
	csarv1.UnimplementedAuthServiceServer

	mu                    sync.RWMutex
	tokens                map[string]TokenEntry // token_ref -> entry
	logger                *slog.Logger
	states                statestore.TokenStates
	backend               TokenStore // optional read-through backend (e.g. PostgresTokenStore)
	sf                    singleflight.Group
	metadataSF            singleflight.Group
	fetchTimeout          time.Duration // max time for read-through backend queries (audit §4)
	storedRefreshInterval time.Duration
	cacheEpoch            uint64
	cacheState            map[string]tokenCacheState

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
		tokens:                make(map[string]TokenEntry),
		logger:                logger,
		fetchTimeout:          defaultFetchTimeout,
		storedRefreshInterval: time.Minute,
		cacheState:            make(map[string]tokenCacheState),
		now:                   time.Now,
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
	_, err := s.fetchThrough(ctx, backend, tokenRef, true)
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
func (s *AuthServiceImpl) fetchThrough(ctx context.Context, backend TokenStore, tokenRef string, force bool) (TokenEntry, error) {
	res, err, _ := s.sf.Do(tokenRef, func() (interface{}, error) {
		s.mu.RLock()
		previous, existed := s.tokens[tokenRef]
		stamp := s.cacheState[tokenRef]
		interval := s.storedRefreshInterval
		s.mu.RUnlock()
		if !force {
			now := s.clock()
			if stamp.failure != nil && now.Before(stamp.retryAt) {
				return nil, stamp.failure
			}
			// Another caller may have completed validation before this flight.
			if existed && !previous.Minted() && previous.Usable(now) && !s.storedDue(previous, stamp, now, interval) {
				return previous, nil
			}
		}
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
		if fetchErr == nil && !fetched.Minted() && !fetched.Usable(s.clock()) {
			fetchErr = ErrTokenExpired
		}
		if fetchErr == nil && s.states != nil {
			currentState, stateErr := s.states.GetTokenState(fetchCtx, tokenRef)
			switch {
			case stateErr != nil:
				fetchErr = stateErr
			case currentState.Pending != "" || currentState.Revision != stamp.controlRevision:
				fetchErr = ErrTokenChanged
			case rejected(currentState, fetched):
				fetchErr = ErrTokenRejected
			}
		}
		s.mu.Lock()
		// A local write/delete is newer than a backend read started before it.
		if s.cacheState[tokenRef].epoch != stamp.epoch {
			if s.states != nil {
				s.mu.Unlock()
				return nil, ErrTokenChanged
			}
			current, present := s.tokens[tokenRef]
			s.mu.Unlock()
			if !present {
				return nil, ErrTokenNotFound
			}
			if !current.Minted() && !current.Usable(s.clock()) {
				return nil, ErrTokenExpired
			}
			return current, nil
		}
		if fetchErr == nil && !s.isValid(tokenRef, fetched) {
			fetchErr = ErrTokenNotFound
		}
		if fetchErr != nil {
			if !previous.Minted() {
				// Fail closed on a stale stored credential; bound repeated failure
				// checks without declaring the old credential fresh again.
				stamp.failure = fetchErr
				stamp.retryAt = s.clock().Add(storedRefreshRetry)
				if errors.Is(fetchErr, ErrTokenNotFound) {
					s.cacheEpoch++
					stamp.epoch = s.cacheEpoch
					delete(s.tokens, tokenRef)
				}
				s.cacheState[tokenRef] = stamp
			}
			s.mu.Unlock()
			return nil, fetchErr
		}
		s.loadTokenLocked(tokenRef, fetched)
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
// Routers retain HTTP 502 and expose only an allowlisted apierror machine code.
// The gRPC class also separates revoked credentials, quota, configuration and
// transient endpoint failures for observability; raw messages stay internal.
func statusForFetchError(tokenRef string, err error) error {
	switch {
	case errors.Is(err, ErrTokenRejected), errors.Is(err, ErrTokenExpired):
		return status.Error(codes.Unauthenticated, "stored credential is expired or was rejected upstream")
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

// SetStoredRefreshInterval bounds legacy demand validation of stored tokens.
// Coherent mode uses lifetime and exact-ref invalidation instead.
// It must be configured before requests start. No background scans are started.
func (s *AuthServiceImpl) SetStoredRefreshInterval(d time.Duration) {
	s.mu.Lock()
	s.storedRefreshInterval = d
	s.mu.Unlock()
}

func (s *AuthServiceImpl) loadTokenLocked(ref string, entry TokenEntry) {
	s.cacheEpoch++
	s.tokens[ref] = entry
	s.cacheState[ref] = tokenCacheState{epoch: s.cacheEpoch, checkedAt: s.clock(), controlRevision: s.cacheState[ref].controlRevision}
}

func (s *AuthServiceImpl) removeTokenLocked(ref string) {
	s.cacheEpoch++
	delete(s.tokens, ref)
	s.cacheState[ref] = tokenCacheState{epoch: s.cacheEpoch}
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
	s.loadTokenLocked(tokenRef, entry)
}

// LoadTokens bulk-loads tokens into the store (replacing any existing ones with the same ref).
func (s *AuthServiceImpl) LoadTokens(entries map[string]TokenEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for ref, entry := range entries {
		s.loadTokenLocked(ref, entry)
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
	s.removeTokenLocked(tokenRef)
	s.mu.Unlock()

	s.forgetServed(tokenRef)
}

// GetEncryptedToken implements csarv1.AuthServiceServer.
//
// Missing or stale stored credentials are validated through the backend before
// being served. Minted credentials retain their independent lifetime policy.
func (s *AuthServiceImpl) GetEncryptedToken(ctx context.Context, req *csarv1.TokenRequest) (*csarv1.TokenResponse, error) {
	if req.TokenRef == "" {
		return nil, status.Error(codes.InvalidArgument, "token_ref is required")
	}

	if err := s.checkTokenState(ctx, req.TokenRef); err != nil {
		return nil, statusForFetchError(req.TokenRef, err)
	}
	now := s.clock()

	// Fast path: in-memory hit.
	s.mu.RLock()
	entry, ok := s.tokens[req.TokenRef]
	backend := s.backend
	stamp := s.cacheState[req.TokenRef]
	interval := s.storedRefreshInterval
	s.mu.RUnlock()
	if backend != nil && stamp.failure != nil && now.Before(stamp.retryAt) {
		if errors.Is(stamp.failure, ErrTokenNotFound) {
			return nil, status.Error(codes.NotFound, "stored token no longer exists")
		}
		return nil, statusForFetchError(req.TokenRef, stamp.failure)
	}
	if ok && !entry.Minted() && backend != nil && s.storedDue(entry, stamp, now, interval) {
		ok = false
	}

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
		s.logger.Info("token missing or due for validation, trying backend read-through",
			"token_ref", req.TokenRef,
		)

		fetched, fetchErr := s.fetchThrough(ctx, backend, req.TokenRef, false)

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
			// Stored failures have a bounded demand retry delay. Minting retains
			// its separate retry policy; return a typed error to the router.
			s.logger.Error("credential read-through failed",
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

	if s.states != nil && !entry.Minted() {
		s.mu.RLock()
		verifyEpoch := s.cacheState[req.TokenRef].epoch
		s.mu.RUnlock()
		verifyCtx, cancel := context.WithTimeout(ctx, defaultFetchTimeout)
		latest, verifyErr := s.states.GetTokenState(verifyCtx, req.TokenRef)
		cancel()
		if verifyErr != nil {
			s.cacheMetadataFailure(req.TokenRef, verifyEpoch, verifyErr)
			return nil, statusForFetchError(req.TokenRef, verifyErr)
		}
		if latest.Pending != "" || latest.Revision != stamp.controlRevision {
			return nil, statusForFetchError(req.TokenRef, ErrTokenChanged)
		}
		if rejected(latest, entry) {
			return nil, statusForFetchError(req.TokenRef, ErrTokenRejected)
		}
	}
	if ok && !entry.Minted() && !entry.Usable(s.clock()) {
		return nil, statusForFetchError(req.TokenRef, ErrTokenExpired)
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
			s.removeTokenLocked(ref)
			continue
		}
		s.loadTokenLocked(ref, entry)
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
