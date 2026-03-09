package coordinator

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	csarv1 "github.com/ledatu/csar/proto/csar/v1"
	"golang.org/x/sync/singleflight"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// defaultFetchTimeout is the maximum time allowed for a read-through
// backend fetch. Prevents singleflight lanes from being occupied
// indefinitely under degraded DB/network conditions (audit §4).
const defaultFetchTimeout = 5 * time.Second

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
}

// LogValue implements slog.LogValuer to prevent accidental logging of
// the encrypted token blob. Only the KMS key ID and version are shown.
func (e TokenEntry) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("kms_key_id", e.KMSKeyID),
		slog.String("version", e.Version),
		slog.String("encrypted_token", "[REDACTED]"),
	)
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
}

// NewAuthService creates an AuthServiceImpl with an empty token store.
func NewAuthService(logger *slog.Logger) *AuthServiceImpl {
	return &AuthServiceImpl{
		tokens:       make(map[string]TokenEntry),
		logger:       logger,
		fetchTimeout: defaultFetchTimeout,
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
	defer s.mu.Unlock()
	delete(s.tokens, tokenRef)
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

	// Fast path: in-memory hit.
	s.mu.RLock()
	entry, ok := s.tokens[req.TokenRef]
	backend := s.backend
	s.mu.RUnlock()

	if !ok && backend != nil {
		// Read-through: query the backing store for this specific token_ref.
		// Use singleflight to prevent cache stampede (thundering herd) if multiple
		// concurrent requests arrive for the same missing token.
		s.logger.Info("token ref not in cache, trying backend read-through",
			"token_ref", req.TokenRef,
		)

		res, fetchErr, _ := s.sf.Do(req.TokenRef, func() (interface{}, error) {
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

			fetched, err := backend.FetchOne(fetchCtx, req.TokenRef)
			if err != nil {
				return nil, err
			}

			if !s.isValid(req.TokenRef, fetched) {
				return fetched, nil
			}

			// Cache inside the singleflight closure so only the leader goroutine
			// writes, eliminating redundant lock contention from shared waiters.
			s.mu.Lock()
			s.tokens[req.TokenRef] = fetched
			s.mu.Unlock()

			s.logger.Info("token fetched from backend and cached",
				"token_ref", req.TokenRef,
				"version", fetched.Version,
			)

			return fetched, nil
		})

		switch {
		case fetchErr == nil:
			fetched := res.(TokenEntry)
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
			// Transient error (DB down, network, etc.) — don't cache the
			// negative result. Log as error so operators notice.
			s.logger.Error("backend read-through failed (transient)",
				"token_ref", req.TokenRef,
				"error", fetchErr,
			)
			return nil, status.Errorf(codes.Unavailable,
				"token store temporarily unavailable for ref %q", req.TokenRef)
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
