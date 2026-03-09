package coordinator

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"
)

// ErrTokenNotFound is returned by TokenStore.FetchOne when the requested
// token_ref does not exist in the backing store. Implementations MUST return
// this sentinel (or wrap it with fmt.Errorf("…: %w", ErrTokenNotFound)) so
// callers can distinguish "genuinely missing" from transient failures.
var ErrTokenNotFound = errors.New("token not found")

// TokenStore is the interface for encrypted token storage backends.
// Implementations include PostgreSQL, YDB, Redis, and others.
//
// Security contract:
//   - SQL backends MUST use parameterized queries ($1, @p1, etc.) — never
//     string interpolation — to prevent injection.
//   - KV backends (Redis, etc.) MUST validate/escape keys appropriately.
//   - All implementations store pre-encrypted blobs; they MUST NOT
//     decrypt tokens or expose plaintext.
type TokenStore interface {
	// LoadAll returns every token in the store. Used for initial load and
	// periodic full refresh. Implementations should return an empty map
	// (not nil) when the store is empty.
	LoadAll(ctx context.Context) (map[string]TokenEntry, error)

	// FetchOne retrieves a single token by ref. Returns ErrTokenNotFound
	// (possibly wrapped) when the ref doesn't exist.
	FetchOne(ctx context.Context, tokenRef string) (TokenEntry, error)

	// Close releases resources held by the store (DB connections, etc.).
	Close() error
}

// TokenMetadata holds optional metadata written alongside a token object.
type TokenMetadata struct {
	UpdatedBy string
	Tenant    string
}

// MutableTokenStore extends TokenStore with write operations for the
// admin API. Not all backends need to support mutations — only those
// used with the coordinator admin token lifecycle API.
type MutableTokenStore interface {
	TokenStore

	// UpsertToken creates or replaces a token in the backing store.
	// Returns the new version (e.g. S3 ETag) on success.
	UpsertToken(ctx context.Context, ref string, entry TokenEntry, meta TokenMetadata) (version string, err error)

	// DeleteToken removes a token from the backing store.
	DeleteToken(ctx context.Context, ref string) error
}

// ---------------------------------------------------------------------------
// TokenRefresher — backend-agnostic periodic poll + diff
// ---------------------------------------------------------------------------

// TokenRefresher periodically polls a TokenStore, detects version changes
// (added / updated / removed tokens), updates the AuthServiceImpl's
// in-memory cache, and broadcasts invalidation events via the Coordinator.
//
// It is fully backend-agnostic — any TokenStore implementation works.
type TokenRefresher struct {
	store  TokenStore
	logger *slog.Logger

	mu       sync.RWMutex
	versions map[string]string // token_ref -> last known version
}

// NewTokenRefresher creates a refresher for the given store.
func NewTokenRefresher(store TokenStore, logger *slog.Logger) *TokenRefresher {
	return &TokenRefresher{
		store:    store,
		logger:   logger,
		versions: make(map[string]string),
	}
}

// SeedVersions records the initial version snapshot so the first
// RefreshAndDiff correctly detects only real changes vs. the initial load.
func (r *TokenRefresher) SeedVersions(entries map[string]TokenEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for ref, entry := range entries {
		r.versions[ref] = entry.Version
	}
}

// RefreshAndDiff queries all tokens from the store, detects additions,
// updates, and removals, applies them to the AuthService, and returns the
// list of changed token_refs for invalidation broadcasting.
func (r *TokenRefresher) RefreshAndDiff(ctx context.Context, authSvc *AuthServiceImpl) (changed []string, err error) {
	entries, err := r.store.LoadAll(ctx)
	if err != nil {
		return nil, err
	}

	r.mu.RLock()
	oldVersions := make(map[string]string, len(r.versions))
	for k, v := range r.versions {
		oldVersions[k] = v
	}
	r.mu.RUnlock()

	// Detect added / updated tokens.
	for ref, entry := range entries {
		oldVer, existed := oldVersions[ref]
		if !existed || oldVer != entry.Version {
			changed = append(changed, ref)
		}
	}

	// Detect removed tokens: present in old snapshot but absent now.
	for ref := range oldVersions {
		if _, stillExists := entries[ref]; !stillExists {
			changed = append(changed, ref)
			authSvc.RemoveToken(ref)
			r.logger.Info("token removed from store, evicted from cache",
				"token_ref", ref,
			)
		}
	}

	// Bulk-load all current tokens (unchanged ones are just overwritten).
	loaded := authSvc.LoadTokensFromMap(entries)

	r.logger.Debug("token refresh completed",
		"total", loaded,
		"changed", len(changed),
	)

	// Update version tracking (also clears removed entries).
	r.mu.Lock()
	r.versions = make(map[string]string, len(entries))
	for ref, entry := range entries {
		r.versions[ref] = entry.Version
	}
	r.mu.Unlock()

	return changed, nil
}

// RunPeriodicRefresh starts a background loop that polls the TokenStore at
// the given interval, updates the AuthService, and broadcasts invalidation
// events for changed tokens via the Coordinator.
//
// It blocks until ctx is cancelled.
func (r *TokenRefresher) RunPeriodicRefresh(
	ctx context.Context,
	interval time.Duration,
	authSvc *AuthServiceImpl,
	coord *Coordinator,
) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			r.logger.Info("token refresh loop stopped")
			return
		case <-ticker.C:
			changed, err := r.RefreshAndDiff(ctx, authSvc)
			if err != nil {
				r.logger.Error("token refresh failed", "error", err)
				continue
			}
			if len(changed) > 0 {
				r.logger.Info("token changes detected, broadcasting invalidation",
					"changed_refs", changed,
				)
				coord.BroadcastTokenInvalidation(changed)
			}
		}
	}
}
