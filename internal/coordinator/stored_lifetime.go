package coordinator

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ledatu/csar-core/s3store"

	"github.com/ledatu/csar/internal/statestore"
)

const storedExpirySkew = 30 * time.Second

var ErrTokenExpired = errors.New("stored credential expired")

func validStoredExpiry(expiry *time.Time) bool {
	return s3store.ValidateStoredExpiry(expiry) == nil
}

// SetTokenStates switches stored values to lifetime/event-driven caching. All
// writers must fence through the same metadata store. Configure before serving.
func (s *AuthServiceImpl) SetTokenStates(states statestore.TokenStates) { s.states = states }

func (s *AuthServiceImpl) storedDue(entry TokenEntry, stamp tokenCacheState, now time.Time, interval time.Duration) bool {
	if !entry.Usable(now) {
		return true
	}
	if s.states == nil {
		return now.Sub(stamp.checkedAt) >= interval
	}
	// Unknown-expiry static/legacy credentials depend on mutation/rejection
	// events; an absent expiry must not be interpreted as a fabricated JWT exp.
	return entry.ExpiresAt != nil && !now.Add(time.Minute).Before(*entry.ExpiresAt) && now.Sub(stamp.checkedAt) >= storedRefreshRetry
}

func (s *AuthServiceImpl) checkTokenState(ctx context.Context, ref string) error {
	if s.states == nil {
		return nil
	}
	result, err, _ := s.metadataSF.Do(ref, func() (any, error) {
		s.mu.RLock()
		stamp := s.cacheState[ref]
		s.mu.RUnlock()
		if stamp.validationFailure != nil && s.clock().Before(stamp.validationRetryAt) {
			return nil, stamp.validationFailure
		}
		bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), defaultFetchTimeout)
		defer cancel()
		state, readErr := s.states.GetTokenState(bounded, ref)
		if readErr != nil {
			s.cacheMetadataFailure(ref, readErr)
			return nil, readErr
		}
		s.mu.Lock()
		stamp = s.cacheState[ref]
		stamp.validationFailure = nil
		stamp.validationRetryAt = time.Time{}
		s.cacheState[ref] = stamp
		s.mu.Unlock()
		return state, nil
	})
	if err != nil {
		return err
	}
	state, valid := result.(statestore.TokenState)
	if !valid {
		return fmt.Errorf("invalid token control state result")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stamp := s.cacheState[ref]
	if state.Revision < stamp.controlRevision {
		return ErrTokenChanged
	}
	if stamp.controlRevision != state.Revision {
		s.removeTokenLocked(ref)
		stamp = s.cacheState[ref]
		stamp.controlRevision = state.Revision
		s.cacheState[ref] = stamp
	}
	if state.Pending != "" {
		return ErrTokenPending
	}
	if entry, ok := s.tokens[ref]; ok && !entry.Minted() && rejected(state, entry) {
		return ErrTokenRejected
	}
	return nil
}

// WatchTokenChanges pushes exact-ref eviction hints to connected routers. Each
// GetEncryptedToken still validates a linearizable per-ref revision, so missed
// events, reconnection and etcd compaction cannot authorize stale cache entries.
func WatchTokenChanges(ctx context.Context, states statestore.TokenStates, auth *AuthServiceImpl, coord *Coordinator) {
	for ctx.Err() == nil {
		events, err := states.WatchTokenStates(ctx)
		if err == nil {
			for event := range events {
				auth.RemoveToken(event.Ref)
				coord.BroadcastTokenInvalidation([]string{event.Ref})
			}
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (s *AuthServiceImpl) cacheMetadataFailure(ref string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stamp := s.cacheState[ref]
	stamp.validationFailure = err
	stamp.validationRetryAt = s.clock().Add(storedRefreshRetry)
	s.cacheState[ref] = stamp
}
