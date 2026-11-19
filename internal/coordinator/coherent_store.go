package coordinator

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/ledatu/csar/internal/statestore"
)

func rejectTokenMutation(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrTokenMutationUnknown) || errors.Is(err, ErrTokenPending) {
		w.Header().Set("Retry-After", "5")
		respondJSON(w, http.StatusServiceUnavailable, map[string]string{"code": "credential_mutation_outcome_unknown", "status": "pending"})
		return
	}
	if errors.Is(err, ErrTokenChanged) {
		adminRejectJSON(w, http.StatusServiceUnavailable, "credential changed concurrently; retry operation")
		return
	}
	adminRejectJSON(w, http.StatusInternalServerError, "credential storage mutation failed")
}

var (
	ErrTokenMutationUnknown = errors.New("credential mutation outcome unknown")
	ErrTokenPending         = errors.New("credential mutation pending; outcome unknown")
	ErrTokenRejected        = errors.New("credential version rejected upstream")
	ErrTokenChanged         = errors.New("credential changed during read")
)

// CoherentTokenStore fences object writes with durable per-ref metadata. Every
// writer must use it before event-driven caching is enabled. It never lists S3.
type CoherentTokenStore struct {
	MutableTokenStore
	states statestore.TokenStates
}

func NewCoherentTokenStore(raw MutableTokenStore, states statestore.TokenStates) *CoherentTokenStore {
	return &CoherentTokenStore{MutableTokenStore: raw, states: states}
}

func rejected(state statestore.TokenState, entry TokenEntry) bool {
	return (state.RejectedVersion != "" && state.RejectedVersion == entry.Version) ||
		(state.RejectedID != "" && entry.CredentialID != "" && state.RejectedID == entry.CredentialID)
}

func (s *CoherentTokenStore) FetchOne(ctx context.Context, ref string) (TokenEntry, error) {
	before, err := s.states.GetTokenState(ctx, ref)
	if err != nil {
		return TokenEntry{}, err
	}
	if before.Pending != "" {
		return TokenEntry{}, ErrTokenPending
	}
	entry, err := s.MutableTokenStore.FetchOne(ctx, ref)
	if err != nil {
		return TokenEntry{}, err
	}
	after, err := s.states.GetTokenState(ctx, ref)
	if err != nil {
		return TokenEntry{}, err
	}
	if after.Revision != before.Revision {
		return TokenEntry{}, ErrTokenChanged
	}
	if rejected(after, entry) {
		return TokenEntry{}, ErrTokenRejected
	}
	return entry, nil
}

func (s *CoherentTokenStore) begin(ctx context.Context, ref string) (statestore.TokenState, error) {
	state, err := s.states.GetTokenState(ctx, ref)
	if err != nil {
		return state, err
	}
	if state.Pending != "" {
		return state, ErrTokenPending
	}
	state.Pending = uuid.NewString()
	rev, err := s.states.CASTokenState(ctx, ref, state.Revision, state)
	if err != nil {
		return state, err
	}
	if rev == 0 {
		return state, ErrTokenChanged
	}
	state.Revision = rev
	return state, nil
}

func (s *CoherentTokenStore) finish(ctx context.Context, ref string, state statestore.TokenState) error {
	state.Pending = ""
	rev, err := s.states.CASTokenState(ctx, ref, state.Revision, state)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrTokenMutationUnknown, err)
	}
	if rev == 0 {
		return ErrTokenChanged
	}
	return nil
}

func (s *CoherentTokenStore) UpsertToken(ctx context.Context, ref string, entry TokenEntry, meta TokenMetadata) (string, error) {
	state, err := s.begin(ctx, ref)
	if err != nil {
		return "", err
	}
	version, err := s.MutableTokenStore.UpsertToken(ctx, ref, entry, meta)
	// An object request can commit after a lost receipt. Leave the durable fence
	// on any error; never clear it on a timeout and silently resume old credentials.
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrTokenMutationUnknown, err)
	}
	state.Version = version
	state.CredentialID = entry.CredentialID
	if err = s.finish(ctx, ref, state); err != nil {
		return "", err
	}
	return version, nil
}

func (s *CoherentTokenStore) DeleteToken(ctx context.Context, ref string) error {
	state, err := s.begin(ctx, ref)
	if err != nil {
		return err
	}
	if err = s.MutableTokenStore.DeleteToken(ctx, ref); err != nil {
		return fmt.Errorf("%w: %w", ErrTokenMutationUnknown, err)
	}
	state.Version = ""
	state.CredentialID = ""
	return s.finish(ctx, ref, state)
}
