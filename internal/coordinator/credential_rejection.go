package coordinator

import (
	"context"
	"encoding/hex"
	"errors"

	credentialv1 "github.com/ledatu/csar-proto/csar/credential/v1"
	"github.com/ledatu/csar/internal/statestore"
	"golang.org/x/sync/singleflight"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// CredentialRejections is registered only with coherent storage enabled. Its
// transport must have the same trusted-router authentication as AuthService.
type CredentialRejections struct {
	credentialv1.UnimplementedCredentialServiceServer
	store   *CoherentTokenStore
	auth    *AuthServiceImpl
	coord   *Coordinator
	flights singleflight.Group
}

func NewCredentialRejections(store *CoherentTokenStore, auth *AuthServiceImpl, coord *Coordinator) *CredentialRejections {
	return &CredentialRejections{store: store, auth: auth, coord: coord}
}

func (s *CredentialRejections) ReportRejection(ctx context.Context, req *credentialv1.ReportRejectionRequest) (*credentialv1.ReportRejectionResponse, error) {
	if ValidateTokenRef(req.GetTokenRef()) != nil || req.GetVersion() == "" || len(req.GetVersion()) > 1024 || len(req.GetCredentialFingerprint()) != 64 {
		return nil, status.Error(codes.InvalidArgument, "exact ref, version and fingerprint are required")
	}
	if _, err := hex.DecodeString(req.GetCredentialFingerprint()); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid fingerprint")
	}
	_, err, _ := s.flights.Do(req.TokenRef+"\x00"+req.Version, func() (any, error) {
		bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), defaultFetchTimeout)
		defer cancel()
		return nil, s.reject(bounded, req)
	})
	if err != nil {
		return nil, statusForFetchError(req.TokenRef, err)
	}
	return &credentialv1.ReportRejectionResponse{}, nil
}

func (s *CredentialRejections) reject(ctx context.Context, req *credentialv1.ReportRejectionRequest) error {
	state, err := s.store.states.GetTokenState(ctx, req.TokenRef)
	if err != nil {
		return err
	}
	if state.Pending != "" {
		return ErrTokenPending
	}
	if state.Version != "" && state.Version != req.Version && state.CredentialID != req.CredentialFingerprint {
		return nil
	}
	if state.RejectedVersion == state.Version && state.RejectedID == req.CredentialFingerprint {
		return nil
	}
	// Legacy objects have no control-plane version until their first mutation.
	// Compare against the current object, never against an arbitrary peer cache.
	if state.Version == "" {
		current, fetchErr := s.store.MutableTokenStore.FetchOne(ctx, req.TokenRef)
		if fetchErr != nil && !errors.Is(fetchErr, ErrTokenNotFound) {
			return fetchErr
		}
		if fetchErr == nil && (current.Descriptor != nil || current.Minted() || (current.Version != req.Version && (current.CredentialID == "" || current.CredentialID != req.CredentialFingerprint))) {
			return nil
		}
		if fetchErr == nil && current.CredentialID != "" && current.CredentialID != req.CredentialFingerprint {
			return nil
		}
		state.Version = req.Version
		if fetchErr == nil {
			state.Version = current.Version
		}
		state.CredentialID = current.CredentialID
	}
	if state.CredentialID != "" && state.CredentialID != req.CredentialFingerprint {
		return nil
	}
	state.RejectedID = req.CredentialFingerprint
	state.RejectedVersion = state.Version
	rev, err := s.store.states.CASTokenState(ctx, req.TokenRef, state.Revision, state)
	if err != nil {
		return err
	}
	// A concurrent rotation wins. A later request will see its new revision.
	if rev == 0 {
		latest, readErr := s.store.states.GetTokenState(ctx, req.TokenRef)
		if readErr != nil {
			return readErr
		}
		if latest.Pending != "" {
			return ErrTokenPending
		}
		if latest.CredentialID == req.CredentialFingerprint {
			return ErrTokenChanged
		}
		return nil
	}
	s.auth.RemoveToken(req.TokenRef)
	s.coord.BroadcastTokenInvalidation([]string{req.TokenRef})
	return nil
}

// RevalidateRef publishes an explicit administrative cache invalidation without
// modifying token contents or clearing a provider rejection.
func RevalidateRef(ctx context.Context, states statestore.TokenStates, ref string) error {
	state, err := states.GetTokenState(ctx, ref)
	if err != nil {
		return err
	}
	if state.Pending != "" {
		return ErrTokenPending
	}
	rev, err := states.CASTokenState(ctx, ref, state.Revision, state)
	if err != nil {
		return err
	}
	if rev == 0 {
		return ErrTokenChanged
	}
	return nil
}
