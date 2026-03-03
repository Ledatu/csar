package coordinator

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	csarv1 "github.com/ledatu/csar/proto/csar/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TokenEntry holds an encrypted token and its associated KMS key.
type TokenEntry struct {
	EncryptedToken []byte
	KMSKeyID       string
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
// Tokens are loaded into the in-memory store at startup (from file, external AuthService, etc.).
type AuthServiceImpl struct {
	csarv1.UnimplementedAuthServiceServer

	mu     sync.RWMutex
	tokens map[string]TokenEntry // token_ref -> entry
	logger *slog.Logger
}

// NewAuthService creates an AuthServiceImpl with an empty token store.
func NewAuthService(logger *slog.Logger) *AuthServiceImpl {
	return &AuthServiceImpl{
		tokens: make(map[string]TokenEntry),
		logger: logger,
	}
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

// GetEncryptedToken implements csarv1.AuthServiceServer.
func (s *AuthServiceImpl) GetEncryptedToken(_ context.Context, req *csarv1.TokenRequest) (*csarv1.TokenResponse, error) {
	if req.TokenRef == "" {
		return nil, status.Error(codes.InvalidArgument, "token_ref is required")
	}

	s.mu.RLock()
	entry, ok := s.tokens[req.TokenRef]
	s.mu.RUnlock()

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
func (s *AuthServiceImpl) LoadTokensFromMap(m map[string]TokenEntry) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	loaded := 0
	for ref, entry := range m {
		if len(entry.EncryptedToken) == 0 {
			s.logger.Warn("skipping token with empty encrypted_token", "token_ref", ref)
			continue
		}
		if entry.KMSKeyID == "" {
			s.logger.Warn("skipping token with empty kms_key_id", "token_ref", ref)
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
