package middleware

import (
	"context"
	"fmt"

	csarv1 "github.com/ledatu/csar/proto/csar/v1"
)

// CoordinatorTokenFetcher implements TokenFetcher using the coordinator's
// gRPC AuthService. This is the production token source — the router
// fetches encrypted tokens from the coordinator, which in turn retrieves
// them from the configured AuthService backend (Vault, DB, etc.).
type CoordinatorTokenFetcher struct {
	client csarv1.AuthServiceClient
}

// NewCoordinatorTokenFetcher creates a token fetcher backed by the coordinator gRPC service.
func NewCoordinatorTokenFetcher(client csarv1.AuthServiceClient) *CoordinatorTokenFetcher {
	return &CoordinatorTokenFetcher{client: client}
}

// GetEncryptedToken implements TokenFetcher by calling the coordinator's AuthService.
func (f *CoordinatorTokenFetcher) GetEncryptedToken(ctx context.Context, tokenRef string) ([]byte, string, string, error) {
	resp, err := f.client.GetEncryptedToken(ctx, &csarv1.TokenRequest{
		TokenRef: tokenRef,
	})
	if err != nil {
		return nil, "", "", fmt.Errorf("coordinator GetEncryptedToken(%q): %w", tokenRef, err)
	}
	return resp.EncryptedToken, resp.KmsKeyId, resp.Version, nil
}
