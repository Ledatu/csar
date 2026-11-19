package middleware

import (
	"context"
	"fmt"

	credentialv1 "github.com/ledatu/csar-proto/csar/credential/v1"
	csarv1 "github.com/ledatu/csar/proto/csar/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// CoordinatorTokenFetcher implements TokenFetcher using the coordinator's
// gRPC AuthService. This is the production token source — the router
// fetches encrypted tokens from the coordinator, which in turn retrieves
// them from the configured AuthService backend (Vault, DB, etc.).
type CoordinatorTokenFetcher struct {
	client     csarv1.AuthServiceClient
	rejections credentialv1.CredentialServiceClient
}

// NewCoordinatorTokenFetcher creates a token fetcher backed by the coordinator gRPC service.
func NewCoordinatorTokenFetcher(client csarv1.AuthServiceClient, reports ...credentialv1.CredentialServiceClient) *CoordinatorTokenFetcher {
	f := &CoordinatorTokenFetcher{client: client}
	if len(reports) > 0 {
		f.rejections = reports[0]
	}
	return f
}

// ReportCredentialRejection reports only an actual upstream authentication 401.
// Older coordinators return Unimplemented; this never causes a request replay.
func (f *CoordinatorTokenFetcher) ReportCredentialRejection(ctx context.Context, ref, version, fingerprint string) error {
	if f.rejections == nil {
		return status.Error(codes.Unimplemented, "credential reports not configured")
	}
	_, err := f.rejections.ReportRejection(ctx, &credentialv1.ReportRejectionRequest{TokenRef: ref, Version: version, CredentialFingerprint: fingerprint})
	return err
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
