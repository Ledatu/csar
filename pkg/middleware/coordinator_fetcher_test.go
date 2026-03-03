package middleware

import (
	"context"
	"fmt"
	"testing"

	csarv1 "github.com/ledatu/csar/proto/csar/v1"
	"google.golang.org/grpc"
)

// mockAuthServiceClient implements csarv1.AuthServiceClient for testing.
type mockAuthServiceClient struct {
	tokens map[string]*csarv1.TokenResponse
	err    error
}

func (m *mockAuthServiceClient) GetEncryptedToken(ctx context.Context, in *csarv1.TokenRequest, opts ...grpc.CallOption) (*csarv1.TokenResponse, error) {
	if m.err != nil {
		return nil, m.err
	}
	resp, ok := m.tokens[in.TokenRef]
	if !ok {
		return nil, fmt.Errorf("token ref %q not found", in.TokenRef)
	}
	return resp, nil
}

func (m *mockAuthServiceClient) ListTokenRefs(ctx context.Context, in *csarv1.ListTokenRefsRequest, opts ...grpc.CallOption) (*csarv1.ListTokenRefsResponse, error) {
	return nil, fmt.Errorf("not implemented in mock")
}

func TestCoordinatorTokenFetcher_OK(t *testing.T) {
	mock := &mockAuthServiceClient{
		tokens: map[string]*csarv1.TokenResponse{
			"api_main": {
				TokenRef:       "api_main",
				EncryptedToken: []byte("encrypted-blob"),
				KmsKeyId:       "key-123",
			},
		},
	}

	fetcher := NewCoordinatorTokenFetcher(mock)
	enc, keyID, _, err := fetcher.GetEncryptedToken(context.Background(), "api_main")
	if err != nil {
		t.Fatalf("GetEncryptedToken: %v", err)
	}
	if string(enc) != "encrypted-blob" {
		t.Errorf("encrypted_token = %q, want %q", enc, "encrypted-blob")
	}
	if keyID != "key-123" {
		t.Errorf("kms_key_id = %q, want %q", keyID, "key-123")
	}
}

func TestCoordinatorTokenFetcher_NotFound(t *testing.T) {
	mock := &mockAuthServiceClient{
		tokens: map[string]*csarv1.TokenResponse{},
	}

	fetcher := NewCoordinatorTokenFetcher(mock)
	_, _, _, err := fetcher.GetEncryptedToken(context.Background(), "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent token ref")
	}
}

func TestCoordinatorTokenFetcher_RPCError(t *testing.T) {
	mock := &mockAuthServiceClient{
		err: fmt.Errorf("connection refused"),
	}

	fetcher := NewCoordinatorTokenFetcher(mock)
	_, _, _, err := fetcher.GetEncryptedToken(context.Background(), "api_main")
	if err == nil {
		t.Error("expected error when RPC fails")
	}
}
