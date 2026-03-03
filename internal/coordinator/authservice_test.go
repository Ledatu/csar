package coordinator

import (
	"context"
	"io"
	"log/slog"
	"testing"

	csarv1 "github.com/ledatu/csar/proto/csar/v1"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestAuthService_GetEncryptedToken_OK(t *testing.T) {
	svc := NewAuthService(testLogger())
	svc.LoadToken("api_main", TokenEntry{
		EncryptedToken: []byte("encrypted-blob"),
		KMSKeyID:       "key-1",
	})

	resp, err := svc.GetEncryptedToken(context.Background(), &csarv1.TokenRequest{TokenRef: "api_main"})
	if err != nil {
		t.Fatalf("GetEncryptedToken: %v", err)
	}
	if string(resp.EncryptedToken) != "encrypted-blob" {
		t.Errorf("encrypted_token = %q, want %q", resp.EncryptedToken, "encrypted-blob")
	}
	if resp.KmsKeyId != "key-1" {
		t.Errorf("kms_key_id = %q, want %q", resp.KmsKeyId, "key-1")
	}
	if resp.TokenRef != "api_main" {
		t.Errorf("token_ref = %q, want %q", resp.TokenRef, "api_main")
	}
}

func TestAuthService_GetEncryptedToken_NotFound(t *testing.T) {
	svc := NewAuthService(testLogger())

	_, err := svc.GetEncryptedToken(context.Background(), &csarv1.TokenRequest{TokenRef: "nonexistent"})
	if err == nil {
		t.Fatal("expected error for nonexistent token ref")
	}
}

func TestAuthService_GetEncryptedToken_EmptyRef(t *testing.T) {
	svc := NewAuthService(testLogger())

	_, err := svc.GetEncryptedToken(context.Background(), &csarv1.TokenRequest{TokenRef: ""})
	if err == nil {
		t.Fatal("expected error for empty token_ref")
	}
}

func TestAuthService_ListTokenRefs(t *testing.T) {
	svc := NewAuthService(testLogger())
	svc.LoadToken("ref_a", TokenEntry{EncryptedToken: []byte("a"), KMSKeyID: "k1"})
	svc.LoadToken("ref_b", TokenEntry{EncryptedToken: []byte("b"), KMSKeyID: "k2"})

	resp, err := svc.ListTokenRefs(context.Background(), &csarv1.ListTokenRefsRequest{})
	if err != nil {
		t.Fatalf("ListTokenRefs: %v", err)
	}
	if len(resp.Refs) != 2 {
		t.Fatalf("expected 2 refs, got %d", len(resp.Refs))
	}

	found := make(map[string]string)
	for _, r := range resp.Refs {
		found[r.TokenRef] = r.KmsKeyId
	}
	if found["ref_a"] != "k1" {
		t.Errorf("ref_a kms_key_id = %q, want %q", found["ref_a"], "k1")
	}
	if found["ref_b"] != "k2" {
		t.Errorf("ref_b kms_key_id = %q, want %q", found["ref_b"], "k2")
	}
}

func TestAuthService_LoadTokensFromMap_SkipsInvalid(t *testing.T) {
	svc := NewAuthService(testLogger())
	loaded := svc.LoadTokensFromMap(map[string]TokenEntry{
		"good":       {EncryptedToken: []byte("enc"), KMSKeyID: "k1"},
		"empty_enc":  {EncryptedToken: nil, KMSKeyID: "k1"},
		"empty_key":  {EncryptedToken: []byte("enc"), KMSKeyID: ""},
		"also_empty": {EncryptedToken: []byte{}, KMSKeyID: "k1"},
	})

	if loaded != 1 {
		t.Errorf("expected 1 loaded token, got %d", loaded)
	}
	if svc.TokenCount() != 1 {
		t.Errorf("expected TokenCount() == 1, got %d", svc.TokenCount())
	}
}

func TestAuthService_Validate_Empty(t *testing.T) {
	svc := NewAuthService(testLogger())
	if err := svc.Validate(); err == nil {
		t.Error("expected error for empty token store")
	}
}

func TestAuthService_Validate_OK(t *testing.T) {
	svc := NewAuthService(testLogger())
	svc.LoadToken("ref", TokenEntry{EncryptedToken: []byte("x"), KMSKeyID: "k"})
	if err := svc.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
}
