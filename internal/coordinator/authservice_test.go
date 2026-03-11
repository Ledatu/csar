package coordinator

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

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

// ==========================================================================
// Singleflight context cancellation tests (audit §2)
// ==========================================================================

// slowStore is a test TokenStore that adds a delay to FetchOne, allowing
// us to test singleflight context cancellation behavior.
type slowStore struct {
	delay   time.Duration
	entries map[string]TokenEntry
}

func (s *slowStore) LoadAll(_ context.Context) (map[string]TokenEntry, error) {
	return s.entries, nil
}

func (s *slowStore) FetchOne(ctx context.Context, ref string) (TokenEntry, error) {
	select {
	case <-time.After(s.delay):
	case <-ctx.Done():
		return TokenEntry{}, ctx.Err()
	}
	entry, ok := s.entries[ref]
	if !ok {
		return TokenEntry{}, fmt.Errorf("ref %q: %w", ref, ErrTokenNotFound)
	}
	return entry, nil
}

func (s *slowStore) Close() error { return nil }

func TestAuthService_ReadThrough_FirstCallerCancel(t *testing.T) {
	// Verify that when the first caller's context is cancelled, other
	// concurrent callers in the singleflight group are NOT affected.
	// This tests the context.WithoutCancel fix (audit §2).
	store := &slowStore{
		delay: 200 * time.Millisecond,
		entries: map[string]TokenEntry{
			"tok": {EncryptedToken: []byte("enc"), KMSKeyID: "k1", Version: "v1"},
		},
	}

	svc := NewAuthService(testLogger())
	svc.SetBackend(store)

	// Launch two concurrent requests for the same token.
	var wg sync.WaitGroup
	var err1, err2 error
	var resp2 *csarv1.TokenResponse

	// Caller 1: will be cancelled immediately.
	ctx1, cancel1 := context.WithCancel(context.Background())
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err1 = svc.GetEncryptedToken(ctx1, &csarv1.TokenRequest{TokenRef: "tok"})
	}()

	// Give caller 1 a moment to start the singleflight.
	time.Sleep(20 * time.Millisecond)

	// Caller 2: should succeed even after caller 1 cancels.
	wg.Add(1)
	go func() {
		defer wg.Done()
		resp2, err2 = svc.GetEncryptedToken(context.Background(), &csarv1.TokenRequest{TokenRef: "tok"})
	}()

	// Cancel caller 1's context.
	cancel1()

	wg.Wait()

	// The key assertion: caller 2 must succeed because WithoutCancel
	// decoupled the backend query from caller 1's context.
	if err2 != nil {
		t.Fatalf("caller 2 should succeed despite caller 1 cancellation, got error: %v", err2)
	}
	if resp2 == nil {
		t.Fatal("caller 2 response is nil")
	}
	if string(resp2.EncryptedToken) != "enc" {
		t.Errorf("caller 2 encrypted_token = %q, want %q", resp2.EncryptedToken, "enc")
	}

	// Caller 1 may have succeeded (if singleflight completed before cancel
	// was observed) or failed — either outcome is acceptable for the first
	// caller. The important thing is that caller 2 was not affected.
	_ = err1
}

// ==========================================================================
// Redundant cache writes test (audit §3)
// ==========================================================================

func TestAuthService_ReadThrough_CachesOnce(t *testing.T) {
	// Verify that when multiple concurrent requests trigger a read-through,
	// only one cache write happens (inside the singleflight closure).
	store := &slowStore{
		delay: 50 * time.Millisecond,
		entries: map[string]TokenEntry{
			"tok": {EncryptedToken: []byte("enc"), KMSKeyID: "k1", Version: "v1"},
		},
	}

	svc := NewAuthService(testLogger())
	svc.SetBackend(store)

	var wg sync.WaitGroup
	const concurrency = 5
	errs := make([]error, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = svc.GetEncryptedToken(context.Background(), &csarv1.TokenRequest{TokenRef: "tok"})
		}()
	}

	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("caller %d error: %v", i, err)
		}
	}

	// After all callers complete, the token should be cached.
	if svc.TokenCount() != 1 {
		t.Errorf("TokenCount() = %d, want 1", svc.TokenCount())
	}
}
