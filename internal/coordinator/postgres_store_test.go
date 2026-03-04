package coordinator

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"

	csarv1 "github.com/ledatu/csar/proto/csar/v1"
)

// tokenReq is a test helper that creates a TokenRequest.
func tokenReq(ref string) *csarv1.TokenRequest {
	return &csarv1.TokenRequest{TokenRef: ref}
}

func TestPostgresTokenStore_RefreshAndDiff_DetectsChanges(t *testing.T) {
	// This test validates the diff logic using the AuthServiceImpl in-memory store.
	// It does NOT require a real PostgreSQL connection — we test the diff/version
	// tracking by calling LoadTokensFromMap directly and verifying the coordinator
	// integration.

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	authSvc := NewAuthService(logger)

	// Simulate initial token load (as if from PG).
	initial := map[string]TokenEntry{
		"api_token_shop1": {
			EncryptedToken: []byte("enc-blob-1"),
			KMSKeyID:       "key-aaa",
			Version:        "1",
		},
		"api_token_shop2": {
			EncryptedToken: []byte("enc-blob-2"),
			KMSKeyID:       "key-bbb",
			Version:        "1",
		},
	}
	loaded := authSvc.LoadTokensFromMap(initial)
	if loaded != 2 {
		t.Fatalf("expected 2 loaded, got %d", loaded)
	}

	// Verify tokens are served correctly.
	resp, err := authSvc.GetEncryptedToken(context.Background(), tokenReq("api_token_shop1"))
	if err != nil {
		t.Fatalf("GetEncryptedToken: %v", err)
	}
	if string(resp.EncryptedToken) != "enc-blob-1" {
		t.Errorf("encrypted_token = %q, want %q", resp.EncryptedToken, "enc-blob-1")
	}
	if resp.KmsKeyId != "key-aaa" {
		t.Errorf("kms_key_id = %q, want %q", resp.KmsKeyId, "key-aaa")
	}

	// Simulate a token rotation: version bump on shop1, shop2 unchanged.
	updated := map[string]TokenEntry{
		"api_token_shop1": {
			EncryptedToken: []byte("enc-blob-1-rotated"),
			KMSKeyID:       "key-aaa",
			Version:        "2", // bumped
		},
		"api_token_shop2": {
			EncryptedToken: []byte("enc-blob-2"),
			KMSKeyID:       "key-bbb",
			Version:        "1", // unchanged
		},
	}
	loaded2 := authSvc.LoadTokensFromMap(updated)
	if loaded2 != 2 {
		t.Fatalf("expected 2 loaded on update, got %d", loaded2)
	}

	// Verify rotated token is served.
	resp2, err := authSvc.GetEncryptedToken(context.Background(), tokenReq("api_token_shop1"))
	if err != nil {
		t.Fatalf("GetEncryptedToken after rotation: %v", err)
	}
	if string(resp2.EncryptedToken) != "enc-blob-1-rotated" {
		t.Errorf("encrypted_token = %q, want %q", resp2.EncryptedToken, "enc-blob-1-rotated")
	}
	if resp2.Version != "2" {
		t.Errorf("version = %q, want %q", resp2.Version, "2")
	}
}

func TestPostgresTokenStore_EmptyStore(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	authSvc := NewAuthService(logger)

	// Empty map should result in zero loaded tokens.
	loaded := authSvc.LoadTokensFromMap(map[string]TokenEntry{})
	if loaded != 0 {
		t.Fatalf("expected 0 loaded, got %d", loaded)
	}

	if authSvc.TokenCount() != 0 {
		t.Fatalf("expected 0 tokens, got %d", authSvc.TokenCount())
	}
}

func TestPostgresTokenStore_SkipsInvalidEntries(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	authSvc := NewAuthService(logger)

	entries := map[string]TokenEntry{
		"good_token": {
			EncryptedToken: []byte("enc-blob"),
			KMSKeyID:       "key-1",
			Version:        "1",
		},
		"empty_blob": {
			EncryptedToken: []byte{}, // empty — should be skipped
			KMSKeyID:       "key-2",
			Version:        "1",
		},
		"no_key": {
			EncryptedToken: []byte("enc-blob-2"),
			KMSKeyID:       "", // empty — should be skipped
			Version:        "1",
		},
	}

	loaded := authSvc.LoadTokensFromMap(entries)
	if loaded != 1 {
		t.Fatalf("expected 1 loaded (2 skipped), got %d", loaded)
	}
}

func TestNewPostgresTokenStore_NilDB(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	store := NewPostgresTokenStore(nil, logger)
	if store == nil {
		t.Fatal("expected non-nil store")
	}
}

// --- TokenRefresher tests ---

func TestTokenRefresher_DetectsAddedUpdatedRemoved(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	authSvc := NewAuthService(logger)

	store := &mockTokenStore{
		tokens: map[string]TokenEntry{
			"token_a": {EncryptedToken: []byte("enc-a"), KMSKeyID: "k1", Version: "1"},
			"token_b": {EncryptedToken: []byte("enc-b"), KMSKeyID: "k2", Version: "1"},
		},
	}

	refresher := NewTokenRefresher(store, logger)

	// Initial load + seed.
	entries, _ := store.LoadAll(context.Background())
	authSvc.LoadTokensFromMap(entries)
	refresher.SeedVersions(entries)

	// Simulate changes: token_a updated, token_b removed, token_c added.
	store.tokens = map[string]TokenEntry{
		"token_a": {EncryptedToken: []byte("enc-a-v2"), KMSKeyID: "k1", Version: "2"},
		"token_c": {EncryptedToken: []byte("enc-c"), KMSKeyID: "k3", Version: "1"},
	}

	changed, err := refresher.RefreshAndDiff(context.Background(), authSvc)
	if err != nil {
		t.Fatalf("RefreshAndDiff: %v", err)
	}

	// Should detect 3 changes: token_a (updated), token_b (removed), token_c (added).
	if len(changed) != 3 {
		t.Fatalf("expected 3 changed, got %d: %v", len(changed), changed)
	}

	changedSet := make(map[string]bool)
	for _, ref := range changed {
		changedSet[ref] = true
	}
	for _, expected := range []string{"token_a", "token_b", "token_c"} {
		if !changedSet[expected] {
			t.Errorf("expected %q in changed set, got %v", expected, changed)
		}
	}

	// Verify token_b was removed from AuthService.
	_, err = authSvc.GetEncryptedToken(context.Background(), tokenReq("token_b"))
	if err == nil {
		t.Error("expected NotFound for removed token_b")
	}

	// Verify token_c is now available.
	resp, err := authSvc.GetEncryptedToken(context.Background(), tokenReq("token_c"))
	if err != nil {
		t.Fatalf("expected token_c to be available: %v", err)
	}
	if string(resp.EncryptedToken) != "enc-c" {
		t.Errorf("token_c encrypted_token = %q, want %q", resp.EncryptedToken, "enc-c")
	}

	// Verify token_a was updated.
	respA, err := authSvc.GetEncryptedToken(context.Background(), tokenReq("token_a"))
	if err != nil {
		t.Fatalf("expected token_a to be available: %v", err)
	}
	if string(respA.EncryptedToken) != "enc-a-v2" {
		t.Errorf("token_a encrypted_token = %q, want %q", respA.EncryptedToken, "enc-a-v2")
	}
}

func TestTokenRefresher_NoChanges(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	authSvc := NewAuthService(logger)

	store := &mockTokenStore{
		tokens: map[string]TokenEntry{
			"token_a": {EncryptedToken: []byte("enc-a"), KMSKeyID: "k1", Version: "1"},
		},
	}

	refresher := NewTokenRefresher(store, logger)
	entries, _ := store.LoadAll(context.Background())
	authSvc.LoadTokensFromMap(entries)
	refresher.SeedVersions(entries)

	// Refresh with no changes.
	changed, err := refresher.RefreshAndDiff(context.Background(), authSvc)
	if err != nil {
		t.Fatalf("RefreshAndDiff: %v", err)
	}
	if len(changed) != 0 {
		t.Errorf("expected 0 changed, got %d: %v", len(changed), changed)
	}
}

// --- Read-through (TokenStore) tests ---

// mockTokenStore implements TokenStore for testing the read-through path
// and TokenRefresher logic without requiring a real database.
type mockTokenStore struct {
	tokens map[string]TokenEntry
	closed bool
}

func (m *mockTokenStore) LoadAll(_ context.Context) (map[string]TokenEntry, error) {
	result := make(map[string]TokenEntry, len(m.tokens))
	for k, v := range m.tokens {
		result[k] = v
	}
	return result, nil
}

func (m *mockTokenStore) FetchOne(_ context.Context, tokenRef string) (TokenEntry, error) {
	entry, ok := m.tokens[tokenRef]
	if !ok {
		return TokenEntry{}, fmt.Errorf("token ref %q: %w", tokenRef, ErrTokenNotFound)
	}
	return entry, nil
}

func (m *mockTokenStore) Close() error {
	m.closed = true
	return nil
}

func TestAuthService_ReadThrough_CacheMiss(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	authSvc := NewAuthService(logger)

	// Backend has a token that the in-memory store doesn't.
	backend := &mockTokenStore{
		tokens: map[string]TokenEntry{
			"api_token_new_seller": {
				EncryptedToken: []byte("enc-new"),
				KMSKeyID:       "key-xyz",
				Version:        "1",
			},
		},
	}
	authSvc.SetBackend(backend)

	// First request — should read-through to backend.
	resp, err := authSvc.GetEncryptedToken(context.Background(), tokenReq("api_token_new_seller"))
	if err != nil {
		t.Fatalf("expected read-through to succeed, got: %v", err)
	}
	if string(resp.EncryptedToken) != "enc-new" {
		t.Errorf("encrypted_token = %q, want %q", resp.EncryptedToken, "enc-new")
	}
	if resp.KmsKeyId != "key-xyz" {
		t.Errorf("kms_key_id = %q, want %q", resp.KmsKeyId, "key-xyz")
	}

	// Second request — should be served from cache (no backend hit).
	// Remove from backend to prove it comes from cache.
	delete(backend.tokens, "api_token_new_seller")

	resp2, err := authSvc.GetEncryptedToken(context.Background(), tokenReq("api_token_new_seller"))
	if err != nil {
		t.Fatalf("expected cached response, got: %v", err)
	}
	if string(resp2.EncryptedToken) != "enc-new" {
		t.Errorf("cached encrypted_token = %q, want %q", resp2.EncryptedToken, "enc-new")
	}
}

func TestAuthService_ReadThrough_BackendMiss_ReturnsNotFound(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	authSvc := NewAuthService(logger)

	// Backend has no tokens — FetchOne returns ErrTokenNotFound.
	backend := &mockTokenStore{tokens: map[string]TokenEntry{}}
	authSvc.SetBackend(backend)

	// Should return gRPC NotFound when neither cache nor backend has it.
	_, err := authSvc.GetEncryptedToken(context.Background(), tokenReq("api_token_nonexistent"))
	if err == nil {
		t.Fatal("expected NotFound error, got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected NotFound in error message, got: %v", err)
	}
}

func TestAuthService_ReadThrough_TransientError_ReturnsUnavailable(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	authSvc := NewAuthService(logger)

	// Backend that returns a transient error (not ErrTokenNotFound).
	backend := &failingTokenStore{err: fmt.Errorf("connection refused")}
	authSvc.SetBackend(backend)

	_, err := authSvc.GetEncryptedToken(context.Background(), tokenReq("api_token_x"))
	if err == nil {
		t.Fatal("expected Unavailable error, got nil")
	}
	if !strings.Contains(err.Error(), "temporarily unavailable") {
		t.Errorf("expected Unavailable in error message, got: %v", err)
	}
}

// failingTokenStore is a TokenStore that always returns an error from FetchOne.
type failingTokenStore struct {
	err error
}

func (f *failingTokenStore) LoadAll(_ context.Context) (map[string]TokenEntry, error) {
	return nil, f.err
}
func (f *failingTokenStore) FetchOne(_ context.Context, _ string) (TokenEntry, error) {
	return TokenEntry{}, f.err
}
func (f *failingTokenStore) Close() error { return nil }

func TestAuthService_ReadThrough_NoBackend(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	authSvc := NewAuthService(logger)

	// No backend configured — should return NotFound on cache miss.
	_, err := authSvc.GetEncryptedToken(context.Background(), tokenReq("api_token_missing"))
	if err == nil {
		t.Fatal("expected NotFound error, got nil")
	}
}

func TestAuthService_RemoveToken(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	authSvc := NewAuthService(logger)

	authSvc.LoadToken("api_token_to_remove", TokenEntry{
		EncryptedToken: []byte("enc-blob"),
		KMSKeyID:       "key-1",
		Version:        "1",
	})

	// Verify it's there.
	if authSvc.TokenCount() != 1 {
		t.Fatalf("expected 1 token, got %d", authSvc.TokenCount())
	}

	// Remove it.
	authSvc.RemoveToken("api_token_to_remove")
	if authSvc.TokenCount() != 0 {
		t.Fatalf("expected 0 tokens after removal, got %d", authSvc.TokenCount())
	}

	// GetEncryptedToken should return NotFound.
	_, err := authSvc.GetEncryptedToken(context.Background(), tokenReq("api_token_to_remove"))
	if err == nil {
		t.Fatal("expected NotFound error after removal")
	}
}
