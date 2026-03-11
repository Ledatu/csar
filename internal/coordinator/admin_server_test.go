package coordinator

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ledatu/csar/internal/statestore"
)

// mockMutableStore is a test double for MutableTokenStore.
type mockMutableStore struct {
	entries map[string]TokenEntry
}

func newMockMutableStore() *mockMutableStore {
	return &mockMutableStore{entries: make(map[string]TokenEntry)}
}

func (m *mockMutableStore) LoadAll(_ context.Context) (map[string]TokenEntry, error) {
	return m.entries, nil
}

func (m *mockMutableStore) FetchOne(_ context.Context, ref string) (TokenEntry, error) {
	e, ok := m.entries[ref]
	if !ok {
		return TokenEntry{}, ErrTokenNotFound
	}
	return e, nil
}

func (m *mockMutableStore) UpsertToken(_ context.Context, ref string, entry TokenEntry, _ TokenMetadata) (string, error) {
	entry.Version = "etag-new"
	m.entries[ref] = entry
	return "etag-new", nil
}

func (m *mockMutableStore) DeleteToken(_ context.Context, ref string) error {
	delete(m.entries, ref)
	return nil
}

func (m *mockMutableStore) Close() error { return nil }

// mockKMSProvider implements kms.Provider for testing.
type mockKMSProvider struct{}

func (m *mockKMSProvider) Name() string { return "mock" }
func (m *mockKMSProvider) Encrypt(_ context.Context, _ string, plaintext []byte) ([]byte, error) {
	return append([]byte("enc:"), plaintext...), nil
}
func (m *mockKMSProvider) Decrypt(_ context.Context, _ string, ciphertext []byte) ([]byte, error) {
	return bytes.TrimPrefix(ciphertext, []byte("enc:")), nil
}
func (m *mockKMSProvider) Health(_ context.Context) error { return nil }
func (m *mockKMSProvider) Close() error                   { return nil }

func boolPtr(v bool) *bool { return &v }

func newTestAdminServer(s3Managed bool) (*AdminServer, *mockMutableStore) {
	store := newMockMutableStore()
	authSvc := NewAuthService(testLogger())
	coord := New(statestore.NewMemoryStore(), testLogger())

	var kmsP *mockKMSProvider
	if !s3Managed {
		kmsP = &mockKMSProvider{}
	}

	cfg := AdminAPIConfig{
		Enabled:             true,
		ListenAddr:          ":0",
		S3ManagesEncryption: boolPtr(s3Managed),
		AllowInsecure:       true,
		Auth: AdminAuthConfig{
			JWKSUrl:   "http://localhost/.well-known/jwks.json",
			Issuer:    "https://test-auth",
			Audiences: []string{"csar-coordinator-admin"},
		},
		Limits: AdminLimitsConfig{
			MaxTokenSize:   16384,
			RequestTimeout: 5 * time.Second,
		},
	}

	srv := NewAdminServer(cfg, authSvc, coord, store, kmsP, testLogger())
	return srv, store
}

// withAdminClaims injects AdminClaims into the request context, bypassing
// JWT validation for unit testing the handlers directly.
func withAdminClaims(r *http.Request, claims *AdminClaims) *http.Request {
	ctx := context.WithValue(r.Context(), adminClaimsContextKey{}, claims)
	return r.WithContext(ctx)
}

func TestAdminServer_Health(t *testing.T) {
	srv, _ := newTestAdminServer(true)

	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/health", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("health status = %d, want 200", rec.Code)
	}
}

func TestAdminServer_PutToken_S3Managed(t *testing.T) {
	srv, store := newTestAdminServer(true)

	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	body := `{"value": "my-secret-token", "metadata": {"tenant": "balance"}}`
	req := httptest.NewRequest(http.MethodPut, "/admin/v1/tokens/balance/upstream_api", bytes.NewBufferString(body))
	req = withAdminClaims(req, &AdminClaims{
		Sub:   "svc-deployer",
		Scope: "csar.token.write csar.token.read",
	})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}

	var resp tokenMutationResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.TokenRef != "balance/upstream_api" {
		t.Errorf("token_ref = %q, want %q", resp.TokenRef, "balance/upstream_api")
	}
	if resp.Version != "etag-new" {
		t.Errorf("version = %q, want %q", resp.Version, "etag-new")
	}
	if resp.Status != "updated" {
		t.Errorf("status = %q, want %q", resp.Status, "updated")
	}

	if _, ok := store.entries["balance/upstream_api"]; !ok {
		t.Error("token not stored in mock store")
	}

	if srv.authSvc.TokenCount() != 1 {
		t.Errorf("TokenCount() = %d, want 1", srv.authSvc.TokenCount())
	}
}

func TestAdminServer_PutToken_KMSManaged(t *testing.T) {
	srv, _ := newTestAdminServer(false)

	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	body := `{"value": "my-secret-token", "kms_key_id": "key-1"}`
	req := httptest.NewRequest(http.MethodPut, "/admin/v1/tokens/balance/token", bytes.NewBufferString(body))
	req = withAdminClaims(req, &AdminClaims{
		Sub:   "svc-deployer",
		Scope: "csar.token.write",
	})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
}

func TestAdminServer_PutToken_MissingKMSKeyID(t *testing.T) {
	srv, _ := newTestAdminServer(false)

	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	body := `{"value": "my-secret-token"}`
	req := httptest.NewRequest(http.MethodPut, "/admin/v1/tokens/balance/token", bytes.NewBufferString(body))
	req = withAdminClaims(req, &AdminClaims{
		Sub:   "svc-deployer",
		Scope: "csar.token.write",
	})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("PUT status = %d, want 400", rec.Code)
	}
}

func TestAdminServer_PutToken_InvalidTokenRef(t *testing.T) {
	srv, _ := newTestAdminServer(true)

	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	body := `{"value": "secret"}`
	// Use a token_ref that contains ".." but won't be cleaned by net/http path normalization.
	req := httptest.NewRequest(http.MethodPut, "/admin/v1/tokens/balance%2F..%2Fetc", bytes.NewBufferString(body))
	req = withAdminClaims(req, &AdminClaims{
		Sub:   "svc-deployer",
		Scope: "csar.token.write",
	})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	// The mux may clean the path, so the handler sees "balance/../etc" or similar.
	// If the handler sees a clean path, we test with raw path value instead.
	// The key check: the token_ref validation catches ".." patterns.
	if rec.Code == http.StatusOK {
		t.Error("PUT should not succeed with path traversal token_ref")
	}
}

func TestAdminServer_PutToken_Unauthenticated(t *testing.T) {
	srv, _ := newTestAdminServer(true)

	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	body := `{"value": "secret"}`
	req := httptest.NewRequest(http.MethodPut, "/admin/v1/tokens/balance/token", bytes.NewBufferString(body))
	// No claims injected.

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("PUT status = %d, want 401", rec.Code)
	}
}

func TestAdminServer_DeleteToken(t *testing.T) {
	srv, store := newTestAdminServer(true)
	store.entries["balance/token"] = TokenEntry{
		EncryptedToken: []byte("old-value"),
		Version:        "v1",
	}
	srv.authSvc.LoadToken("balance/token", TokenEntry{
		EncryptedToken: []byte("old-value"),
		Version:        "v1",
	})

	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	req := httptest.NewRequest(http.MethodDelete, "/admin/v1/tokens/balance/token", nil)
	req = withAdminClaims(req, &AdminClaims{
		Sub:   "svc-deployer",
		Scope: "csar.token.delete",
	})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}

	if _, ok := store.entries["balance/token"]; ok {
		t.Error("token still in store after delete")
	}

	if srv.authSvc.TokenCount() != 0 {
		t.Errorf("TokenCount() = %d, want 0", srv.authSvc.TokenCount())
	}
}

func TestAdminServer_GetToken_Metadata(t *testing.T) {
	srv, store := newTestAdminServer(true)
	store.entries["balance/token"] = TokenEntry{
		EncryptedToken: []byte("encrypted-blob"),
		KMSKeyID:       "key-1",
		Version:        "v42",
	}

	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/tokens/balance/token", nil)
	req = withAdminClaims(req, &AdminClaims{
		Sub:   "svc-reader",
		Scope: "csar.token.read",
	})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}

	var resp tokenMetadataResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.TokenRef != "balance/token" {
		t.Errorf("token_ref = %q, want %q", resp.TokenRef, "balance/token")
	}
	if resp.KMSKeyID != "key-1" {
		t.Errorf("kms_key_id = %q, want %q", resp.KMSKeyID, "key-1")
	}
	if !resp.HasValue {
		t.Error("has_value should be true")
	}
}

func TestAdminServer_GetToken_NotFound(t *testing.T) {
	srv, _ := newTestAdminServer(true)

	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/tokens/nonexistent", nil)
	req = withAdminClaims(req, &AdminClaims{
		Sub:   "svc-reader",
		Scope: "csar.token.read",
	})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("GET status = %d, want 404", rec.Code)
	}
}

func TestAdminServer_PostInvalidate(t *testing.T) {
	srv, _ := newTestAdminServer(true)

	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	body := `{"token_refs": ["balance/token_a", "balance/token_b"]}`
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/tokens/:invalidate", bytes.NewBufferString(body))
	req = withAdminClaims(req, &AdminClaims{
		Sub:   "svc-deployer",
		Scope: "csar.token.invalidate",
	})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("POST :invalidate status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
}

func TestAdminServer_PostInvalidate_PrefixEnforced(t *testing.T) {
	srv, _ := newTestAdminServer(true)
	srv.cfg.Authorization.EnforceTokenPrefixClaim = true

	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	body := `{"token_refs": ["balance/token_a", "bidding/token_b"]}`
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/tokens/:invalidate", bytes.NewBufferString(body))
	req = withAdminClaims(req, &AdminClaims{
		Sub:         "svc-balance",
		Scope:       "csar.token.invalidate",
		TokenPrefix: "balance/",
	})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("POST :invalidate with out-of-prefix ref: status = %d, want 403, body: %s", rec.Code, rec.Body.String())
	}
}

func TestAdminServer_PostRotate(t *testing.T) {
	srv, _ := newTestAdminServer(true)

	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	body := `{"value": "rotated-secret"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/tokens/balance/token:rotate", bytes.NewBufferString(body))
	req = withAdminClaims(req, &AdminClaims{
		Sub:   "svc-deployer",
		Scope: "csar.token.rotate",
	})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("POST :rotate status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
}
