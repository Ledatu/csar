package coordinator

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ledatu/csar/internal/statestore"
)

func newTestSvcServer(s3Managed bool, prefixMap map[string]string) (*AdminServer, *mockMutableStore) {
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
		Svc: SvcAPIConfig{PrefixMap: prefixMap},
	}

	srv := NewAdminServer(cfg, authSvc, coord, store, kmsP, testLogger())
	return srv, store
}

func svcRequest(method, path, body, subject string) *http.Request {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, bytes.NewBufferString(body))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	if subject != "" {
		r.Header.Set("X-Gateway-Subject", subject)
	}
	return r
}

func TestSvcPutToken_HappyPath(t *testing.T) {
	srv, store := newTestSvcServer(true, map[string]string{
		"svc:campaigns": "campaigns/",
	})

	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	req := svcRequest(http.MethodPut, "/svc/tokens/campaigns/wb/s1/api_token",
		`{"value":"secret-tok"}`, "svc:campaigns")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}

	var resp tokenMutationResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.TokenRef != "campaigns/wb/s1/api_token" {
		t.Errorf("token_ref = %q, want %q", resp.TokenRef, "campaigns/wb/s1/api_token")
	}
	if resp.Status != "updated" {
		t.Errorf("status = %q, want %q", resp.Status, "updated")
	}
	if _, ok := store.entries["campaigns/wb/s1/api_token"]; !ok {
		t.Error("token not stored")
	}
	if srv.authSvc.TokenCount() != 1 {
		t.Errorf("TokenCount() = %d, want 1", srv.authSvc.TokenCount())
	}
}

func TestSvcDeleteToken_HappyPath(t *testing.T) {
	srv, store := newTestSvcServer(true, map[string]string{
		"svc:campaigns": "campaigns/",
	})
	store.entries["campaigns/wb/s1/api_token"] = TokenEntry{
		EncryptedToken: []byte("old"), Version: "v1",
	}
	srv.authSvc.LoadToken("campaigns/wb/s1/api_token", TokenEntry{
		EncryptedToken: []byte("old"), Version: "v1",
	})

	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	req := svcRequest(http.MethodDelete, "/svc/tokens/campaigns/wb/s1/api_token",
		"", "svc:campaigns")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	if _, ok := store.entries["campaigns/wb/s1/api_token"]; ok {
		t.Error("token still in store after delete")
	}
	if srv.authSvc.TokenCount() != 0 {
		t.Errorf("TokenCount() = %d, want 0", srv.authSvc.TokenCount())
	}
}

func TestSvcPutToken_MissingSubject(t *testing.T) {
	srv, _ := newTestSvcServer(true, map[string]string{
		"svc:campaigns": "campaigns/",
	})

	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	req := svcRequest(http.MethodPut, "/svc/tokens/campaigns/wb/s1/api_token",
		`{"value":"tok"}`, "")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("PUT status = %d, want 401, body: %s", rec.Code, rec.Body.String())
	}
}

func TestSvcPutToken_UnknownSubject(t *testing.T) {
	srv, _ := newTestSvcServer(true, map[string]string{
		"svc:campaigns": "campaigns/",
	})

	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	req := svcRequest(http.MethodPut, "/svc/tokens/campaigns/wb/s1/api_token",
		`{"value":"tok"}`, "svc:unknown")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("PUT status = %d, want 403, body: %s", rec.Code, rec.Body.String())
	}
}

func TestSvcPutToken_PrefixEnforced(t *testing.T) {
	srv, _ := newTestSvcServer(true, map[string]string{
		"svc:campaigns": "campaigns/",
	})

	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	req := svcRequest(http.MethodPut, "/svc/tokens/other/wb/s1/api_token",
		`{"value":"tok"}`, "svc:campaigns")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("PUT status = %d, want 403 (out-of-prefix), body: %s", rec.Code, rec.Body.String())
	}
}

func TestSvcPutToken_InvalidTokenRef(t *testing.T) {
	srv, _ := newTestSvcServer(true, map[string]string{
		"svc:campaigns": "campaigns/",
	})

	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	req := svcRequest(http.MethodPut, "/svc/tokens/campaigns/wb/../etc",
		`{"value":"tok"}`, "svc:campaigns")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Error("PUT should not succeed with path-traversal token_ref")
	}
}

func TestSvcPutToken_EmptyValue(t *testing.T) {
	srv, _ := newTestSvcServer(true, map[string]string{
		"svc:campaigns": "campaigns/",
	})

	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	req := svcRequest(http.MethodPut, "/svc/tokens/campaigns/wb/s1/api_token",
		`{"value":""}`, "svc:campaigns")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("PUT status = %d, want 400, body: %s", rec.Code, rec.Body.String())
	}
}

func TestSvcPutToken_RejectsKMSMode(t *testing.T) {
	srv, _ := newTestSvcServer(false, map[string]string{
		"svc:campaigns": "campaigns/",
	})

	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	req := svcRequest(http.MethodPut, "/svc/tokens/campaigns/wb/s1/api_token",
		`{"value":"tok"}`, "svc:campaigns")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("PUT status = %d, want 503 (KMS mode unsupported), body: %s", rec.Code, rec.Body.String())
	}
}

func TestSvcPutToken_NoPrefixMapDisablesRoutes(t *testing.T) {
	srv, _ := newTestSvcServer(true, nil)

	mux := http.NewServeMux()
	srv.registerRoutes(mux)

	req := svcRequest(http.MethodPut, "/svc/tokens/campaigns/wb/s1/api_token",
		`{"value":"tok"}`, "svc:campaigns")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("PUT status = %d, want 404/405 (routes not registered), body: %s", rec.Code, rec.Body.String())
	}
}
