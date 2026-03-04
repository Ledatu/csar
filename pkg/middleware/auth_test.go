package middleware

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ledatu/csar/internal/kms"
)

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestAuthInjector_InjectsToken(t *testing.T) {
	// Set up KMS
	provider, _ := kms.NewLocalProvider(map[string]string{"key1": "test-pass"})

	// Encrypt a test token
	encToken, _ := provider.Encrypt(context.Background(), "key1", []byte("my-secret-api-token"))

	// Set up token fetcher
	fetcher := NewStaticTokenFetcher()
	fetcher.Add("api_token", encToken, "key1")

	// Create middleware
	injector := NewAuthInjector(fetcher, provider, newTestLogger())

	cfg := AuthInjectorConfig{
		TokenRef:     "api_token",
		KMSKeyID:     "key1",
		InjectHeader: "Authorization",
		InjectFormat: "Bearer {token}",
	}

	// Track what the upstream receives
	var receivedHeader string
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	})

	handler := injector.Wrap(cfg, upstream)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	if receivedHeader != "Bearer my-secret-api-token" {
		t.Errorf("Authorization = %q, want %q", receivedHeader, "Bearer my-secret-api-token")
	}
}

func TestAuthInjector_CustomHeaderAndFormat(t *testing.T) {
	provider, _ := kms.NewLocalProvider(map[string]string{"k": "pass"})
	encToken, _ := provider.Encrypt(context.Background(), "k", []byte("partner-key-123"))

	fetcher := NewStaticTokenFetcher()
	fetcher.Add("partner_token", encToken, "k")

	injector := NewAuthInjector(fetcher, provider, newTestLogger())

	cfg := AuthInjectorConfig{
		TokenRef:     "partner_token",
		KMSKeyID:     "k",
		InjectHeader: "Api-Key",
		InjectFormat: "{token}",
	}

	var receivedHeader string
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeader = r.Header.Get("Api-Key")
		w.WriteHeader(http.StatusOK)
	})

	handler := injector.Wrap(cfg, upstream)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if receivedHeader != "partner-key-123" {
		t.Errorf("Api-Key = %q, want %q", receivedHeader, "partner-key-123")
	}
}

func TestAuthInjector_NoTokenRef_PassThrough(t *testing.T) {
	provider, _ := kms.NewLocalProvider(map[string]string{"k": "pass"})
	fetcher := NewStaticTokenFetcher()
	injector := NewAuthInjector(fetcher, provider, newTestLogger())

	cfg := AuthInjectorConfig{} // Empty — no injection

	called := false
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := injector.Wrap(cfg, upstream)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("upstream should be called when no token injection needed")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestAuthInjector_TokenNotFound(t *testing.T) {
	provider, _ := kms.NewLocalProvider(map[string]string{"k": "pass"})
	fetcher := NewStaticTokenFetcher() // Empty — no tokens registered

	injector := NewAuthInjector(fetcher, provider, newTestLogger())

	cfg := AuthInjectorConfig{
		TokenRef:     "nonexistent",
		KMSKeyID:     "k",
		InjectHeader: "Authorization",
		InjectFormat: "Bearer {token}",
	}

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should NOT be called when token fetch fails")
	})

	handler := injector.Wrap(cfg, upstream)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
}

func TestAuthInjector_DecryptFails(t *testing.T) {
	provider, _ := kms.NewLocalProvider(map[string]string{"k": "pass"})

	// Store garbage as the encrypted token — decrypt will fail
	fetcher := NewStaticTokenFetcher()
	fetcher.Add("bad_token", []byte("not-valid-ciphertext-at-all-needs-to-be-long-enough"), "k")

	injector := NewAuthInjector(fetcher, provider, newTestLogger())

	cfg := AuthInjectorConfig{
		TokenRef:     "bad_token",
		KMSKeyID:     "k",
		InjectHeader: "Authorization",
		InjectFormat: "Bearer {token}",
	}

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should NOT be called when decrypt fails")
	})

	handler := injector.Wrap(cfg, upstream)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
}

func TestFormatToken(t *testing.T) {
	tests := []struct {
		format string
		token  string
		want   string
	}{
		{"Bearer {token}", "abc123", "Bearer abc123"},
		{"{token}", "abc123", "abc123"},
		{"", "abc123", "abc123"},
		{"Token {token} extra", "x", "Token x extra"},
	}

	for _, tt := range tests {
		got := formatToken(tt.format, tt.token)
		if got != tt.want {
			t.Errorf("formatToken(%q, %q) = %q, want %q", tt.format, tt.token, got, tt.want)
		}
	}
}

func TestAuthInjector_DynamicTokenRef_Query(t *testing.T) {
	provider, _ := kms.NewLocalProvider(map[string]string{"k": "pass"})

	// Register two tokens for different seller IDs.
	enc1, _ := provider.Encrypt(context.Background(), "k", []byte("seller-100-secret"))
	enc2, _ := provider.Encrypt(context.Background(), "k", []byte("seller-200-secret"))

	fetcher := NewStaticTokenFetcher()
	fetcher.Add("token_100", enc1, "k")
	fetcher.Add("token_200", enc2, "k")

	injector := NewAuthInjector(fetcher, provider, newTestLogger())

	cfg := AuthInjectorConfig{
		TokenRef:     "token_{query.seller_id}",
		KMSKeyID:     "k",
		InjectHeader: "Authorization",
		InjectFormat: "Bearer {token}",
	}

	var receivedHeader string
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	})

	handler := injector.Wrap(cfg, upstream)

	// Seller 100
	req := httptest.NewRequest(http.MethodGet, "/test?seller_id=100", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if receivedHeader != "Bearer seller-100-secret" {
		t.Errorf("Authorization = %q, want %q", receivedHeader, "Bearer seller-100-secret")
	}

	// Seller 200
	req = httptest.NewRequest(http.MethodGet, "/test?seller_id=200", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if receivedHeader != "Bearer seller-200-secret" {
		t.Errorf("Authorization = %q, want %q", receivedHeader, "Bearer seller-200-secret")
	}
}

func TestAuthInjector_DynamicTokenRef_Header(t *testing.T) {
	provider, _ := kms.NewLocalProvider(map[string]string{"k": "pass"})
	enc, _ := provider.Encrypt(context.Background(), "k", []byte("header-resolved-token"))

	fetcher := NewStaticTokenFetcher()
	fetcher.Add("token_abc", enc, "k")

	injector := NewAuthInjector(fetcher, provider, newTestLogger())

	cfg := AuthInjectorConfig{
		TokenRef:     "token_{header.X-Seller-ID}",
		KMSKeyID:     "k",
		InjectHeader: "Authorization",
		InjectFormat: "Bearer {token}",
	}

	var receivedHeader string
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	})

	handler := injector.Wrap(cfg, upstream)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Seller-ID", "abc")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if receivedHeader != "Bearer header-resolved-token" {
		t.Errorf("Authorization = %q, want %q", receivedHeader, "Bearer header-resolved-token")
	}
}

func TestAuthInjector_DynamicTokenRef_MissingParam(t *testing.T) {
	provider, _ := kms.NewLocalProvider(map[string]string{"k": "pass"})
	fetcher := NewStaticTokenFetcher()
	injector := NewAuthInjector(fetcher, provider, newTestLogger())

	cfg := AuthInjectorConfig{
		TokenRef:     "token_{query.seller_id}",
		KMSKeyID:     "k",
		InjectHeader: "Authorization",
		InjectFormat: "Bearer {token}",
	}

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should NOT be called when required param is missing")
	})

	handler := injector.Wrap(cfg, upstream)

	// Request without seller_id → should get 400
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestResolveTokenRef_Static(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	ref, err := resolveTokenRef("static_ref", req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ref != "static_ref" {
		t.Errorf("ref = %q, want %q", ref, "static_ref")
	}
}

func TestResolveTokenRef_QueryPlaceholder(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test?seller_id=42", nil)
	ref, err := resolveTokenRef("token_{query.seller_id}", req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ref != "token_42" {
		t.Errorf("ref = %q, want %q", ref, "token_42")
	}
}

func TestResolveTokenRef_HeaderPlaceholder(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Tenant", "acme")
	ref, err := resolveTokenRef("tenant_{header.X-Tenant}", req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ref != "tenant_acme" {
		t.Errorf("ref = %q, want %q", ref, "tenant_acme")
	}
}

func TestResolveTokenRef_MissingParam_Error(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil) // no query params
	_, err := resolveTokenRef("token_{query.seller_id}", req)
	if err == nil {
		t.Fatal("expected error for missing query param")
	}
}

func TestStaticTokenFetcher(t *testing.T) {
	f := NewStaticTokenFetcher()
	f.Add("ref1", []byte("encrypted1"), "key1")
	f.Add("ref2", []byte("encrypted2"), "key2")

	enc, keyID, _, err := f.GetEncryptedToken(context.Background(), "ref1")
	if err != nil {
		t.Fatalf("GetEncryptedToken: %v", err)
	}
	if string(enc) != "encrypted1" || keyID != "key1" {
		t.Errorf("ref1: got (%q, %q), want (%q, %q)", enc, keyID, "encrypted1", "key1")
	}

	_, _, _, err = f.GetEncryptedToken(context.Background(), "nonexistent")
	if err == nil {
		t.Error("GetEncryptedToken for nonexistent ref should fail")
	}
}

// ==========================================================================
// Strip Token Params tests (Feature B)
// ==========================================================================

func TestStripReferencedQueryParams(t *testing.T) {
	tests := []struct {
		name     string
		tokenRef string
		url      string
		wantURL  string
	}{
		{
			name:     "strips query param used in token_ref",
			tokenRef: "token_{query.seller_id}",
			url:      "/test?seller_id=42&page=1",
			wantURL:  "page=1",
		},
		{
			name:     "strips multiple query params",
			tokenRef: "token_{query.seller_id}_{query.region}",
			url:      "/test?seller_id=42&region=eu&page=1",
			wantURL:  "page=1",
		},
		{
			name:     "does not strip header params",
			tokenRef: "token_{header.X-Seller}",
			url:      "/test?seller_id=42",
			wantURL:  "seller_id=42",
		},
		{
			name:     "no placeholders",
			tokenRef: "static_ref",
			url:      "/test?seller_id=42",
			wantURL:  "seller_id=42",
		},
		{
			name:     "strips all params — empty query",
			tokenRef: "token_{query.seller_id}",
			url:      "/test?seller_id=42",
			wantURL:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.url, nil)
			stripReferencedQueryParams(tt.tokenRef, req)
			if req.URL.RawQuery != tt.wantURL {
				t.Errorf("RawQuery = %q, want %q", req.URL.RawQuery, tt.wantURL)
			}
		})
	}
}

func TestCollectQueryPlaceholders(t *testing.T) {
	keys := CollectQueryPlaceholders(
		"token_{query.seller_id}",
		"other_{query.region}_{header.X-Tenant}",
		"static_ref",
	)
	if _, ok := keys["seller_id"]; !ok {
		t.Error("expected seller_id in collected keys")
	}
	if _, ok := keys["region"]; !ok {
		t.Error("expected region in collected keys")
	}
	// header placeholders should NOT appear
	if _, ok := keys["X-Tenant"]; ok {
		t.Error("header placeholder X-Tenant should not be collected")
	}
	if len(keys) != 2 {
		t.Errorf("expected 2 keys, got %d: %v", len(keys), keys)
	}
}

func TestStripQueryKeys(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test?seller_id=42&region=eu&page=1", nil)
	keys := map[string]struct{}{"seller_id": {}, "region": {}}
	StripQueryKeys(req, keys)
	if req.URL.RawQuery != "page=1" {
		t.Errorf("RawQuery = %q, want %q", req.URL.RawQuery, "page=1")
	}
}

func TestStripQueryKeys_Empty(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test?seller_id=42", nil)
	StripQueryKeys(req, nil)
	if req.URL.RawQuery != "seller_id=42" {
		t.Errorf("RawQuery = %q, want %q (should be unchanged)", req.URL.RawQuery, "seller_id=42")
	}
}

// TestStripTokenParams_SingleCredential_EndToEnd exercises the full pipeline:
// collect placeholders → inject credential → strip once.
func TestStripTokenParams_SingleCredential_EndToEnd(t *testing.T) {
	provider, _ := kms.NewLocalProvider(map[string]string{"k": "pass"})
	enc, _ := provider.Encrypt(context.Background(), "k", []byte("secret"))

	fetcher := NewStaticTokenFetcher()
	fetcher.Add("token_42", enc, "k")

	injector := NewAuthInjector(fetcher, provider, newTestLogger())

	cfg := AuthInjectorConfig{
		TokenRef:     "token_{query.seller_id}",
		KMSKeyID:     "k",
		InjectHeader: "Authorization",
		InjectFormat: "Bearer {token}",
	}

	// Collect keys and strip after all credentials are injected.
	stripKeys := CollectQueryPlaceholders(cfg.TokenRef)

	var receivedQuery string
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
	})

	// Chain: Wrap → strip → upstream
	stripped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		StripQueryKeys(r, stripKeys)
		upstream.ServeHTTP(w, r)
	})
	handler := injector.Wrap(cfg, stripped)

	req := httptest.NewRequest(http.MethodGet, "/test?seller_id=42&page=1", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if receivedQuery != "page=1" {
		t.Errorf("query = %q, want %q (seller_id should be stripped)", receivedQuery, "page=1")
	}
}

// TestStripTokenParams_MultiCredential_SameQueryParam tests the critical
// multi-credential scenario: both entries reference {query.seller_id}.
// With the old per-Wrap stripping, entry B would fail because entry A
// already stripped seller_id. With collect-then-strip, both succeed.
func TestStripTokenParams_MultiCredential_SameQueryParam(t *testing.T) {
	provider, _ := kms.NewLocalProvider(map[string]string{"k": "pass"})
	enc1, _ := provider.Encrypt(context.Background(), "k", []byte("bearer-secret"))
	enc2, _ := provider.Encrypt(context.Background(), "k", []byte("client-secret"))

	fetcher := NewStaticTokenFetcher()
	fetcher.Add("bearer_42", enc1, "k")
	fetcher.Add("client_42", enc2, "k")

	injector := NewAuthInjector(fetcher, provider, newTestLogger())

	cfgA := AuthInjectorConfig{
		TokenRef:     "bearer_{query.seller_id}",
		KMSKeyID:     "k",
		InjectHeader: "Authorization",
		InjectFormat: "Bearer {token}",
	}
	cfgB := AuthInjectorConfig{
		TokenRef:     "client_{query.seller_id}",
		KMSKeyID:     "k",
		InjectHeader: "X-Client-Secret",
		InjectFormat: "{token}",
	}

	// Collect from both entries.
	stripKeys := CollectQueryPlaceholders(cfgA.TokenRef, cfgB.TokenRef)

	var receivedAuth, receivedSecret, receivedQuery string
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		receivedSecret = r.Header.Get("X-Client-Secret")
		receivedQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
	})

	// Chain: cfgA → cfgB → strip → upstream
	stripped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		StripQueryKeys(r, stripKeys)
		upstream.ServeHTTP(w, r)
	})
	handler := injector.Wrap(cfgA, injector.Wrap(cfgB, stripped))

	req := httptest.NewRequest(http.MethodGet, "/test?seller_id=42&page=1", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if receivedAuth != "Bearer bearer-secret" {
		t.Errorf("Authorization = %q, want %q", receivedAuth, "Bearer bearer-secret")
	}
	if receivedSecret != "client-secret" {
		t.Errorf("X-Client-Secret = %q, want %q", receivedSecret, "client-secret")
	}
	if receivedQuery != "page=1" {
		t.Errorf("query = %q, want %q (seller_id stripped once after both injections)", receivedQuery, "page=1")
	}
}

// TestStripTokenParams_MultiCredential_DifferentQueryParams tests two entries
// using different {query.*} params — both get stripped after injection.
func TestStripTokenParams_MultiCredential_DifferentQueryParams(t *testing.T) {
	provider, _ := kms.NewLocalProvider(map[string]string{"k": "pass"})
	enc1, _ := provider.Encrypt(context.Background(), "k", []byte("seller-secret"))
	enc2, _ := provider.Encrypt(context.Background(), "k", []byte("region-secret"))

	fetcher := NewStaticTokenFetcher()
	fetcher.Add("bearer_42", enc1, "k")
	fetcher.Add("region_eu", enc2, "k")

	injector := NewAuthInjector(fetcher, provider, newTestLogger())

	cfgA := AuthInjectorConfig{
		TokenRef:     "bearer_{query.seller_id}",
		KMSKeyID:     "k",
		InjectHeader: "Authorization",
		InjectFormat: "Bearer {token}",
	}
	cfgB := AuthInjectorConfig{
		TokenRef:     "region_{query.region}",
		KMSKeyID:     "k",
		InjectHeader: "X-Region-Secret",
		InjectFormat: "{token}",
	}

	stripKeys := CollectQueryPlaceholders(cfgA.TokenRef, cfgB.TokenRef)

	var receivedQuery string
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
	})

	stripped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		StripQueryKeys(r, stripKeys)
		upstream.ServeHTTP(w, r)
	})
	handler := injector.Wrap(cfgA, injector.Wrap(cfgB, stripped))

	req := httptest.NewRequest(http.MethodGet, "/test?seller_id=42&region=eu&page=1", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	// Both seller_id and region should be stripped, page remains
	if receivedQuery != "page=1" {
		t.Errorf("query = %q, want %q", receivedQuery, "page=1")
	}
}
