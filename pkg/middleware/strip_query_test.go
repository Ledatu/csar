package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ledatu/csar/internal/kms"
)

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
