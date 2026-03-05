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
