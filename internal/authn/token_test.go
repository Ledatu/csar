package authn

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ledatu/csar-core/gatewayctx"
	"github.com/ledatu/csar/pkg/middleware/authzmw"
)

type tokenTransport func(*http.Request) (*http.Response, error)

func (f tokenTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestTokenValidatorScopesCabinetAndStripsCredential(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: tokenTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Path != "/auth/token/introspect" {
			t.Fatalf("unexpected introspection path %q", r.URL.Path)
		}
		payload := `{"active":true,"subject":"user-1","credential_id":"key-1",` +
			`"seller_id":"123","scopes":["adverts:read"],"expires_at":"` +
			time.Now().Add(time.Hour).UTC().Format(time.RFC3339) + `"}`
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(payload)), Header: make(http.Header)}, nil
	})}
	v := NewTokenValidator(slog.New(slog.NewTextHandler(io.Discard, nil)), client)
	cfg := TokenConfig{Endpoint: "https://authn/auth/token/introspect", RequiredScope: "adverts:read"}
	seen := false
	h := v.Wrap(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = true
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Fatal("raw credentials reached backend")
		}
		if r.Header.Get(gatewayctx.HeaderSubject) != "user-1" ||
			r.Header.Get(gatewayctx.HeaderCredentialID) != "key-1" {
			t.Fatal("verified identity not forwarded")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/v1/wildberries/123/adverts/bidder-settings", nil)
		req.Header.Set("Authorization", "Bearer aurum_pat_fake")
		req.Header.Set("Cookie", "session=secret")
		req = req.WithContext(authzmw.WithPathVars(req.Context(), map[string]string{"seller_id": "123"}))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204", rec.Code)
		}
	}
	if !seen || calls != 1 {
		t.Fatalf("seen=%v introspection calls=%d, want true and 1", seen, calls)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/wildberries/999/adverts/bidder-settings", nil)
	req.Header.Set("Authorization", "Bearer aurum_pat_fake")
	req = req.WithContext(authzmw.WithPathVars(req.Context(), map[string]string{"seller_id": "999"}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("foreign cabinet status=%d, want 403", rec.Code)
	}
}
