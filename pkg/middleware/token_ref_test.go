package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ledatu/csar/pkg/middleware/authzmw"
)

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

func TestResolveTokenRef_PathPlaceholder(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/svc/wb/wildberries/s1/stats", nil)
	req = req.WithContext(authzmw.WithPathVars(req.Context(), map[string]string{
		"marketplace": "wildberries",
		"external_id": "s1",
	}))
	ref, err := resolveTokenRef("accounts/{path.marketplace}/{path.external_id}/api_token", req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ref != "accounts/wildberries/s1/api_token" {
		t.Errorf("ref = %q, want %q", ref, "accounts/wildberries/s1/api_token")
	}
}

func TestResolveTokenRef_MissingParam_Error(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil) // no query params
	_, err := resolveTokenRef("token_{query.seller_id}", req)
	if err == nil {
		t.Fatal("expected error for missing query param")
	}
}

func TestResolveTokenRef_MissingPathParam_Error(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/svc/wb/wildberries/s1/stats", nil)
	req = req.WithContext(authzmw.WithPathVars(req.Context(), map[string]string{
		"marketplace": "wildberries",
	}))
	_, err := resolveTokenRef("accounts/{path.marketplace}/{path.external_id}/api_token", req)
	if err == nil {
		t.Fatal("expected error for missing path param")
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
