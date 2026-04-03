package authzmw

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResolvePlaceholder_CompositePathScopeID(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/campaigns/by-account/wildberries/s1", nil)
	req = req.WithContext(WithPathVars(req.Context(), map[string]string{
		"marketplace": "wildberries",
		"external_id": "s1",
	}))

	got, err := resolvePlaceholder("{path.marketplace}:{path.external_id}", req, PathVarsFromContext(req.Context()))
	if err != nil {
		t.Fatalf("resolvePlaceholder() error: %v", err)
	}
	if got != "wildberries:s1" {
		t.Fatalf("scope_id = %q, want %q", got, "wildberries:s1")
	}
}

func TestResolvePlaceholder_MissingPathValue(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/campaigns/by-account/wildberries/s1", nil)
	req = req.WithContext(WithPathVars(req.Context(), map[string]string{
		"marketplace": "wildberries",
	}))

	_, err := resolvePlaceholder("{path.marketplace}:{path.external_id}", req, PathVarsFromContext(req.Context()))
	if err == nil {
		t.Fatal("expected error for missing external_id path variable")
	}
}
