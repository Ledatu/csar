package authn

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ledatu/csar-core/caller"
	"github.com/ledatu/csar/pkg/middleware/authzmw"
)

func TestSourceOwnershipAndLegacyAbsence(t *testing.T) {
	id := tokenCaller(caller.APIKey)
	r := withSource(httptest.NewRequest("GET", "/", nil), id, time.Now().Add(time.Minute))
	id.CallerID = "mutated"
	source, ok := SourceFromContext(r.Context())
	if !ok || source.Caller.CallerID != "caller:1" {
		t.Fatal("source aliases issuer metadata")
	}
	source.Caller.CallerID = "changed"
	stored, _ := SourceFromContext(r.Context())
	if stored.Caller.CallerID != "caller:1" {
		t.Fatal("source getter aliases context")
	}
	legacy := withSource(r, nil, time.Now().Add(time.Minute))
	if _, ok := SourceFromContext(legacy.Context()); ok {
		t.Fatal("legacy request retained previous source")
	}
}

func TestCachedTokenSourceDoesNotRenewValidationLease(t *testing.T) {
	issuer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewEncoder(w).Encode(tokenResult{Active: true, Subject: "user:1", CredentialID: "key:1", SellerID: "123", Scopes: []string{"analytics:read"}, ExpiresAt: time.Now().Add(time.Hour), Identity: tokenCaller(caller.APIKey)}); err != nil {
			t.Error(err)
		}
	}))
	defer issuer.Close()
	v := NewTokenValidator(newTestLogger(), issuer.Client())
	var firstUntil time.Time
	h := v.Wrap(TokenConfig{Mode: "token", Endpoint: issuer.URL, RequiredScope: "analytics:read", CacheTTL: time.Minute}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		source, ok := SourceFromContext(r.Context())
		if !ok {
			t.Fatal("verified source missing")
		}
		if firstUntil.IsZero() {
			firstUntil = source.ValidUntil
		} else if !source.ValidUntil.Equal(firstUntil) {
			t.Fatal("cache hit renewed source freshness")
		}
		w.WriteHeader(204)
	}))
	for range 2 {
		r := httptest.NewRequest("GET", "/report/123", nil)
		r.Header.Set("Authorization", "Bearer aurum_pat_fake")
		r = r.WithContext(authzmw.WithPathVars(r.Context(), map[string]string{"seller_id": "123"}))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 204 {
			t.Fatal(w.Code)
		}
	}
}
