package router

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ledatu/csar-core/gatewayctx"
	"github.com/ledatu/csar/internal/config"
)

func TestSharedAuthAuditUsesOnlySelectedVerifiedEmail(t *testing.T) {
	session := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookies := r.Cookies()
		if len(cookies) != 1 || cookies[0].Value == "expired" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set(gatewayctx.HeaderSubject, "verified-user")
		w.Header().Set(actorEmailHeader, "verified@example.test")
	}))
	defer session.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer upstream.Close()
	mode := config.AuditModeAll
	cfg := newTestConfig(map[string]config.PathConfig{"/catalog": {"get": {
		Backend: config.BackendConfig{TargetURL: upstream.URL}, Audit: &mode,
		AuthValidate: &config.AuthValidateConfig{Mode: "select", Methods: []config.AuthValidateConfig{
			{Mode: "session", SessionEndpoint: session.URL, CookieName: "with_email", ForwardHeaders: []string{gatewayctx.HeaderSubject, actorEmailHeader}},
			{Mode: "session", SessionEndpoint: session.URL, CookieName: "without_email", ForwardHeaders: []string{gatewayctx.HeaderSubject}},
		}},
	}}})
	recorder := &stubAuditRecorder{}
	router, err := New(cfg, newTestLogger(), func(r *Router) { r.auditClient = recorder })
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	for _, tc := range []struct {
		cookie string
		want   int
		email  any
	}{
		{"with_email=valid-a", 204, "verified@example.test"},
		{"without_email=valid-b", 204, nil},
		{"with_email=expired", 401, nil},
	} {
		t.Run(tc.cookie, func(t *testing.T) {
			recorder.events = nil
			req := httptest.NewRequest(http.MethodGet, "/catalog", nil)
			req.Header.Set("Cookie", tc.cookie)
			req.Header.Set(actorEmailHeader, "spoofed@example.test")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			if w.Code != tc.want || len(recorder.events) != 1 {
				t.Fatalf("status %d, events %d", w.Code, len(recorder.events))
			}
			var metadata map[string]any
			if err := json.Unmarshal(recorder.events[0].Metadata, &metadata); err != nil {
				t.Fatal(err)
			}
			if metadata["actor_email"] != tc.email {
				t.Fatalf("actor email %v want %v", metadata["actor_email"], tc.email)
			}
		})
	}
}

func TestSharedAuthRejectsDuplicateSourcesAtConstruction(t *testing.T) {
	cfg := newTestConfig(map[string]config.PathConfig{"/catalog": {"get": {
		Backend: config.BackendConfig{TargetURL: "https://owner.example.test"},
		AuthValidate: &config.AuthValidateConfig{Mode: "select", Methods: []config.AuthValidateConfig{
			{Mode: "jwt", JWKSURL: "https://auth.example.test/jwks"},
			{Mode: "jwt", JWKSURL: "https://auth.example.test/jwks"},
		}},
	}}})
	router, err := New(cfg, newTestLogger())
	if err == nil {
		router.Close()
		t.Fatal("duplicate credential sources accepted")
	}
}
