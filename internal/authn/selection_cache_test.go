package authn

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ledatu/csar-core/gatewayctx"
)

func TestSelectedSessionsDoNotShareValidationAcrossCookieNames(t *testing.T) {
	checks := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checks++
		cookie, err := r.Cookie("approved")
		if err != nil || cookie.Value != "same-value" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set(gatewayctx.HeaderSubject, "verified-user")
	}))
	defer server.Close()
	validator := NewSessionValidator(newTestLogger(), server.Client())
	methods := make([]Method, 0, 2)
	for _, name := range []string{"approved", "other"} {
		cfg := SessionConfig{Endpoint: server.URL, CookieName: name, ForwardHeaders: []string{gatewayctx.HeaderSubject}}
		methods = append(methods, Method{Source: "cookie:" + name, Wrap: func(next http.Handler) http.Handler { return validator.Wrap(cfg, next) }})
	}
	h := Select(methods, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	for _, tc := range []struct {
		cookie string
		want   int
	}{{"approved=same-value", 204}, {"other=same-value", 401}} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Cookie", tc.cookie)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != tc.want {
			t.Fatalf("%s: status %d want %d; cookie-specific validation was bypassed", tc.cookie, w.Code, tc.want)
		}
	}
	if checks != 2 {
		t.Fatalf("validation calls %d want 2", checks)
	}
}
