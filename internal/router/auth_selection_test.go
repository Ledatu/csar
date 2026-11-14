package router

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ledatu/csar-core/gatewayctx"
	"github.com/ledatu/csar/internal/config"
)

func TestSharedAuthRouterKeepsIdentityAndStripsSpoofing(t *testing.T) {
	session := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(gatewayctx.HeaderSubject, "verified-user")
	}))
	defer session.Close()
	calls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get(gatewayctx.HeaderSubject) != "verified-user" || r.Header.Get(gatewayctx.HeaderAuthzResult) != "" {
			t.Error("spoofed gateway identity")
		}
		if r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" || r.Header.Get("X-Csar-Authorization") != "" {
			t.Error("credential forwarded")
		}
		w.WriteHeader(204)
	}))
	defer upstream.Close()
	cfg := newTestConfig(map[string]config.PathConfig{"/catalog": {"get": {Backend: config.BackendConfig{TargetURL: upstream.URL}, AuthValidate: &config.AuthValidateConfig{Mode: "select", Methods: []config.AuthValidateConfig{
		{Mode: "session", SessionEndpoint: session.URL, CookieName: "csar_session", ForwardHeaders: []string{gatewayctx.HeaderSubject}},
		{Mode: "jwt", JWKSURL: session.URL + "/jwks"},
	}}}}})
	router, err := New(cfg, newTestLogger())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		cookie, header string
		want           int
	}{{"csar_session=valid", "", 204}, {"", "invalid", 401}, {"csar_session=valid", "invalid", 401}, {"", "", 401}} {
		req := httptest.NewRequest("GET", "/catalog", nil)
		for _, name := range gatewayctx.TrustedHeaders {
			req.Header.Set(name, "spoofed")
		}
		if tc.cookie != "" {
			req.Header.Set("Cookie", tc.cookie)
		}
		if tc.header != "" {
			req.Header.Set("X-Csar-Authorization", tc.header)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != tc.want {
			t.Fatalf("status %d want %d: %s", w.Code, tc.want, w.Body.String())
		}
	}
	if calls != 1 {
		t.Fatalf("upstream calls %d", calls)
	}
}
