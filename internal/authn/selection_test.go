package authn

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSelectRejectsConflictingCredentialsWithoutCallingValidators(t *testing.T) {
	for _, tc := range []struct {
		name    string
		headers map[string][]string
		want    int
	}{
		{"missing", nil, 401},
		{"service", map[string][]string{"X-Csar-Authorization": {"Bearer svc"}}, 204},
		{"personal", map[string][]string{"Authorization": {"Bearer key"}}, 204},
		{"session", map[string][]string{"Cookie": {"csar_session=session"}}, 204},
		{"unrelated cookie", map[string][]string{"Cookie": {"theme=dark"}, "Authorization": {"Bearer key"}}, 204},
		{"two headers", map[string][]string{"Authorization": {"Bearer key"}, "X-Csar-Authorization": {"Bearer svc"}}, 401},
		{"cookie and header", map[string][]string{"Cookie": {"csar_session=session"}, "Authorization": {"Bearer key"}}, 401},
		{"duplicate header", map[string][]string{"Authorization": {"Bearer a", "Bearer b"}}, 401},
		{"duplicate cookie", map[string][]string{"Cookie": {"csar_session=a; csar_session=b"}}, 401},
		{"empty header still conflicts", map[string][]string{"Authorization": {""}, "Cookie": {"csar_session=session"}}, 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			wrap := func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; next.ServeHTTP(w, r) })
			}
			h := Select([]Method{{"header:X-Csar-Authorization", wrap}, {"header:Authorization", wrap}, {"cookie:csar_session", wrap}}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "" || r.Header.Get("X-Csar-Authorization") != "" || r.Header.Get("Cookie") != "" {
					t.Error("credentials leaked")
				}
				w.WriteHeader(204)
			}))
			r := httptest.NewRequest("GET", "/", nil)
			r.Header = http.Header(tc.headers)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("got %d want %d", w.Code, tc.want)
			}
			if (tc.want == 204 && calls != 1) || (tc.want == 401 && calls != 0) {
				t.Fatalf("validator calls %d", calls)
			}
		})
	}
}

func TestSelectDoesNotFallbackAfterRejection(t *testing.T) {
	calls := 0
	rejecting := func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls++; w.WriteHeader(403) })
	}
	h := Select([]Method{{"header:Authorization", rejecting}, {"cookie:csar_session", rejecting}}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("rejected credential passed") }))
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "bad")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 || calls != 1 {
		t.Fatalf("status %d calls %d", w.Code, calls)
	}
}
