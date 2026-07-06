package authn

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ledatu/csar-core/authntokens"
)

func TestSessionValidator_IssueTokensPOSTAndInjects(t *testing.T) {
	var method string
	var requested []authntokens.IssueTokenRequest
	authnServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		if cookie, err := r.Cookie("session"); err != nil || cookie.Value != "sess-1" {
			t.Fatalf("cookie = %v, %v", cookie, err)
		}
		var req authntokens.ValidateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		requested = req.IssueTokens
		_ = json.NewEncoder(w).Encode(authntokens.ValidateResponse{
			Headers: map[string]string{"X-Gateway-Subject": "user-1"},
			Tokens: []authntokens.IssuedToken{{
				Profile:   "telegram-webapp",
				Token:     "signed-token",
				ExpiresAt: time.Now().Add(time.Minute),
			}},
		})
	}))
	defer authnServer.Close()

	validator := NewSessionValidator(slog.New(slog.NewTextHandler(io.Discard, nil)), authnServer.Client())
	nextCalled := false
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		nextCalled = true
		if got := r.Header.Get("Authorization"); got != "Bearer signed-token" {
			t.Fatalf("Authorization = %q", got)
		}
		if got := r.Header.Get("X-Gateway-Subject"); got != "user-1" {
			t.Fatalf("X-Gateway-Subject = %q", got)
		}
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: "sess-1"})
	req.Header.Set("Authorization", "Bearer spoofed")
	w := httptest.NewRecorder()
	validator.Wrap(SessionConfig{
		Endpoint:       authnServer.URL,
		CookieName:     "session",
		ForwardHeaders: []string{"X-Gateway-Subject"},
		IssueTokens: []IssueTokenConfig{{
			Profile:        "telegram-webapp",
			InjectHeader:   "Authorization",
			InjectFormat:   "Bearer {token}",
			OnMissingClaim: "fail_closed",
		}},
		CacheTTL: time.Minute,
	}, next).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", w.Code, w.Body.String())
	}
	if !nextCalled {
		t.Fatal("next was not called")
	}
	if method != http.MethodPost {
		t.Fatalf("method = %q, want POST", method)
	}
	if len(requested) != 1 || requested[0].Profile != "telegram-webapp" {
		t.Fatalf("requested = %#v", requested)
	}
}
