package authn

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ledatu/csar-core/gatewayctx"
	"github.com/ledatu/csar/pkg/middleware/authzmw"
)

func TestSelectionWithRealValidatorsAndAudienceAlternatives(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/jwks":
			if err := json.NewEncoder(w).Encode(jwksResponse{Keys: []JSONWebKey{rsaKeyToJWK(&key.PublicKey, "key")}}); err != nil {
				t.Error(err)
			}
		case "/session":
			c, err := r.Cookie("csar_session")
			if err != nil || c.Value != "valid" {
				w.WriteHeader(401)
				return
			}
			w.Header().Set(gatewayctx.HeaderSubject, "user:browser")
		case "/introspect":
			var body struct {
				Token string `json:"token"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if err := json.NewEncoder(w).Encode(tokenResult{Active: body.Token == "aurum_pat_valid", Subject: "user:key", CredentialID: "key", SellerID: "seller", Scopes: []string{"adverts:read"}, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
				t.Error(err)
			}
		default:
			t.Error("unexpected auth path", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	jv := NewJWTValidator(newTestLogger(), server.Client())
	sv := NewSessionValidator(newTestLogger(), server.Client())
	tv := NewTokenValidator(newTestLogger(), server.Client())
	jwtConfig := Config{JWKSURL: server.URL + "/jwks", Issuer: "issuer", Audiences: []string{"reader", "legacy-reader"}, ForwardClaims: map[string]string{"sub": gatewayctx.HeaderSubject}}
	methods := []Method{
		{"header:X-Csar-Authorization", func(next http.Handler) http.Handler { return jv.Wrap(jwtConfig, next) }},
		{"cookie:csar_session", func(next http.Handler) http.Handler {
			return sv.Wrap(SessionConfig{Endpoint: server.URL + "/session", CookieName: "csar_session", ForwardHeaders: []string{gatewayctx.HeaderSubject}}, next)
		}},
		{"header:Authorization", func(next http.Handler) http.Handler {
			return tv.Wrap(TokenConfig{Endpoint: server.URL + "/introspect", RequiredScope: "adverts:read"}, next)
		}},
	}
	token := func(aud, issuer string, expiry time.Time) string {
		return signJWT(map[string]interface{}{"alg": "RS256", "kid": "key"}, map[string]interface{}{"sub": "svc:reader", "aud": aud, "iss": issuer, "exp": expiry.Unix()}, key)
	}
	for _, tc := range []struct {
		name, header, value, subject, seller string
		want                                 int
	}{
		{"service", "X-Csar-Authorization", "Bearer " + token("reader", "issuer", time.Now().Add(time.Hour)), "svc:reader", "seller", 204},
		{"legacy service audience", "X-Csar-Authorization", "Bearer " + token("legacy-reader", "issuer", time.Now().Add(time.Hour)), "svc:reader", "seller", 204},
		{"wrong audience", "X-Csar-Authorization", "Bearer " + token("other", "issuer", time.Now().Add(time.Hour)), "", "seller", 401},
		{"wrong issuer", "X-Csar-Authorization", "Bearer " + token("reader", "other", time.Now().Add(time.Hour)), "", "seller", 401},
		{"expired service", "X-Csar-Authorization", "Bearer " + token("reader", "issuer", time.Now().Add(-time.Hour)), "", "seller", 401},
		{"session", "Cookie", "csar_session=valid", "user:browser", "seller", 204},
		{"invalid session", "Cookie", "csar_session=invalid", "", "seller", 401},
		{"key", "Authorization", "Bearer aurum_pat_valid", "user:key", "seller", 204},
		{"wrong cabinet key", "Authorization", "Bearer aurum_pat_valid", "", "other", 403},
		{"invalid key", "Authorization", "Bearer aurum_pat_invalid", "", "seller", 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get(gatewayctx.HeaderSubject) != tc.subject {
					t.Errorf("identity %q", r.Header.Get(gatewayctx.HeaderSubject))
				}
				if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("X-Csar-Authorization") != "" {
					t.Error("credential reached upstream")
				}
				w.WriteHeader(204)
			})
			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set(tc.header, tc.value)
			req = req.WithContext(authzmw.WithPathVars(req.Context(), map[string]string{"seller_id": tc.seller}))
			w := httptest.NewRecorder()
			Select(methods, next).ServeHTTP(w, req)
			if w.Code != tc.want {
				t.Fatalf("status %d want %d: %s", w.Code, tc.want, w.Body.String())
			}
		})
	}
}
