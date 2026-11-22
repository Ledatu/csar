package authn

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ledatu/csar-core/authntokens"
	"github.com/ledatu/csar-core/caller"
	"github.com/ledatu/csar-core/gatewayctx"
	"github.com/ledatu/csar-core/origincontext"
)

func TestSessionCacheUsesCurrentRouteTTLAndRevocation(t *testing.T) {
	var calls atomic.Int32
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) > 1 {
			w.WriteHeader(401)
			return
		}
		id := &caller.Identity{Version: 1, CallerKind: caller.Human, CallerID: "owner", OwnerSubject: "owner", EffectiveSubject: "effective", CredentialKind: caller.Session, Assurance: caller.Verified}
		w.Header().Set(gatewayctx.HeaderSubject, "effective")
		if err := gatewayctx.SetCaller(w.Header(), id); err != nil {
			t.Error(err)
		}
		w.Header().Set(authntokens.HeaderSessionExpiresAt, time.Now().Add(time.Hour).Format(time.RFC3339Nano))
	}))
	defer issuer.Close()
	v := NewSessionValidator(newTestLogger(), nil)
	send := func(ttl time.Duration) int {
		h := v.Wrap(SessionConfig{Endpoint: issuer.URL, CookieName: "session", CacheTTL: ttl}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, err := gatewayctx.CallerFromHeaders(r.Header)
			if err != nil || id == nil || id.OwnerSubject != "owner" || r.Header.Get(gatewayctx.HeaderOriginCaller) != "" {
				t.Fatal("forged or lost identity", err)
			}
			w.WriteHeader(204)
		}))
		r := httptest.NewRequest(http.MethodGet, "/report", nil)
		r.AddCookie(&http.Cookie{Name: "session", Value: "fake-session"})
		r.Header.Set(gatewayctx.HeaderCaller, "forged")
		r.Header.Set(gatewayctx.HeaderOriginCaller, "forged")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	first, second := send(time.Hour), send(time.Hour)
	if first != 204 || second != 204 || calls.Load() != 1 {
		t.Fatal("validated session cache missed")
	}
	v.mu.Lock()
	for _, entry := range v.cache {
		entry.fetchedAt = time.Now().Add(-time.Minute)
	}
	v.mu.Unlock()
	if send(time.Second) != 401 || calls.Load() != 2 {
		t.Fatal("long TTL hid current route revocation")
	}
	if send(time.Hour) != 401 {
		t.Fatal("revoked session survived in old positive entry")
	}
}

func TestJWTCallerRequiresVerifiedSubjectAndAccessPurpose(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewEncoder(w).Encode(jwksResponse{Keys: []JSONWebKey{rsaKeyToJWK(&key.PublicKey, "key")}}); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	for _, test := range []struct {
		name   string
		mutate func(map[string]any)
		want   int
	}{
		{"service", nil, 204},
		{"legacy", func(c map[string]any) { delete(c, "caller") }, 204},
		{"foreign subject", func(c map[string]any) { c["sub"] = "foreign" }, 401},
		{"foreign credential", func(c map[string]any) { c["credential_id"] = "foreign" }, 401},
		{"null caller", func(c map[string]any) { c["caller"] = nil }, 401},
		{"origin is not access", func(c map[string]any) { c["token_use"] = origincontext.TokenUse }, 401},
	} {
		t.Run(test.name, func(t *testing.T) {
			id := &caller.Identity{Version: 1, CallerKind: caller.Service, CallerID: "reporting", EffectiveSubject: "reporting", CredentialKind: caller.STS, Assurance: caller.Verified}
			claims := map[string]any{"caller": id, "sub": "reporting", "iss": "issuer", "aud": "api", "exp": time.Now().Add(time.Minute).Unix()}
			if test.mutate != nil {
				test.mutate(claims)
			}
			token := signJWT(map[string]any{"alg": "RS256", "kid": "key"}, claims, key)
			r := httptest.NewRequest(http.MethodGet, "/report", nil)
			r.Header.Set(gatewayctx.HeaderCaller, "spoofed")
			r.Header.Set(gatewayctx.HeaderOriginCaller, "spoofed")
			r.Header.Set(gatewayctx.HeaderCsarAuthorization, "Bearer "+token)
			v := NewJWTValidator(newTestLogger(), nil)
			h := v.Wrap(Config{JWKSURL: server.URL, Issuer: "issuer", Audiences: []string{"api"}}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got, err := gatewayctx.CallerFromHeaders(r.Header)
				if err != nil || test.name == "service" && (got == nil || got.CallerID != "reporting") || test.name == "legacy" && got != nil || r.Header.Get(gatewayctx.HeaderOriginCaller) != "" {
					t.Fatal("incorrect verified caller", err)
				}
				w.WriteHeader(204)
			}))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != test.want {
				t.Fatalf("status=%d want=%d", w.Code, test.want)
			}
		})
	}
}

func TestSessionCallerGETPOSTAndExpiry(t *testing.T) {
	for _, post := range []bool{false, true} {
		t.Run(map[bool]string{false: "GET", true: "POST"}[post], func(t *testing.T) {
			id := &caller.Identity{Version: 1, CallerKind: caller.Human, CallerID: "owner", OwnerSubject: "owner", EffectiveSubject: "effective", CredentialKind: caller.Session, Assurance: caller.Verified}
			expiry := time.Now().Add(5 * time.Second)
			var result *http.Response
			if post {
				payload, err := json.Marshal(authntokens.ValidateResponse{Identity: id, ExpiresAt: expiry, Headers: map[string]string{gatewayctx.HeaderSubject: "effective"}})
				if err != nil {
					t.Fatal(err)
				}
				result = &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(payload)))}
			} else {
				header := make(http.Header)
				header.Set(gatewayctx.HeaderSubject, "effective")
				if err := gatewayctx.SetCaller(header, id); err != nil {
					t.Fatal(err)
				}
				header.Set(authntokens.HeaderSessionExpiresAt, expiry.Format(time.RFC3339Nano))
				result = &http.Response{StatusCode: 200, Header: header, Body: http.NoBody}
			}
			cfg := SessionConfig{CacheTTL: time.Hour}
			if post {
				cfg.IssueTokens = []IssueTokenConfig{{Profile: "p"}}
			}
			entry, err := buildSessionCacheEntry(cfg, result)
			if err != nil || entry.identity == nil || entry.identity.OwnerSubject != "owner" || !entry.expiresAt.Equal(expiry) {
				t.Fatal("session identity or expiry lost", err)
			}
			entry.headers.Set(gatewayctx.HeaderSubject, "foreign")
			if !post {
				if _, err := buildSessionCacheEntry(cfg, &http.Response{StatusCode: 200, Header: entry.headers, Body: http.NoBody}); err == nil {
					t.Fatal("foreign session binding accepted")
				}
			}
		})
	}
}
