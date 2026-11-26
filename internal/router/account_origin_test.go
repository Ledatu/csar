package router

import (
	"crypto"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/ledatu/csar-core/authntokens"
	"github.com/ledatu/csar-core/caller"
	"github.com/ledatu/csar-core/gatewayctx"
	"github.com/ledatu/csar-core/jwtx"
	"github.com/ledatu/csar-core/origincontext"
	"github.com/ledatu/csar/internal/config"
)

func TestAccountRootAndServiceHopHaveNoTenantOrProofLeak(t *testing.T) {
	keys, err := jwtx.GenerateKeyPair("EdDSA")
	if err != nil {
		t.Fatal(err)
	}
	rootIssuer := &testRootIssuer{keys: keys}
	jwk, err := jwtx.NewJWKFromPublicKey(keys.PublicKey, keys.KID)
	if err != nil {
		t.Fatal(err)
	}
	identity := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/jwks" {
			_ = json.NewEncoder(w).Encode(jwtx.JWKS{Keys: []jwtx.JWK{*jwk}})
			return
		}
		c, err := r.Cookie("session")
		if err != nil {
			w.WriteHeader(401)
			return
		}
		id := &caller.Identity{Version: 1, CallerKind: caller.Human, CallerID: c.Value, OwnerSubject: c.Value, EffectiveSubject: c.Value, CredentialKind: caller.Session, Assurance: caller.Verified}
		w.Header().Set(gatewayctx.HeaderSubject, c.Value)
		if err := gatewayctx.SetCaller(w.Header(), id); err != nil {
			t.Error(err)
		}
		w.Header().Set(authntokens.HeaderSessionExpiresAt, time.Now().Add(time.Hour).Format(time.RFC3339Nano))
	}))
	defer identity.Close()
	var calls atomic.Int32
	backend, tlsConfig := forwardingTLSFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		id, err := gatewayctx.FromRequestChecked(r)
		if err != nil || id.Origin == nil || id.Origin.Account == nil || id.Tenant != "" || len(r.TLS.VerifiedChains) == 0 {
			t.Error("account identity/verified ingress lost", err)
			w.WriteHeader(500)
			return
		}
		if strings.Contains(r.Header.Get("Accept"), "event-stream") {
			t.Error("JSON negotiation retained SSE")
		}
		token := strings.TrimPrefix(r.Header.Get(origincontext.HeaderForwardedAuthorization), "Bearer ")
		proof, err := origincontext.Verify(token, func(_, _ string) (crypto.PublicKey, error) { return keys.PublicKey, nil }, "issuer", map[bool]string{true: "svc:authn", false: "svc:campaigns"}[id.Subject == "svc:campaigns"])
		if err != nil || proof.Resource != "" || proof.Account == nil || *proof.Account != *id.Origin.Account {
			t.Error("account proof lost binding", err)
			w.WriteHeader(500)
			return
		}
		w.Header().Set(origincontext.HeaderForwardedAuthorization, token)
		w.Header().Set(gatewayctx.HeaderOriginAccount, r.Header.Get(gatewayctx.HeaderOriginAccount))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	cfg := newTestConfig(map[string]config.PathConfig{
		"/account": {"post": {OriginReceiver: "svc:campaigns", OriginBinding: "account", Backend: config.BackendConfig{TargetURL: backend.URL, TLS: tlsConfig}, AuthValidate: &config.AuthValidateConfig{Mode: "session", SessionEndpoint: identity.URL + "/session", CookieName: "session"}}},
		"/private": {"post": {OriginReceiver: "svc:authn", OriginBinding: "account", Backend: config.BackendConfig{TargetURL: backend.URL, TLS: tlsConfig}, AuthValidate: &config.AuthValidateConfig{Mode: "jwt", JWKSURL: identity.URL + "/jwks", Issuer: "issuer", Audiences: []string{"security"}}}},
	})
	router, err := New(cfg, newTestLogger(), WithRootIssuer(rootIssuer))
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	send := func(path, access, proof string, stream bool, want int) {
		t.Helper()
		r := httptest.NewRequest("POST", path, strings.NewReader(`{}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		if path == "/account" {
			r.AddCookie(&http.Cookie{Name: "session", Value: "owner"})
			r.Header.Set(gatewayctx.HeaderTenant, "forged")
		}
		if access != "" {
			r.Header.Set(gatewayctx.HeaderCsarAuthorization, "Bearer "+access)
		}
		if proof != "" {
			r.Header.Set(origincontext.HeaderAuthorization, "Bearer "+proof)
		}
		if stream {
			r.Header.Set("Accept", "text/event-stream")
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatal(path, w.Code, w.Body.String())
		}
		if w.Header().Get(origincontext.HeaderForwardedAuthorization) != "" || w.Header().Get(gatewayctx.HeaderOriginAccount) != "" {
			t.Fatal("attribution proof/metadata leaked")
		}
	}
	send("/account", "", "", false, 200)
	send("/account", "", "", true, 401)
	service := &caller.Identity{Version: 1, CallerKind: caller.Service, CallerID: "svc:campaigns", EffectiveSubject: "svc:campaigns", CredentialKind: caller.STS, Assurance: caller.Verified}
	access, err := jwtx.Sign(keys, jwt.MapClaims{"caller": service, "sub": service.CallerID, "iss": "issuer", "aud": "security", "exp": time.Now().Add(time.Minute).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	hashRequest := httptest.NewRequest("POST", "/private", strings.NewReader(`{}`))
	hashRequest.Header.Set("Content-Type", "application/json")
	hash, err := origincontext.RequestHash(hashRequest)
	if err != nil {
		t.Fatal(err)
	}
	account := &authntokens.AccountBinding{Kind: "credential", ProfileID: "reports", ProfileRevision: 1, Audience: "https://reports.test"}
	original := &caller.Identity{Version: 1, CallerKind: caller.Agent, CallerID: "agent", OwnerSubject: "owner", EffectiveSubject: "owner", CredentialKind: caller.APIKey, CredentialID: "grant", Assurance: caller.Verified}
	root, err := origincontext.IssueRoot(keys, "issuer", &origincontext.RootRequest{Caller: original, Account: account, Receiver: "svc:campaigns", RequestHash: hash, SourceExpiresAt: time.Now().Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	child, err := origincontext.Delegate(keys, "issuer", "svc:campaigns", &origincontext.DelegateRequest{ParentToken: root.Token, Account: account, Receiver: "svc:authn", RequestHash: hash})
	if err != nil {
		t.Fatal(err)
	}
	send("/private", access, child.Token, false, 200)
	send("/private", access, child.Token+"x", false, 401)
	if calls.Load() != 2 || rootIssuer.calls.Load() != 1 {
		t.Fatal("denial/child caused mint or backend access", calls.Load(), rootIssuer.calls.Load())
	}
}
