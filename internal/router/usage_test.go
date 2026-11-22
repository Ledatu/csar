package router

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/golang-jwt/jwt/v5"
	auditcore "github.com/ledatu/csar-core/audit"
	"github.com/ledatu/csar-core/caller"
	"github.com/ledatu/csar-core/gatewayctx"
	"github.com/ledatu/csar-core/jwtx"
	"github.com/ledatu/csar/internal/config"
	"github.com/redis/go-redis/v9"
)

func TestUsageBudgetsCoverCredentialsRoutesAndCacheHits(t *testing.T) {
	for _, audited := range []bool{true, false} {
		t.Run(fmt.Sprint("audit=", audited), func(t *testing.T) {
			receipts := 0
			recorder := &releaseRecorder{release: func(context.Context, *auditcore.Event) error { receipts++; return nil }}
			seed, calls := releaseFixture(t, recorder)
			store := miniredis.RunT(t)
			client := redis.NewClient(&redis.Options{Addr: store.Addr()})
			defer client.Close()
			keys, err := jwtx.GenerateKeyPair("EdDSA")
			if err != nil {
				t.Fatal(err)
			}
			jwk, err := jwtx.NewJWKFromPublicKey(keys.PublicKey, keys.KID)
			if err != nil {
				t.Fatal(err)
			}
			identity := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(jwtx.JWKS{Keys: []jwtx.JWK{*jwk}})
			}))
			defer identity.Close()
			cfg := *seed.cfg
			route := cfg.Paths["/report"]["get"]
			route.AuthValidate = &config.AuthValidateConfig{Mode: "jwt", JWKSURL: identity.URL, Issuer: "issuer", Audiences: []string{"reports-access"}}
			route.UsageBudget = &config.UsageBudgetConfig{Name: "analytics.read", Window: config.Duration{Duration: time.Minute}, Caller: 2, Owner: 3, OwnerSeller: 3, Fleet: 10}
			expectedReceipts := 3
			if !audited {
				cfg.Audit = nil
				route.AuditRelease = false
				off := config.AuditModeOff
				route.Audit = &off
				expectedReceipts = 0
			}
			cfg.Paths = map[string]config.PathConfig{"/report": {"get": route}, "/tool-report": {"get": route}}
			router, err := New(&cfg, newTestLogger(), WithRedisClient(client), WithAuthzClient(seed.authzClient), func(r *Router) { r.auditClient = recorder })
			if err != nil {
				t.Fatal(err)
			}
			defer router.Close()
			send := func(path, agent, credential string, kind caller.CredentialKind) *httptest.ResponseRecorder {
				t.Helper()
				id := &caller.Identity{Version: 1, CallerKind: caller.Agent, CallerID: agent, OwnerSubject: "owner", EffectiveSubject: "owner", CredentialKind: kind, CredentialID: credential, Assurance: caller.Verified}
				token, err := jwtx.Sign(keys, jwt.MapClaims{"caller": id, "credential_id": credential, "sub": "owner", "iss": "issuer", "aud": "reports-access", "exp": time.Now().Add(time.Minute).Unix()})
				if err != nil {
					t.Fatal(err)
				}
				req := httptest.NewRequest("GET", path, nil)
				req.Header.Set(gatewayctx.HeaderCsarAuthorization, "Bearer "+token)
				response := httptest.NewRecorder()
				router.ServeHTTP(response, req)
				return response
			}
			if w := send("/report", "agent-one", "key-one", caller.APIKey); w.Code != 200 {
				t.Fatal(w.Code, w.Body.String())
			}
			if w := send("/report", "agent-one", "oauth-refreshed", caller.OAuthAccess); w.Code != 200 || w.Header().Get("X-CSAR-Cache") != "HIT" {
				t.Fatal("route/credential change lost shared cache", w.Code, w.Body.String())
			}
			if w := send("/tool-report", "agent-one", "new-key", caller.APIKey); w.Code != 429 || w.Header().Get("Retry-After") == "" {
				t.Fatal("new credential bypassed caller budget", w.Code, w.Body.String())
			}
			if w := send("/report", "agent-two", "second-key", caller.APIKey); w.Code != 200 {
				t.Fatal(w.Code, w.Body.String())
			}
			if w := send("/tool-report", "agent-three", "third-key", caller.APIKey); w.Code != 429 {
				t.Fatal("new caller bypassed owner budget", w.Code, w.Body.String())
			}
			if calls.Load() != 1 || receipts != expectedReceipts {
				t.Fatal("budget did not guard HIT/receipt", calls.Load(), receipts)
			}
			if client.Options().MaxRetries == 0 || client.Options().ContextTimeoutEnabled || router.usageRedis.Options().MaxRetries != 0 || !router.usageRedis.Options().ContextTimeoutEnabled {
				t.Fatal("admission mutated shared pool or failed to bound private pool")
			}
			if router.usageRedis.Options().PushNotificationProcessor == client.Options().PushNotificationProcessor {
				t.Fatal("admission reused live push state from the shared pool")
			}
			store.Close()
			if w := send("/report", "agent-four", "fourth-key", caller.APIKey); w.Code != 503 || w.Header().Get("X-CSAR-Status") != "usage_unavailable" {
				t.Fatal("Redis outage bypassed budget", w.Code, w.Body.String())
			}
			if receipts != expectedReceipts || calls.Load() != 1 {
				t.Fatal("outage reached cache/receipt/backend")
			}
		})
	}
}

func TestUsageRejectsConflictingPolicyBeforeRedis(t *testing.T) {
	policy := &config.UsageBudgetConfig{Name: "read", Window: config.Duration{Duration: time.Minute}, Caller: 1, Owner: 2, OwnerSeller: 2, Fleet: 3}
	other := *policy
	other.Fleet++
	cfg := newTestConfig(map[string]config.PathConfig{"/a": {"get": {UsageBudget: policy, AuthValidate: &config.AuthValidateConfig{}, Authz: &config.AuthzRouteConfig{}}}, "/b": {"get": {UsageBudget: &other, AuthValidate: &config.AuthValidateConfig{}, Authz: &config.AuthzRouteConfig{}}}})
	if _, err := New(cfg, newTestLogger()); err == nil || !strings.Contains(err.Error(), "conflicting") {
		t.Fatal("conflicting same-policy capacities accepted")
	}
}
