package authn

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ledatu/csar-core/authntokens"
	"github.com/ledatu/csar-core/caller"
	"github.com/ledatu/csar-core/gatewayctx"
	"github.com/ledatu/csar/pkg/middleware/authzmw"
)

func tokenCaller(kind caller.CredentialKind) *caller.Identity {
	return &caller.Identity{Version: caller.Version, CallerKind: caller.Agent, CallerID: "caller:1", OwnerSubject: "user:1",
		EffectiveSubject: "user:1", CredentialKind: kind, CredentialID: "key:1", Assurance: caller.Verified}
}

func TestOpaqueTokenCallerBindingCacheAndLegacy(t *testing.T) {
	for _, test := range []struct {
		name, mode string
		kind       caller.CredentialKind
		mutate     func(*tokenResult)
		want       int
	}{
		{"API agent", "token", caller.APIKey, nil, 204},
		{"API application", "token", caller.APIKey, func(r *tokenResult) { r.Identity.CallerKind = caller.Application }, 204},
		{"legacy", "token", caller.APIKey, func(r *tokenResult) { r.Identity = nil }, 204},
		{"unregistered", "token", caller.APIKey, func(r *tokenResult) {
			r.Identity.CallerKind, r.Identity.CallerID, r.Identity.Assurance = caller.Unknown, "", caller.Legacy
		}, 204},
		{"MCP access", "mcp-account", caller.OAuthAccess, nil, 204},
		{"MCP proof", "delegated", caller.DelegationProof, nil, 204},
		{"foreign subject", "token", caller.APIKey, func(r *tokenResult) { r.Identity.EffectiveSubject = "foreign" }, 502},
		{"foreign credential", "token", caller.APIKey, func(r *tokenResult) { r.Identity.CredentialID = "foreign" }, 502},
		{"wrong credential type", "token", caller.STS, nil, 502},
		{"unknown version", "token", caller.APIKey, func(r *tokenResult) { r.Identity.Version = 2 }, 502},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := tokenResult{Active: true, Subject: "user:1", CredentialID: "key:1", SellerID: "123", Scopes: []string{"analytics:read"},
				ExpiresAt: time.Now().Add(time.Hour), Identity: tokenCaller(test.kind), AccountGrant: true, DelegatedToken: "aurum_dlg_" + strings.Repeat("p", 43)}
			if test.mutate != nil {
				test.mutate(&result)
			}
			var calls atomic.Int32
			issuer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if err := json.NewEncoder(w).Encode(result); err != nil {
					t.Error(err)
				}
			}))
			defer issuer.Close()
			v := NewTokenValidator(slog.New(slog.NewTextHandler(io.Discard, nil)), issuer.Client())
			seen := 0
			h := v.Wrap(TokenConfig{Mode: test.mode, Endpoint: issuer.URL, RequiredScope: "analytics:read"}, gatewayctx.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen++
				id, _ := gatewayctx.FromContext(r.Context())
				if r.Header.Get(gatewayctx.HeaderOriginCaller) != "" || r.Header.Get("X-Gateway-Future-Identity") != "" {
					t.Fatal("forged reserved headers survived")
				}
				switch {
				case result.Identity == nil:
					if id.Caller != nil {
						t.Fatal("legacy issuer acquired inferred identity")
					}
				case id.Caller == nil || *id.Caller != *result.Identity:
					t.Fatal("issuer-bound caller lost or changed in cache")
				default:
					id.Caller.CallerID = "mutated-backend-copy"
				}
				w.WriteHeader(http.StatusNoContent)
			})))
			for range 2 {
				r := httptest.NewRequest(http.MethodGet, "/reports/123", nil)
				header, raw := "Authorization", "aurum_pat_fake"
				if test.mode == "mcp-account" {
					raw = "aurum_mcp_fake"
				}
				if test.mode == "delegated" {
					header, raw = gatewayctx.HeaderCsarAuthorization, "aurum_dlg_fake"
				}
				r.Header.Set(header, "Bearer "+raw)
				r.Header.Set(gatewayctx.HeaderCaller, "forged")
				r.Header.Set(gatewayctx.HeaderOriginCaller, "forged")
				r.Header.Set("X-Gateway-Future-Identity", "forged")
				r = r.WithContext(authzmw.WithPathVars(r.Context(), map[string]string{"seller_id": "123"}))
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				if w.Code != test.want {
					t.Fatalf("status=%d want=%d", w.Code, test.want)
				}
			}
			wantCalls := 2
			if test.mode == "token" && test.want == 204 {
				wantCalls = 1
			}
			if int(calls.Load()) != wantCalls || (test.want == 204 && seen != 2) || (test.want != 204 && seen != 0) {
				t.Fatalf("calls=%d backend=%d", calls.Load(), seen)
			}
		})
	}
}

func TestUniversalGrantPreservesIssuerCredentialVocabulary(t *testing.T) {
	for _, bad := range []bool{false, true} {
		result := authntokens.DelegationResult{Active: true, Subject: "user:1", CredentialID: "key:1", Purpose: authntokens.GrantExchange,
			Audience: "projects", Scope: "documents:read", ExpiresAt: time.Now().Add(time.Minute), DelegatedToken: "new-proof", Identity: tokenCaller(caller.APIKey)}
		if bad {
			result.Identity.CredentialID = "foreign"
		}
		issuer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := json.NewEncoder(w).Encode(result); err != nil {
				t.Error(err)
			}
		}))
		v := NewTokenValidator(slog.New(slog.NewTextHandler(io.Discard, nil)), issuer.Client())
		seen := false
		h := v.Wrap(TokenConfig{Mode: authntokens.GrantExchange, Endpoint: issuer.URL, RequiredScope: "documents:read", Audiences: []string{"projects"}}, gatewayctx.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seen = true
			id, _ := gatewayctx.FromContext(r.Context())
			if id.Caller == nil || id.Caller.CredentialKind != caller.APIKey || r.Header.Get("Authorization") != "Bearer new-proof" {
				t.Fatal("universal exchange assumed an OAuth-only credential or lost its proof")
			}
			w.WriteHeader(http.StatusNoContent)
		})))
		r := httptest.NewRequest(http.MethodGet, "/projects", nil)
		r.Header.Set("Authorization", "Bearer old-access")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		issuer.Close()
		want := http.StatusNoContent
		if bad {
			want = http.StatusBadGateway
		}
		if w.Code != want || seen == bad {
			t.Fatal("universal issuer binding mismatch", w.Code)
		}
	}
}
