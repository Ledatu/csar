package authn

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ledatu/csar-core/authntokens"
	"github.com/ledatu/csar-core/caller"
	"github.com/ledatu/csar-core/gatewayctx"
	"github.com/ledatu/csar/pkg/middleware/authzmw"
)

func TestV2NamespaceProfileAndStrictResponse(t *testing.T) {
	for _, scenario := range []string{"valid", "namespace", "profile", "duplicate", "v1", "expired"} {
		t.Run(scenario, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var in authntokens.DelegationRequestV2
				if json.NewDecoder(r.Body).Decode(&in) != nil || in.Validate() != nil {
					t.Error("invalid request")
					w.WriteHeader(400)
					return
				}
				out := authntokens.DelegationResultV2{Version: 2, Active: true, Purpose: in.Purpose, ProfileID: in.ProfileID, ProfileRevision: 1, Audience: in.Audience, Scope: in.Scope, Namespace: in.Namespace, Resource: in.Resource, AuthorizedScope: &authntokens.ScopeRef{Type: "tenant", ID: "workspace:north-branch"}, Identity: &caller.Identity{Version: 1, CallerKind: caller.Agent, CallerID: "agent", OwnerSubject: "owner", EffectiveSubject: "owner", CredentialID: "grant", CredentialKind: caller.DelegationProof, Assurance: caller.Verified}, ExpiresAt: time.Now().Add(time.Minute)}
				switch scenario {
				case "namespace":
					out.Namespace = "other"
				case "profile":
					out.ProfileID = "other"
				case "v1":
					out.Version = 1
				case "expired":
					out.ExpiresAt = time.Now().Add(-time.Minute)
				}
				body, _ := json.Marshal(out)
				if scenario == "duplicate" {
					body = append([]byte(`{"active":false,`), body[1:]...)
				}
				if _, err := w.Write(body); err != nil {
					t.Error(err)
				}
			}))
			defer server.Close()
			validator := NewTokenValidator(slog.New(slog.NewTextHandler(io.Discard, nil)), server.Client())
			called := false
			h := validator.Wrap(TokenConfig{Mode: authntokens.GrantResourceV2, Endpoint: server.URL, CredentialProfile: "facts", ResourceNamespace: "workspace", ResourcePathParam: "workspace", RequiredScope: "facts:read", Audiences: []string{"https://facts.test"}}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				if r.Header.Get(gatewayctx.HeaderTenant) != "workspace:north-branch" || r.Header.Get("Authorization") != "" {
					t.Error("wrong forwarded binding")
				}
				w.WriteHeader(204)
			}))
			req := httptest.NewRequest("GET", "/workspaces/north-branch", nil)
			req = req.WithContext(authzmw.WithPathVars(req.Context(), map[string]string{"workspace": "north-branch"}))
			req.Header.Set(gatewayctx.HeaderCsarAuthorization, "Bearer proof")
			req.Header.Set(gatewayctx.HeaderTenant, "forged")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if (scenario == "valid") != called || scenario == "valid" && w.Code != 204 || scenario != "valid" && w.Code < 400 {
				t.Fatal("unsafe v2 result accepted", w.Code)
			}
			if strings.Contains(w.Body.String(), "proof") {
				t.Fatal("credential reflected")
			}
		})
	}
}

func TestDirectResourceUsesAuthorizationAndPreservesClassifiedSource(t *testing.T) {
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var in authntokens.DelegationRequestV2
		if json.NewDecoder(r.Body).Decode(&in) != nil || in.Purpose != authntokens.AccessResource || in.Resource == nil || in.Resource.ID != "north" {
			t.Error("incorrect direct binding")
			w.WriteHeader(400)
			return
		}
		out := authntokens.DelegationResultV2{Version: 2, Active: true, Purpose: in.Purpose, ProfileID: in.ProfileID, ProfileRevision: 1, Audience: in.Audience, Scope: in.Scope, Namespace: in.Namespace, Resource: in.Resource, AuthorizedScope: &authntokens.ScopeRef{Type: "tenant", ID: "workspace:north"}, Identity: &caller.Identity{Version: 1, CallerKind: caller.Application, CallerID: "app", OwnerSubject: "owner", EffectiveSubject: "owner", CredentialID: "grant", CredentialKind: caller.APIKey, Assurance: caller.Verified}, ExpiresAt: time.Now().Add(time.Minute)}
		_ = json.NewEncoder(w).Encode(out)
	}))
	defer server.Close()
	v := NewTokenValidator(slog.New(slog.NewTextHandler(io.Discard, nil)), server.Client())
	called := 0
	h := v.Wrap(TokenConfig{Mode: authntokens.AccessResourceV2, Endpoint: server.URL, CredentialProfile: "facts", ResourceNamespace: "workspace", ResourcePathParam: "workspace", RequiredScope: "facts:read", Audiences: []string{"https://facts.test"}}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		source, ok := SourceFromContext(r.Context())
		if !ok || source.Account == nil || source.Account.ProfileID != "facts" || source.Caller.CredentialKind != caller.APIKey || r.Header.Get("Authorization") != "" {
			t.Error("direct source lost classification or leaked credential")
		}
		w.WriteHeader(204)
	}))
	for _, header := range []string{"Authorization", gatewayctx.HeaderCsarAuthorization} {
		r := httptest.NewRequest("GET", "/workspaces/north", nil)
		r = r.WithContext(authzmw.WithPathVars(r.Context(), map[string]string{"workspace": "north"}))
		r.Header.Set(header, "Bearer access")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if header == "Authorization" && w.Code != 204 || header != "Authorization" && w.Code != 401 {
			t.Fatal("wrong direct credential source", w.Code)
		}
	}
	if called != 1 || calls != 1 {
		t.Fatal("wrong source reached issuer/backend", calls, called)
	}
}
