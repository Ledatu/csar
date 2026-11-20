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
	"github.com/ledatu/csar-core/gatewayctx"
	"github.com/ledatu/csar/pkg/middleware/authzmw"
)

// This issuer uses its own credential vocabulary, resource IDs and tenants.
func TestProjectDelegation(t *testing.T) {
	const audience, scope = "https://projects.example", "documents:read"
	const project, tenant = "p42", "organization:blue"
	const access, listProof, readProof = "access.example", "list.example", "read.example"
	for _, tt := range []struct{ purpose, token, path, wantProof, wantTenant string }{
		{authntokens.GrantExchange, access, "", listProof, ""},
		{authntokens.GrantDiscovery, listProof, "", "", ""},
		{authntokens.GrantResource, readProof, project, "", tenant},
	} {
		t.Run(tt.purpose, func(t *testing.T) {
			issuer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var in authntokens.DelegationRequest
				if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
					t.Error(err)
					return
				}
				if in.Token != tt.token || in.Audience != audience || in.Scope != scope || in.Purpose != tt.purpose || in.ResourceID != tt.path {
					t.Error("incorrect introspection request")
					return
				}
				result := authntokens.DelegationResult{
					Active: true, Subject: "reader", CredentialID: "grant-83", Purpose: in.Purpose, Audience: audience, Scope: scope, ExpiresAt: time.Now().Add(time.Minute),
					ResourceID: in.ResourceID, Tenant: tt.wantTenant, DelegatedToken: tt.wantProof,
				}
				if err := json.NewEncoder(w).Encode(result); err != nil {
					t.Error(err)
				}
			}))
			defer issuer.Close()
			validator := NewTokenValidator(slog.New(slog.NewTextHandler(io.Discard, nil)), issuer.Client())
			handler := validator.Wrap(TokenConfig{Mode: tt.purpose, Endpoint: issuer.URL, RequiredScope: scope, Audiences: []string{audience}, ResourcePathParam: "project"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get(gatewayctx.HeaderTenant) != tt.wantTenant || r.Header.Get(gatewayctx.HeaderSubject) != "reader" || r.Header.Get(gatewayctx.HeaderCredentialID) != "grant-83" || r.Header.Get(gatewayctx.HeaderScopes) != scope {
					t.Error("incorrect verified identity")
				}
				want := ""
				if tt.wantProof != "" {
					want = "Bearer " + tt.wantProof
				}
				if r.Header.Get("Authorization") != want || r.Header.Get("Cookie") != "" || r.Header.Get(gatewayctx.HeaderCsarAuthorization) != "" {
					t.Error("incorrect forwarded credential")
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			req := httptest.NewRequest("GET", "/projects/"+project, nil)
			req = req.WithContext(authzmw.WithPathVars(req.Context(), map[string]string{"project": project}))
			header := gatewayctx.HeaderCsarAuthorization
			if tt.purpose == authntokens.GrantExchange {
				header = "Authorization"
			}
			req.Header.Set(header, "Bearer "+tt.token)
			req.Header.Set("Cookie", "session=unused")
			req.Header.Set(gatewayctx.HeaderTenant, "untrusted")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != 204 {
				t.Fatalf("status %d", rec.Code)
			}
		})
	}
}

func TestDelegationRejectsMismatchedAuthority(t *testing.T) {
	req := authntokens.DelegationRequest{Purpose: authntokens.GrantResource, Audience: "projects", Scope: "files:read", ResourceID: "r1"}
	base := authntokens.DelegationResult{Purpose: req.Purpose, Audience: req.Audience, Scope: req.Scope, ResourceID: req.ResourceID, Tenant: "org:blue"}
	for name, mutate := range map[string]func(*authntokens.DelegationResult){
		"another audience": func(r *authntokens.DelegationResult) { r.Audience = "billing" },
		"another resource": func(r *authntokens.DelegationResult) { r.ResourceID = "r2" },
		"no tenant":        func(r *authntokens.DelegationResult) { r.Tenant = "" },
		"discovery":        func(r *authntokens.DelegationResult) { r.Purpose = authntokens.GrantDiscovery },
		"another scope":    func(r *authntokens.DelegationResult) { r.Scope = "files:edit" },
		"extra credential": func(r *authntokens.DelegationResult) { r.DelegatedToken = "unused" },
	} {
		t.Run(name, func(t *testing.T) {
			got := base
			mutate(&got)
			if grantMatches(req, got, false) {
				t.Fatal("accepted mismatched authority")
			}
		})
	}
	platform := base
	platform.Tenant = ""
	if !grantMatches(req, platform, true) || grantMatches(req, platform, false) {
		t.Fatal("unscoped resource requires platform authorization")
	}
	req = authntokens.DelegationRequest{Purpose: authntokens.GrantExchange, Token: "original", Audience: "projects", Scope: "files:read"}
	for _, proof := range []string{"", "original", "two credentials", "bad\r\nheader", strings.Repeat("a", 4097)} {
		if grantMatches(req, authntokens.DelegationResult{Purpose: req.Purpose, Audience: req.Audience, Scope: req.Scope, DelegatedToken: proof}, false) {
			t.Fatal("accepted invalid exchange")
		}
	}
}
