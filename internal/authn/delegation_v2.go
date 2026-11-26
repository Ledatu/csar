package authn

import (
	"net/http"
	"strings"
	"time"

	"github.com/ledatu/csar-core/authntokens"
	"github.com/ledatu/csar-core/gatewayctx"
	"github.com/ledatu/csar/internal/apierror"
	"github.com/ledatu/csar/pkg/middleware/authzmw"
)

func (v *TokenValidator) wrapGrantV2(cfg TokenConfig, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gatewayctx.StripTrusted(r.Header)
		purpose := strings.TrimSuffix(cfg.Mode, "-v2")
		source, other := gatewayctx.HeaderCsarAuthorization, "Authorization"
		if purpose == authntokens.GrantExchange || purpose == authntokens.AccessResource {
			source, other = other, source
		}
		raw, ok := strings.CutPrefix(r.Header.Get(source), "Bearer ")
		if !ok || len(r.Header.Values(source)) != 1 || len(r.Header.Values(other)) != 0 || !validBearer(raw) || len(cfg.Audiences) != 1 {
			rejectGrant(w, 401)
			return
		}
		in := authntokens.DelegationRequestV2{Version: 2, Token: raw, Purpose: purpose, ProfileID: cfg.CredentialProfile, Audience: cfg.Audiences[0], Scope: cfg.RequiredScope, Namespace: cfg.ResourceNamespace}
		if purpose == authntokens.GrantResource || purpose == authntokens.AccessResource {
			in.Resource = &authntokens.ResourceRef{Namespace: cfg.ResourceNamespace, ID: authzmw.PathVarsFromContext(r.Context())[cfg.ResourcePathParam]}
		}
		if in.Validate() != nil {
			rejectGrant(w, 403)
			return
		}
		var out authntokens.DelegationResultV2
		if err := v.postIntrospection(r, cfg.Endpoint, in, &out); err != nil {
			apierror.New(apierror.CodeUpstreamError, 502, "authentication service unavailable").Write(w)
			return
		}
		if !out.Active {
			rejectGrant(w, 401)
			return
		}
		if out.ValidateFor(&in, time.Now()) != nil {
			rejectGrant(w, 403)
			return
		}
		clearCredentials(r)
		r.Header.Del(gatewayctx.HeaderTenant)
		if out.AuthorizedScope != nil && out.AuthorizedScope.Type == "tenant" {
			r.Header.Set(gatewayctx.HeaderTenant, out.AuthorizedScope.ID)
		}
		if purpose == authntokens.GrantExchange {
			r.Header.Set("Authorization", "Bearer "+out.DelegatedToken)
		}
		r.Header.Set(gatewayctx.HeaderSubject, out.Identity.EffectiveSubject)
		r.Header.Set(gatewayctx.HeaderCredentialID, out.Identity.CredentialID)
		r.Header.Set(gatewayctx.HeaderScopes, in.Scope)
		if gatewayctx.SetCaller(r.Header, out.Identity) != nil {
			rejectGrant(w, 403)
			return
		}
		forwarded := withAccountSource(r, out.Identity, out.ExpiresAt, &authntokens.AccountBinding{Kind: "credential", ProfileID: out.ProfileID, ProfileRevision: out.ProfileRevision, Audience: out.Audience})
		if out.AuthorizedScope != nil {
			forwarded = forwarded.WithContext(authzmw.WithRequiredScope(forwarded.Context(), out.Identity.EffectiveSubject, *out.AuthorizedScope))
		}
		next.ServeHTTP(w, forwarded)
	})
}
