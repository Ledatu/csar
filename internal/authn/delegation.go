package authn

import (
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ledatu/csar-core/authntokens"
	"github.com/ledatu/csar-core/gatewayctx"
	"github.com/ledatu/csar/internal/apierror"
	"github.com/ledatu/csar/pkg/middleware/authzmw"
)

// RFC 6750 b64token syntax permits opaque bearer credentials from any issuer.
var bearerSyntax = regexp.MustCompile(`^[A-Za-z0-9._~+/\-]+=*$`)

func validBearer(token string) bool {
	return len(token) > 0 && len(token) <= 4096 && bearerSyntax.MatchString(token)
}

func validResourceID(id string) bool {
	return id != "" && len(id) <= 1024 && utf8.ValidString(id) && strings.IndexFunc(id, unicode.IsControl) == -1
}

func validIdentity(value string) bool {
	if len(value) == 0 || len(value) > 512 {
		return false
	}
	for _, c := range value {
		if c < 0x21 || c > 0x7e || c == ',' {
			return false
		}
	}
	return true
}

func (v *TokenValidator) wrapGrant(cfg TokenConfig, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		source, other := gatewayctx.HeaderCsarAuthorization, "Authorization"
		if cfg.Mode == authntokens.GrantExchange {
			source, other = other, source
		}
		token, ok := strings.CutPrefix(r.Header.Get(source), "Bearer ")
		if !ok || len(r.Header.Values(source)) != 1 || len(r.Header.Values(other)) != 0 || !validBearer(token) {
			rejectGrant(w, http.StatusUnauthorized)
			return
		}
		if len(cfg.Audiences) != 1 || cfg.Audiences[0] == "" || cfg.RequiredScope == "" {
			rejectGrant(w, http.StatusForbidden)
			return
		}
		req := authntokens.DelegationRequest{Token: token, Purpose: cfg.Mode, Audience: cfg.Audiences[0], Scope: cfg.RequiredScope}
		if req.Purpose == authntokens.GrantResource {
			req.ResourceID = authzmw.PathVarsFromContext(r.Context())[cfg.ResourcePathParam]
			if !validResourceID(req.ResourceID) {
				rejectGrant(w, http.StatusForbidden)
				return
			}
		}
		var result authntokens.DelegationResult
		if err := v.postIntrospection(r, cfg.Endpoint, req, &result); err != nil {
			v.logger.Error("delegation introspection failed")
			apierror.New(apierror.CodeUpstreamError, http.StatusBadGateway, "authentication service unavailable").Write(w)
			return
		}
		if !result.Active || !time.Now().Before(result.ExpiresAt) || !validIdentity(result.Subject) || !validIdentity(result.CredentialID) {
			rejectGrant(w, http.StatusUnauthorized)
			return
		}
		if !grantMatches(req, result, cfg.PlatformResource) {
			rejectGrant(w, http.StatusForbidden)
			return
		}
		clearCredentials(r)
		r.Header.Del(gatewayctx.HeaderTenant)
		if result.Tenant != "" {
			r.Header.Set(gatewayctx.HeaderTenant, result.Tenant)
		}
		if req.Purpose == authntokens.GrantExchange {
			r.Header.Set("Authorization", "Bearer "+result.DelegatedToken)
		}
		r.Header.Set(gatewayctx.HeaderScopes, req.Scope)
		r.Header.Set(gatewayctx.HeaderSubject, result.Subject)
		r.Header.Set(gatewayctx.HeaderCredentialID, result.CredentialID)
		next.ServeHTTP(w, r)
	})
}

func grantMatches(req authntokens.DelegationRequest, result authntokens.DelegationResult, platformResource bool) bool {
	if result.Audience != req.Audience || result.Purpose != req.Purpose || result.Scope != req.Scope || result.ResourceID != req.ResourceID {
		return false
	}
	switch req.Purpose {
	case authntokens.GrantExchange:
		return validBearer(result.DelegatedToken) && result.DelegatedToken != req.Token && (result.Tenant == "" || validIdentity(result.Tenant))
	case authntokens.GrantResource:
		return (validIdentity(result.Tenant) || (platformResource && result.Tenant == "")) && result.DelegatedToken == ""
	case authntokens.GrantDiscovery:
		return result.Tenant == "" && result.DelegatedToken == ""
	}
	return false
}

func rejectGrant(w http.ResponseWriter, status int) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	if status == http.StatusForbidden {
		apierror.New(apierror.CodeAccessDenied, status, "delegation does not authorize this operation").Write(w)
		return
	}
	apierror.New(apierror.CodeAuthFailed, status, "valid bearer credential required").Write(w)
}
