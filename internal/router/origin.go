package router

import (
	"context"
	"net/http"
	"time"

	"github.com/ledatu/csar-core/gatewayctx"
	"github.com/ledatu/csar-core/origincontext"
	"github.com/ledatu/csar/pkg/middleware/authzmw"
)

// The proof is attribution only. The service must independently pass normal
// route authz for this same tenant before any cache or backend can serve data.
func validateOriginResource(req *http.Request) error {
	proof, present := origincontext.FromContext(req.Context())
	if !present {
		return nil
	}
	if proof.ExpiresAt == nil || !time.Now().Before(proof.ExpiresAt.Time) {
		return origincontext.ErrInvalid
	}
	if proof.Account != nil {
		if req.Context().Value(accountOriginKey{}) != true || proof.Account.Validate(proof.Origin) != nil || proof.Resource != "" || req.Header.Get(gatewayctx.HeaderTenant) != "" || proof.Sender != req.Header.Get(gatewayctx.HeaderSubject) {
			return origincontext.ErrInvalid
		}
		return nil
	}
	if req.Context().Value(accountOriginKey{}) == true {
		return origincontext.ErrInvalid
	}
	scope, ok := authzmw.ScopeFromContext(req.Context())
	if !ok || scope.Type != "tenant" || scope.ID == "" || scope.ID != proof.Resource || scope.Subject != proof.Sender || scope.Subject != req.Header.Get(gatewayctx.HeaderSubject) {
		return origincontext.ErrInvalid
	}
	return nil
}

type accountOriginKey struct{}

func withOriginBinding(req *http.Request, account bool) *http.Request {
	return req.WithContext(context.WithValue(req.Context(), accountOriginKey{}, account))
}
