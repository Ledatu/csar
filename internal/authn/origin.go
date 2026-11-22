package authn

import (
	"crypto"
	"net/http"
	"strings"

	"github.com/ledatu/csar-core/caller"
	"github.com/ledatu/csar-core/gatewayctx"
	"github.com/ledatu/csar-core/origincontext"
)

// verifyOrigin consumes the separate attribution credential. It never changes
// the access principal; resource binding is checked after normal authorization.
func (v *JWTValidator) verifyOrigin(r *http.Request, cfg Config, keyFunc func(string, string) (crypto.PublicKey, error)) (*http.Request, error) {
	var values []string
	for name, items := range r.Header {
		if strings.EqualFold(name, origincontext.HeaderAuthorization) {
			values = append(values, items...)
			delete(r.Header, name)
		}
	}
	if len(values) == 0 {
		return r, nil
	}
	if len(values) != 1 || cfg.Issuer == "" || len(cfg.Audiences) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		return nil, origincontext.ErrInvalid
	}
	id, err := gatewayctx.CallerFromHeaders(r.Header)
	if err != nil || id == nil || id.CallerKind != caller.Service || id.CredentialKind != caller.STS || id.CallerID != id.EffectiveSubject {
		return nil, origincontext.ErrInvalid
	}
	claims, err := origincontext.Verify(strings.TrimPrefix(values[0], "Bearer "), keyFunc, cfg.Issuer, cfg.Audiences[0])
	if err != nil {
		return nil, err
	}
	hash, err := origincontext.RequestHash(r)
	if err != nil || claims.CheckHop(id.CallerID, claims.Resource, hash) != nil {
		return nil, origincontext.ErrInvalid
	}
	return r.WithContext(origincontext.WithVerified(r.Context(), claims)), nil
}

// RejectUnconsumedOrigin prevents attribution credentials on unsupported auth
// modes from reaching a backend. Only the verified JWT service path consumes it.
func RejectUnconsumedOrigin(r *http.Request) error {
	for name := range r.Header {
		if strings.EqualFold(name, origincontext.HeaderAuthorization) {
			delete(r.Header, name)
			return origincontext.ErrInvalid
		}
	}
	return nil
}
