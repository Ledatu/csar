package router

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/ledatu/csar-core/caller"
	"github.com/ledatu/csar-core/gatewayctx"
	"github.com/ledatu/csar-core/origincontext"
	"github.com/ledatu/csar/internal/apierror"
	"github.com/ledatu/csar/internal/authn"
	"github.com/ledatu/csar/internal/config"
	"github.com/ledatu/csar/pkg/middleware/authzmw"
)

type RootIssuer interface {
	Issue(context.Context, *origincontext.RootRequest) (*origincontext.Proof, error)
}

// WithOriginForwarding supplies explicit METHOD:/path -> service-principal
// bindings. Startup/config distribution must preserve these bindings before this
// opt-in adapter is activated; absence keeps existing routing behavior.
func WithOriginForwarding(issuer RootIssuer, receivers map[string]string) Option {
	return func(r *Router) {
		r.originIssuer = issuer
		r.originReceivers = make(map[string]string, len(receivers))
		for key, value := range receivers {
			r.originReceivers[key] = value
		}
	}
}

func (r *Router) checkOriginRoute(rt *route, transport http.RoundTripper) error {
	receiver, enabled := r.originReceivers[rt.routeKey]
	if !enabled {
		return nil
	}
	if receiver == "" || !caller.ValidReference(receiver) || r.originIssuer == nil || rt.authentication == nil || rt.authzConfig == nil || rt.tenantConfig != nil {
		return fmt.Errorf("route %s: origin forwarding requires issuer, receiver, authentication and static tenant authorization", rt.routeKey)
	}
	tlsTransport, ok := transport.(*http.Transport)
	if !ok || tlsTransport.TLSClientConfig == nil || tlsTransport.TLSClientConfig.InsecureSkipVerify || len(tlsTransport.TLSClientConfig.Certificates) == 0 && tlsTransport.TLSClientConfig.GetClientCertificate == nil {
		return fmt.Errorf("route %s: origin forwarding requires verified backend mTLS", rt.routeKey)
	}
	for _, target := range rt.config.Backend.AllTargets() {
		u, err := url.Parse(target)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			return fmt.Errorf("route %s: origin forwarding requires HTTPS targets", rt.routeKey)
		}
	}
	return nil
}

func (r *Router) originSource(req *http.Request) (*authn.Source, string, error) {
	source, ok := authn.SourceFromContext(req.Context())
	if !ok || source.Caller == nil || !time.Now().Before(source.ValidUntil) {
		return nil, "", origincontext.ErrInvalid
	}
	id, err := gatewayctx.CallerFromHeaders(req.Header)
	scope, allowed := authzmw.ScopeFromContext(req.Context())
	if err != nil || id == nil || *id != *source.Caller || !allowed || scope.Type != "tenant" || scope.ID == "" || scope.Subject != source.Caller.EffectiveSubject {
		return nil, "", origincontext.ErrInvalid
	}
	return source, scope.ID, nil
}

func (r *Router) forwardOrigin(rt *route, next http.Handler) http.Handler {
	receiver := r.originReceivers[rt.routeKey]
	if receiver == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		source, resource, err := r.originSource(req)
		if err != nil {
			apierror.New(apierror.CodeAuthFailed, http.StatusUnauthorized, "verified origin source expired or unavailable").Write(w)
			return
		}
		proof, present := origincontext.ProofFromContext(req.Context())
		if !present {
			hash, hashErr := origincontext.RequestHash(req)
			if hashErr != nil {
				apierror.New(apierror.CodeAuthFailed, http.StatusBadRequest, "request cannot carry origin context").Write(w)
				return
			}
			proof, err = r.originIssuer.Issue(req.Context(), &origincontext.RootRequest{Caller: source.Caller, Receiver: receiver, Resource: resource, RequestHash: hash, SourceExpiresAt: source.ValidUntil})
			if err != nil {
				apierror.New(apierror.CodeUpstreamError, http.StatusBadGateway, "origin issuer unavailable").Write(w)
				return
			}
			if proof == nil || proof.Claims == nil || proof.Claims.Origin == nil || *proof.Claims.Origin != *source.Caller || proof.Claims.Depth != 0 || proof.Claims.RequestHash != hash || proof.Claims.ExpiresAt == nil || proof.Claims.ExpiresAt.After(source.ValidUntil) {
				apierror.New(apierror.CodeUpstreamError, http.StatusBadGateway, "invalid root context").Write(w)
				return
			}
		}
		if proof.Claims == nil || proof.Claims.ExpiresAt == nil || proof.Token == "" || len(proof.Token) > origincontext.MaxTokenBytes || proof.Claims.Receiver != receiver || proof.Claims.Resource != resource || !time.Now().Before(proof.Claims.ExpiresAt.Time) {
			apierror.New(apierror.CodeAccessDenied, http.StatusForbidden, "origin binding expired or mismatched").Write(w)
			return
		}
		if err := gatewayctx.SetOrigin(req.Header, &gatewayctx.Origin{Caller: proof.Claims.Origin, OperationID: proof.Claims.OperationID, ParentOperationID: proof.Claims.ParentOperationID, ExpiresAt: proof.Claims.ExpiresAt.Time}); err != nil {
			apierror.New(apierror.CodeUpstreamError, http.StatusBadGateway, "invalid origin metadata").Write(w)
			return
		}
		req.Header.Set(gatewayctx.HeaderTenant, resource)
		req.Header.Set(origincontext.HeaderForwardedAuthorization, "Bearer "+proof.Token)
		deadline := proof.Claims.ExpiresAt.Time
		if source.ValidUntil.Before(deadline) {
			deadline = source.ValidUntil
		}
		ctx, cancel := context.WithDeadline(req.Context(), deadline)
		defer cancel()
		req = req.WithContext(origincontext.WithVerifiedProof(ctx, proof))
		auditAuthorizedContext(req)
		next.ServeHTTP(&originResponseWriter{ResponseWriter: w}, req)
	})
}

// Strip transport metadata before either public response delivery or cache store.
type originResponseWriter struct{ http.ResponseWriter }

func (w *originResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *originResponseWriter) WriteHeader(status int) {
	gatewayctx.StripTrusted(w.Header())
	w.Header().Del(origincontext.HeaderAuthorization)
	w.ResponseWriter.WriteHeader(status)
}
func (w *originResponseWriter) Write(body []byte) (int, error) {
	gatewayctx.StripTrusted(w.Header())
	w.Header().Del(origincontext.HeaderAuthorization)
	return w.ResponseWriter.Write(body)
}

func (r *Router) validateOriginSelections(routes []config.FlatRoute) error {
	known := make(map[string]bool, len(routes))
	for _, rt := range routes {
		known[rt.Method+":"+rt.Path] = true
	}
	for key := range r.originReceivers {
		if !known[key] {
			return fmt.Errorf("unknown origin forwarding route %s", key)
		}
	}
	return nil
}
