package router

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ledatu/csar-core/authntokens"
	"github.com/ledatu/csar-core/caller"
	"github.com/ledatu/csar-core/gatewayctx"
	"github.com/ledatu/csar-core/origincontext"
	"github.com/ledatu/csar/internal/apierror"
	"github.com/ledatu/csar/internal/authn"
	"github.com/ledatu/csar/internal/config"
	"github.com/ledatu/csar/internal/throttle"
	"github.com/ledatu/csar/pkg/middleware/authzmw"
)

type RootIssuer interface {
	Issue(context.Context, *origincontext.RootRequest) (*origincontext.Proof, error)
}

// WithRootIssuer supplies a router-local issuer reused across router rebuilds.
// Receiver bindings come from route configuration and remain independently reloadable.
func WithRootIssuer(issuer RootIssuer) Option {
	return func(r *Router) { r.originIssuer = issuer }
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
	if err := rt.config.ValidateOriginBinding(); err != nil {
		return err
	}
	if receiver == "" || !caller.ValidReference(receiver) || r.originIssuer == nil || rt.authentication == nil || (rt.config.OriginBinding != "account" && rt.authzConfig == nil) || rt.tenantConfig != nil {
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

func (r *Router) verifiedTenantSource(req *http.Request) (*authn.Source, string, error) {
	source, ok := authn.SourceFromContext(req.Context())
	if !ok || req.Context().Err() != nil || source.Caller == nil || !time.Now().Before(source.ValidUntil) {
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
		source, resource, account, err := r.verifiedOriginSource(req, rt.config.OriginBinding == "account")
		if err != nil {
			apierror.New(apierror.CodeAuthFailed, http.StatusUnauthorized, "verified origin source expired or unavailable").Write(w)
			return
		}
		proof, present := origincontext.ProofFromContext(req.Context())
		if !present {
			if _, hasOrigin := origincontext.FromContext(req.Context()); hasOrigin {
				apierror.New(apierror.CodeUpstreamError, http.StatusBadGateway, "verified origin credential unavailable").Write(w)
				return
			}
			hash, hashErr := origincontext.RequestHash(req)
			if hashErr != nil {
				apierror.New(apierror.CodeAuthFailed, http.StatusBadRequest, "request cannot carry origin context").Write(w)
				return
			}
			proof, err = r.originIssuer.Issue(req.Context(), &origincontext.RootRequest{Account: account, Caller: source.Caller, Receiver: receiver, Resource: resource, RequestHash: hash, SourceExpiresAt: source.ValidUntil})
			if err != nil {
				apierror.New(apierror.CodeUpstreamError, http.StatusBadGateway, "origin issuer unavailable").Write(w)
				return
			}
			if proof == nil || proof.Claims == nil || proof.Claims.Origin == nil || *proof.Claims.Origin != *source.Caller || proof.Claims.Depth != 0 || proof.Claims.RequestHash != hash || proof.Claims.ExpiresAt == nil || proof.Claims.ExpiresAt.After(source.ValidUntil) {
				apierror.New(apierror.CodeUpstreamError, http.StatusBadGateway, "invalid root context").Write(w)
				return
			}
		}
		if proof.Claims != nil && ((account == nil) != (proof.Claims.Account == nil) || account != nil && *account != *proof.Claims.Account) {
			apierror.New(apierror.CodeAccessDenied, http.StatusForbidden, "origin binding mismatch").Write(w)
			return
		}
		if proof.Claims == nil || proof.Claims.ExpiresAt == nil || proof.Token == "" || len(proof.Token) > origincontext.MaxTokenBytes || proof.Claims.Receiver != receiver || proof.Claims.Resource != resource || !time.Now().Before(proof.Claims.ExpiresAt.Time) {
			apierror.New(apierror.CodeAccessDenied, http.StatusForbidden, "origin binding expired or mismatched").Write(w)
			return
		}
		if err := gatewayctx.SetOrigin(req.Header, &gatewayctx.Origin{Caller: proof.Claims.Origin, Account: proof.Claims.Account, OperationID: proof.Claims.OperationID, ParentOperationID: proof.Claims.ParentOperationID, ExpiresAt: proof.Claims.ExpiresAt.Time}); err != nil {
			apierror.New(apierror.CodeUpstreamError, http.StatusBadGateway, "invalid origin metadata").Write(w)
			return
		}
		if account == nil {
			req.Header.Set(gatewayctx.HeaderTenant, resource)
		} else {
			req.Header.Del(gatewayctx.HeaderTenant)
		}
		req.Header.Set(origincontext.HeaderForwardedAuthorization, "Bearer "+proof.Token)
		deadline := proof.Claims.ExpiresAt.Time
		if source.ValidUntil.Before(deadline) {
			deadline = source.ValidUntil
		}
		ctx, cancel := context.WithDeadline(req.Context(), deadline)
		defer cancel()
		req = req.WithContext(origincontext.WithVerifiedProof(ctx, proof))
		auditAuthorizedContext(req)
		defer stripOriginResponseHeaders(w.Header())
		next.ServeHTTP(&originResponseWriter{ResponseWriter: w}, req)
	})
}

// Strip transport metadata before either public response delivery or cache store.
type originResponseWriter struct{ http.ResponseWriter }

func (w *originResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *originResponseWriter) WriteHeader(status int) {
	stripOriginResponseHeaders(w.Header())
	w.ResponseWriter.WriteHeader(status)
}
func (w *originResponseWriter) Write(body []byte) (int, error) {
	stripOriginResponseHeaders(w.Header())
	return w.ResponseWriter.Write(body)
}

func stripOriginResponseHeaders(h http.Header) {
	reserved := func(name string) bool {
		name = strings.ToLower(strings.TrimSpace(name))
		return strings.HasPrefix(name, "x-gateway-") || name == strings.ToLower(origincontext.HeaderAuthorization)
	}
	for name := range h {
		candidate := name
		if strings.HasPrefix(strings.ToLower(candidate), strings.ToLower(http.TrailerPrefix)) {
			candidate = candidate[len(http.TrailerPrefix):]
		}
		if reserved(candidate) {
			delete(h, name)
		}
	}
	var keep []string
	for _, value := range h.Values("Trailer") {
		for _, name := range strings.Split(value, ",") {
			if name = strings.TrimSpace(name); name != "" && !reserved(name) {
				keep = append(keep, name)
			}
		}
	}
	h.Del("Trailer")
	if len(keep) > 0 {
		h.Set("Trailer", strings.Join(keep, ", "))
	}
}

func (r *Router) validateOriginSelections(routes []config.FlatRoute) error {
	if r.originReceivers == nil {
		r.originReceivers = make(map[string]string)
	}
	known := make(map[string]bool, len(routes))
	for i := range routes {
		key := throttle.RouteKey(strings.ToUpper(routes[i].Method), routes[i].Path)
		known[key] = true
		if receiver := routes[i].Route.OriginReceiver; receiver != "" {
			if prior, exists := r.originReceivers[key]; exists && prior != receiver {
				return fmt.Errorf("conflicting origin receiver for route %s", key)
			}
			r.originReceivers[key] = receiver
		}
	}
	for key := range r.originReceivers {
		if !known[key] {
			return fmt.Errorf("unknown origin forwarding route %s", key)
		}
	}
	return nil
}

func (r *Router) verifiedOriginSource(req *http.Request, accountMode bool) (*authn.Source, string, *authntokens.AccountBinding, error) {
	if !accountMode {
		source, resource, err := r.verifiedTenantSource(req)
		return source, resource, nil, err
	}
	source, ok := authn.SourceFromContext(req.Context())
	if !ok || req.Context().Err() != nil || source.Caller == nil || !time.Now().Before(source.ValidUntil) || req.Header.Get(gatewayctx.HeaderTenant) != "" {
		return nil, "", nil, origincontext.ErrInvalid
	}
	id, err := gatewayctx.CallerFromHeaders(req.Header)
	if err != nil || id == nil || *id != *source.Caller {
		return nil, "", nil, origincontext.ErrInvalid
	}
	if claims, present := origincontext.FromContext(req.Context()); present {
		if claims.Account == nil || claims.Account.Validate(claims.Origin) != nil || validateOriginResource(req) != nil {
			return nil, "", nil, origincontext.ErrInvalid
		}
		return source, "", claims.Account.Clone(), nil
	}
	account := source.Account.Clone()
	if account == nil {
		account = &authntokens.AccountBinding{Kind: "subject"}
	}
	if account.Validate(source.Caller) != nil {
		return nil, "", nil, origincontext.ErrInvalid
	}
	return source, "", account, nil
}
