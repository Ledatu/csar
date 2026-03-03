package router

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/ledatu/csar/internal/authn"
	"github.com/ledatu/csar/internal/cache"
	"github.com/ledatu/csar/internal/config"
	"github.com/ledatu/csar/internal/cors"
	"github.com/ledatu/csar/internal/dlp"
	"github.com/ledatu/csar/internal/loadbalancer"
	"github.com/ledatu/csar/internal/metrics"
	"github.com/ledatu/csar/internal/proxy"
	"github.com/ledatu/csar/internal/resilience"
	"github.com/ledatu/csar/internal/retry"
	"github.com/ledatu/csar/internal/telemetry"
	"github.com/ledatu/csar/internal/tenant"
	"github.com/ledatu/csar/internal/throttle"
	"github.com/ledatu/csar/pkg/middleware"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// route holds a compiled route with its proxy and throttler.
type route struct {
	config         config.RouteConfig
	proxy          *proxy.ReverseProxy
	loadBalancer   http.Handler              // nil if no load balancing; otherwise a load-balancing handler
	throttler      *throttle.Throttler       // nil if no traffic shaping configured
	circuitBreaker *resilience.CircuitBreaker // nil if no resilience configured
	retryHandler   http.Handler              // proxy wrapped with retry middleware (nil = use proxy directly)
	routeKey       string                    // "METHOD:PATH"
	injectHeaders  []string                  // headers to strip/inject for security (e.g. ["Authorization", "X-Client-Secret"])
	allowCIDRs     []*net.IPNet              // nil = use global; empty after init = deny all (shouldn't happen)
	hasRouteACL    bool                      // true if this route has its own x-csar-access (overrides global)
	trustProxy     bool                      // route-scoped: trust X-Forwarded-For / X-Real-IP for this route
	pathPattern    *regexp.Regexp            // compiled regex when path contains {var:regex} variables
	pathRewrite    string                    // rewrite template with $1/$2 back-references
	method         string                    // HTTP method for this route (uppercase)
	originalPath   string                    // the original path definition (e.g. "/api/v1/users/{id:[0-9]+}")
	jwtConfig      *authn.Config             // nil if no inbound JWT validation
	dlpConfig      *dlp.Config               // nil if no response redaction
	tenantConfig   *tenant.Config            // nil if no multi-tenant routing
	corsConfig     *config.CORSConfig        // nil if no CORS configuration
	cacheConfig    *cache.Config             // nil if no response caching
}

// Router is the core stateless API router.
// It matches incoming requests to configured routes and applies
// the pipeline: ip_check -> cors -> security_inject -> throttle.Wait -> circuit_breaker -> proxy.Forward.
type Router struct {
	routes           map[string]*route // keyed by "METHOD:PATH" (exact/prefix routes)
	regexRoutes      []*route          // routes with {var:regex} patterns (checked after exact match)
	cfg              *config.Config
	logger           *slog.Logger
	metrics          *metrics.Metrics        // nil if no metrics
	telemetry        *telemetry.Provider     // nil if no telemetry
	authInjector     *middleware.AuthInjector // nil if no auth injection configured
	jwtValidator     *authn.JWTValidator     // nil if no route uses JWT validation
	dlpRedactor      *dlp.Redactor           // nil if no route uses DLP redaction
	tenantRouter     *tenant.Router          // nil if no route uses tenant routing
	responseCache    *cache.ResponseCache    // nil if no route uses response caching
	ssrfProtection   *proxy.SSRFProtection   // nil if SSRF protection is disabled
	throttleManager  *throttle.ThrottleManager // manages all per-route throttlers
	globalCIDRs      []*net.IPNet            // parsed global access_control.allow_cidrs
	hasGlobalACL     bool                    // true if global access_control is configured
	globalTrustProxy bool                    // global default for trust_proxy (from access_control)
}

// Option configures the Router.
type Option func(*Router)

// WithMetrics adds Prometheus metrics to the router.
func WithMetrics(m *metrics.Metrics) Option {
	return func(r *Router) { r.metrics = m }
}

// WithTelemetry adds OpenTelemetry tracing to the router.
func WithTelemetry(p *telemetry.Provider) Option {
	return func(r *Router) { r.telemetry = p }
}

// WithAuthInjector sets the AuthInjector used for routes with x-csar-security config.
func WithAuthInjector(a *middleware.AuthInjector) Option {
	return func(r *Router) { r.authInjector = a }
}

// WithSSRFProtection enables SSRF protection on all outbound proxy connections.
func WithSSRFProtection(p *proxy.SSRFProtection) Option {
	return func(r *Router) { r.ssrfProtection = p }
}

// New creates a new Router from the given configuration.
func New(cfg *config.Config, logger *slog.Logger, opts ...Option) (*Router, error) {
	r := &Router{
		routes:          make(map[string]*route),
		cfg:             cfg,
		logger:          logger,
		throttleManager: throttle.NewManager(),
	}

	for _, opt := range opts {
		opt(r)
	}

	// Parse global access control CIDRs
	if cfg.AccessControl != nil && len(cfg.AccessControl.AllowCIDRs) > 0 {
		nets, err := parseCIDRList(cfg.AccessControl.AllowCIDRs)
		if err != nil {
			return nil, fmt.Errorf("global access_control: %w", err)
		}
		r.globalCIDRs = nets
		r.hasGlobalACL = true
		r.globalTrustProxy = cfg.AccessControl.TrustProxy
		logger.Info("global IP allowlist configured",
			"cidrs", cfg.AccessControl.AllowCIDRs,
			"trust_proxy", r.globalTrustProxy,
		)
	}

	// Build circuit breaker manager from config
	cbManager := resilience.NewCircuitBreakerManager()
	for name, cbCfg := range cfg.CircuitBreakers {
		cbManager.Register(name, resilience.CircuitBreakerConfig{
			MaxRequests:      cbCfg.MaxRequests,
			Interval:         cbCfg.Interval.Duration,
			Timeout:          cbCfg.Timeout.Duration,
			FailureThreshold: cbCfg.FailureThreshold,
		})
		logger.Info("registered circuit breaker", "name", name)
	}

	for _, fr := range cfg.FlatRoutes() {
		// Build proxy options (TLS, SSRF protection, etc.)
		var proxyOpts []proxy.Option
		if bt := fr.Route.Backend.TLS; bt != nil {
			proxyOpts = append(proxyOpts, proxy.WithTLS(&proxy.TLSConfig{
				InsecureSkipVerify: bt.InsecureSkipVerify,
				CAFile:             bt.CAFile,
				CertFile:           bt.CertFile,
				KeyFile:            bt.KeyFile,
			}))
		}
		// Apply SSRF protection to all outbound connections (audit §2.3.2).
		if r.ssrfProtection != nil {
			proxyOpts = append(proxyOpts, proxy.WithSSRFProtection(r.ssrfProtection))
		}

		rp, err := proxy.New(fr.Route.Backend.TargetURL, proxyOpts...)
		if err != nil {
			return nil, fmt.Errorf("creating proxy for %s %s: %w", fr.Method, fr.Path, err)
		}

		key := throttle.RouteKey(strings.ToUpper(fr.Method), fr.Path)

		rt := &route{
			config:       fr.Route,
			proxy:        rp,
			routeKey:     key,
			method:       strings.ToUpper(fr.Method),
			originalPath: fr.Path,
		}

		// Set up load balancing if multiple targets are configured (audit §3.2 Criticism 3).
		allTargets := fr.Route.Backend.AllTargets()
		if len(allTargets) > 1 {
			strategy := loadbalancer.RoundRobin
			if fr.Route.Backend.LoadBalancer == "random" {
				strategy = loadbalancer.Random
			}
			lb, err := loadbalancer.New(allTargets, strategy, logger)
			if err != nil {
				return nil, fmt.Errorf("creating load balancer for %s %s: %w", fr.Method, fr.Path, err)
			}

			// Start active health checks if configured.
			if hc := fr.Route.Backend.HealthCheck; hc != nil && hc.Enabled {
				lb.StartHealthChecks(context.Background(), loadbalancer.HealthCheckConfig{
					Enabled:            true,
					Mode:               hc.Mode,
					Path:               hc.Path,
					Interval:           hc.Interval.Duration,
					Timeout:            hc.Timeout.Duration,
					UnhealthyThreshold: hc.UnhealthyThreshold,
					HealthyThreshold:   hc.HealthyThreshold,
				})
				logger.Info("active health checks started for route",
					"route", key,
					"mode", hc.Mode,
					"interval", hc.Interval.Duration,
				)
			}

			rt.loadBalancer = lb
			logger.Info("load balancer enabled",
				"route", key,
				"strategy", string(strategy),
				"targets", len(allTargets),
			)
		}

		// Compile regex path pattern if path contains {var:regex} segments.
		if pat, hasRegex := compilePathPattern(fr.Path); hasRegex {
			rt.pathPattern = pat
			if fr.Route.Backend.PathRewrite != "" {
				rt.pathRewrite = fr.Route.Backend.PathRewrite
			}
			logger.Info("registered regex route",
				"method", rt.method,
				"path", fr.Path,
				"pattern", pat.String(),
			)
		}

		// Track which headers to strip for security injection.
		// Fail closed: if a route declares security config but no AuthInjector
		// is provided, refuse to start — never silently proxy without credentials.
		if len(fr.Route.Security) > 0 {
			if r.authInjector == nil {
				return nil, fmt.Errorf("route %s has x-csar-security config but no AuthInjector is configured — "+
					"provide WithAuthInjector() or remove the security config", key)
			}
			for _, sec := range fr.Route.Security {
				if sec.InjectHeader != "" {
					rt.injectHeaders = append(rt.injectHeaders, sec.InjectHeader)
				}
			}
			logger.Info("route has security injection configured",
				"route", key,
				"credentials", len(fr.Route.Security),
				"inject_headers", rt.injectHeaders,
			)
		}

		// Parse per-route access control CIDRs.
		// Per-route trust_proxy is stored on the route itself — no global side effects.
		if fr.Route.Access != nil && len(fr.Route.Access.AllowCIDRs) > 0 {
			nets, err := parseCIDRList(fr.Route.Access.AllowCIDRs)
			if err != nil {
				return nil, fmt.Errorf("route %s x-csar-access: %w", key, err)
			}
			rt.allowCIDRs = nets
			rt.hasRouteACL = true
			rt.trustProxy = fr.Route.Access.TrustProxy
			logger.Info("route IP allowlist configured",
				"route", key,
				"cidrs", fr.Route.Access.AllowCIDRs,
				"trust_proxy", rt.trustProxy,
			)
		} else {
			// No per-route ACL — inherit global trust_proxy setting
			rt.trustProxy = r.globalTrustProxy
		}

		// Set up throttler if traffic config is present
		if fr.Route.Traffic != nil {
			t := fr.Route.Traffic
			r.throttleManager.Register(key, t.RPS, t.Burst, t.MaxWait.Duration)
			rt.throttler = r.throttleManager.Get(key)
			logger.Info("registered throttled route",
				"method", strings.ToUpper(fr.Method),
				"path", fr.Path,
				"rps", t.RPS,
				"burst", t.Burst,
				"max_wait", t.MaxWait.Duration,
			)
		} else {
			logger.Info("registered route (no throttle)",
				"method", strings.ToUpper(fr.Method),
				"path", fr.Path,
			)
		}

		// Set up circuit breaker if resilience config is present
		if fr.Route.Resilience != nil && fr.Route.Resilience.CircuitBreaker != "" {
			cb := cbManager.Get(fr.Route.Resilience.CircuitBreaker)
			if cb != nil {
				rt.circuitBreaker = cb
				logger.Info("route uses circuit breaker",
					"route", key,
					"breaker", fr.Route.Resilience.CircuitBreaker,
				)
			}
		}

		// Set up retry middleware if retry config is present (audit §3.1).
		if fr.Route.Retry != nil {
			retryCfg := retry.Config{
				MaxAttempts: fr.Route.Retry.MaxAttempts,
				Backoff:     fr.Route.Retry.Backoff.Duration,
				MaxBackoff:  fr.Route.Retry.MaxBackoff.Duration,
			}
			if len(fr.Route.Retry.RetryableStatusCodes) > 0 {
				retryCfg.RetryableStatusCodes = make(map[int]struct{}, len(fr.Route.Retry.RetryableStatusCodes))
				for _, code := range fr.Route.Retry.RetryableStatusCodes {
					retryCfg.RetryableStatusCodes[code] = struct{}{}
				}
			}
			if len(fr.Route.Retry.RetryableMethods) > 0 {
				retryCfg.RetryableMethods = make(map[string]struct{}, len(fr.Route.Retry.RetryableMethods))
				for _, m := range fr.Route.Retry.RetryableMethods {
					retryCfg.RetryableMethods[strings.ToUpper(m)] = struct{}{}
				}
			}
			rt.retryHandler = retry.New(rt.proxy, retryCfg, logger)
			logger.Info("retry middleware enabled",
				"route", key,
				"max_attempts", retryCfg.MaxAttempts,
				"backoff", retryCfg.Backoff,
			)
		}

		// Set up JWT validation if auth-validate config is present (audit §3.3.1).
		if fr.Route.AuthValidate != nil {
			if r.jwtValidator == nil {
				r.jwtValidator = authn.NewJWTValidator(logger)
			}
			rt.jwtConfig = &authn.Config{
				JWKSURL:        fr.Route.AuthValidate.JWKSURL,
				Issuer:         fr.Route.AuthValidate.Issuer,
				Audiences:      fr.Route.AuthValidate.Audiences,
				HeaderName:     fr.Route.AuthValidate.HeaderName,
				TokenPrefix:    fr.Route.AuthValidate.TokenPrefix,
				CacheTTL:       fr.Route.AuthValidate.CacheTTL.Duration,
				RequiredClaims: fr.Route.AuthValidate.RequiredClaims,
				ForwardClaims:  fr.Route.AuthValidate.ForwardClaims,
			}
			logger.Info("JWT validation enabled",
				"route", key,
				"jwks_url", fr.Route.AuthValidate.JWKSURL,
			)
		}

		// Set up DLP redaction if redact config is present (audit §3.3.2).
		if fr.Route.Redact != nil && fr.Route.Redact.IsEnabled() {
			if r.dlpRedactor == nil {
				r.dlpRedactor = dlp.NewRedactor(logger)
			}
			mask := fr.Route.Redact.Mask
			if mask == "" {
				mask = "***REDACTED***"
			}
			rt.dlpConfig = &dlp.Config{
				Fields: fr.Route.Redact.Fields,
				Mask:   mask,
			}
			logger.Info("DLP redaction enabled",
				"route", key,
				"fields", fr.Route.Redact.Fields,
			)
		}

		// Set up multi-tenant routing if tenant config is present (audit §3.3.3).
		if fr.Route.Tenant != nil {
			if r.tenantRouter == nil {
				r.tenantRouter = tenant.NewRouter(logger)
			}
			rt.tenantConfig = &tenant.Config{
				Header:   fr.Route.Tenant.Header,
				Backends: fr.Route.Tenant.Backends,
				Default:  fr.Route.Tenant.Default,
			}
			logger.Info("multi-tenant routing enabled",
				"route", key,
				"header", fr.Route.Tenant.Header,
				"tenants", len(fr.Route.Tenant.Backends),
			)
		}

		// Set up CORS config if present (audit §3.2 Criticism 5).
		if fr.Route.CORS != nil {
			rt.corsConfig = fr.Route.CORS
			logger.Info("CORS enabled",
				"route", key,
				"origins", fr.Route.CORS.AllowedOrigins,
			)
		}

		// Set up response caching if cache config is present (audit §3.2 Criticism 4).
		if fr.Route.Cache != nil && fr.Route.Cache.IsEnabled() {
			if r.responseCache == nil {
				r.responseCache = cache.NewResponseCache(logger)
			}
			cacheCfg := &cache.Config{
				TTL:         fr.Route.Cache.TTL.Duration,
				MaxEntries:  fr.Route.Cache.MaxEntries,
				MaxBodySize: fr.Route.Cache.MaxBodySize,
			}
			if len(fr.Route.Cache.Methods) > 0 {
				cacheCfg.Methods = make(map[string]struct{}, len(fr.Route.Cache.Methods))
				for _, m := range fr.Route.Cache.Methods {
					cacheCfg.Methods[strings.ToUpper(m)] = struct{}{}
				}
			}
			rt.cacheConfig = cacheCfg
			logger.Info("response caching enabled",
				"route", key,
				"ttl", cacheCfg.TTL,
				"max_entries", cacheCfg.MaxEntries,
			)
		}

		// Apply max_response_size to DLP config if set (audit §2.3.4).
		if fr.Route.MaxResponseSize > 0 && rt.dlpConfig != nil {
			rt.dlpConfig.MaxResponseSize = fr.Route.MaxResponseSize
			logger.Info("max_response_size applied to DLP",
				"route", key,
				"max_bytes", fr.Route.MaxResponseSize,
			)
		}

		if rt.pathPattern != nil {
			r.regexRoutes = append(r.regexRoutes, rt)
		} else {
			r.routes[key] = rt
		}
	}

	return r, nil
}

// ServeHTTP implements the http.Handler interface.
// Pipeline: match route -> strip sensitive headers -> security inject -> throttle.Wait -> circuit_breaker -> proxy.Forward
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	rt, captures := r.matchRoute(req.Method, req.URL.Path)
	if rt == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, `{"error":"no route matched","path":%q,"method":%q}`, req.URL.Path, req.Method)
		return
	}

	// Apply path rewriting for regex routes (audit §3.2).
	if rt.pathRewrite != "" && len(captures) > 0 {
		rewritten := rt.pathPattern.ReplaceAllString(req.URL.Path, rt.pathRewrite)
		req.URL.Path = rewritten
		req.URL.RawPath = "" // reset encoded path
	}

	// Step -2: CORS preflight handling (checked before IP access control).
	// This allows browsers to make OPTIONS preflight requests even from
	// restricted networks (audit §3.2 Criticism 5).
	if rt.corsConfig != nil {
		corsMiddleware := cors.New()
		corsCfg := cors.Config{
			AllowedOrigins:   rt.corsConfig.AllowedOrigins,
			AllowedMethods:   rt.corsConfig.AllowedMethods,
			AllowedHeaders:   rt.corsConfig.AllowedHeaders,
			ExposedHeaders:   rt.corsConfig.ExposedHeaders,
			AllowCredentials: rt.corsConfig.AllowCredentials,
			MaxAge:           rt.corsConfig.MaxAge,
		}

		// For OPTIONS preflight, handle immediately without further pipeline.
		if req.Method == http.MethodOptions && req.Header.Get("Origin") != "" {
			corsMiddleware.Wrap(corsCfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// no-op: preflight already handled by CORS middleware.
			})).ServeHTTP(w, req)
			return
		}

		// For normal requests, wrap the remaining pipeline with CORS headers.
		corsMiddleware.Wrap(corsCfg, http.HandlerFunc(func(cw http.ResponseWriter, cr *http.Request) {
			r.serveWithIPCheck(cw, cr, rt)
		})).ServeHTTP(w, req)
		return
	}

	r.serveWithIPCheck(w, req, rt)
}

// serveWithIPCheck continues the pipeline after CORS processing.
func (r *Router) serveWithIPCheck(w http.ResponseWriter, req *http.Request, rt *route) {
	// Step -1: IP access control (checked before anything else)
	if !r.checkIPAccess(rt, req) {
		clientIP := extractClientIP(req, rt.trustProxy)
		r.logger.Warn("request denied by IP allowlist",
			"client_ip", clientIP,
			"route", rt.routeKey,
		)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, `{"error":"access denied","client_ip":%q}`, clientIP)
		return
	}

	// Start tracing span
	var span trace.Span
	if r.telemetry != nil {
		req, span = r.telemetry.StartSpan(req, "csar.route",
			attribute.String("csar.route", rt.routeKey),
			attribute.String("http.method", req.Method),
			attribute.String("http.path", req.URL.Path),
		)
		defer span.End()
	}

	// Step 0a: Inbound JWT validation (audit §3.3.1).
	// If the route requires JWT auth-validate, validate the token before proceeding.
	if rt.jwtConfig != nil && r.jwtValidator != nil {
		validated := r.jwtValidator.Wrap(*rt.jwtConfig, http.HandlerFunc(func(vw http.ResponseWriter, vr *http.Request) {
			r.serveAfterAuth(vw, vr, rt)
		}))
		validated.ServeHTTP(w, req)
		return
	}

	r.serveAfterAuth(w, req, rt)
}

// serveAfterAuth runs the pipeline after inbound JWT validation.
// Pipeline continues: static headers -> security inject -> throttle -> circuit breaker -> proxy.
func (r *Router) serveAfterAuth(w http.ResponseWriter, req *http.Request, rt *route) {
	// Step 0b-0: Inject static headers from x-csar-headers.
	// These are fixed per-route headers like User-Agent or x-client-secret
	// that don't need KMS decryption.
	for k, v := range rt.config.Headers {
		req.Header.Set(k, v)
	}

	// Step 0b-1: Security — strip incoming headers and inject decrypted tokens.
	// The router refuses to start if security config is set without an injector,
	// so authInjector is guaranteed non-nil here. The nil check is purely defensive.
	if len(rt.config.Security) > 0 && len(rt.injectHeaders) > 0 {
		// Strip all client-supplied values for inject headers to prevent spoofing.
		for _, h := range rt.injectHeaders {
			req.Header.Del(h)
		}

		if r.authInjector == nil {
			// Fail closed: should never happen (caught at init), but don't proxy without creds.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `{"error":"security injection required but not configured"}`)
			return
		}

		// Build a handler chain: pipeline <- security[n-1] <- ... <- security[0].
		// Each Wrap call creates a handler that resolves + injects one credential,
		// then calls the next handler in the chain.
		var handler http.Handler = http.HandlerFunc(func(iw http.ResponseWriter, ir *http.Request) {
			r.servePipeline(iw, ir, rt)
		})
		for i := len(rt.config.Security) - 1; i >= 0; i-- {
			sec := rt.config.Security[i]
			authCfg := middleware.AuthInjectorConfig{
				TokenRef:     sec.TokenRef,
				KMSKeyID:     sec.KMSKeyID,
				InjectHeader: sec.InjectHeader,
				InjectFormat: sec.InjectFormat,
				OnKMSError:   sec.OnKMSError,
				TokenVersion: sec.TokenVersion,
			}
			handler = r.authInjector.Wrap(authCfg, handler)
		}
		handler.ServeHTTP(w, req)
		return
	}

	r.servePipeline(w, req, rt)
}

// servePipeline runs the throttle -> circuit breaker -> proxy pipeline.
func (r *Router) servePipeline(w http.ResponseWriter, req *http.Request, rt *route) {
	// Step 1: Throttle (smoothing — wait instead of reject)
	if rt.throttler != nil {
		// Update queue depth metric
		if r.metrics != nil {
			r.metrics.SetThrottleQueueDepth(rt.routeKey, rt.throttler.Waiting()+1)
		}

		waitStart := time.Now()
		err := rt.throttler.Wait(req.Context())
		waitDur := time.Since(waitStart)

		if r.metrics != nil {
			r.metrics.SetThrottleQueueDepth(rt.routeKey, rt.throttler.Waiting())
		}

		if err != nil {
			if r.metrics != nil {
				r.metrics.RecordThrottleWait(rt.routeKey, waitDur, true)
			}
			r.logger.Warn("request throttled",
				"path", req.URL.Path,
				"method", req.Method,
				"error", err,
			)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "5")
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, `{"error":"service temporarily unavailable","detail":%q}`, err.Error())
			return
		}

		if r.metrics != nil {
			r.metrics.RecordThrottleWait(rt.routeKey, waitDur, false)
		}
	}

	// Step 2: Circuit breaker
	if rt.circuitBreaker != nil {
		if r.metrics != nil {
			r.metrics.SetCircuitBreakerState(rt.routeKey, int(rt.circuitBreaker.State()))
		}

		proxyCalled := false
		err := rt.circuitBreaker.Execute(func() error {
			proxyCalled = true
			// Step 3: Proxy to upstream (inside circuit breaker)
			rec := &statusCapture{ResponseWriter: w, statusCode: 200}
			upstreamStart := time.Now()
			r.upstreamHandler(rt).ServeHTTP(rec, req)
			upstreamDur := time.Since(upstreamStart)

			if r.metrics != nil {
				r.metrics.RecordUpstream(rt.routeKey, rec.statusCode, upstreamDur)
			}

			if rec.statusCode >= 500 {
				return fmt.Errorf("upstream returned %d", rec.statusCode)
			}
			return nil
		})

		if err != nil {
			if r.metrics != nil {
				r.metrics.SetCircuitBreakerState(rt.routeKey, int(rt.circuitBreaker.State()))
				if rt.circuitBreaker.State() == resilience.StateOpen {
					r.metrics.RecordCircuitBreakerTrip(rt.routeKey)
				}
			}
			// Only write an error response if the proxy was never called
			// (circuit was already open). If the proxy was called and
			// returned 5xx, the response is already written to the client.
			if !proxyCalled {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusServiceUnavailable)
				fmt.Fprintf(w, `{"error":"circuit breaker open","route":%q}`, rt.routeKey)
			}
		}
		return
	}

	// Step 3 (no circuit breaker): Proxy to upstream directly
	upstreamStart := time.Now()
	r.upstreamHandler(rt).ServeHTTP(w, req)
	if r.metrics != nil {
		r.metrics.RecordUpstream(rt.routeKey, 0, time.Since(upstreamStart))
	}
}

// upstreamHandler returns the handler that proxies to the upstream.
// Applies middleware layers in order: DLP wraps retry wraps proxy.
// Multi-tenant routing replaces the proxy entirely.
//
// Streaming protocol bypass (audit §3.2): WebSocket upgrades and SSE
// connections skip DLP and Retry middleware to avoid buffering breakage.
func (r *Router) upstreamHandler(rt *route) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Streaming protocol bypass: skip buffering middleware for WebSocket/SSE.
		if isStreamingRequest(req) {
			r.logger.Debug("streaming protocol detected, bypassing DLP/Retry",
				"route", rt.routeKey,
				"upgrade", req.Header.Get("Connection"),
			)
			r.baseProxy(rt).ServeHTTP(w, req)
			return
		}

		// Base handler: tenant routing OR retry-wrapped proxy OR plain proxy.
		handler := r.baseProxy(rt)
		if rt.retryHandler != nil {
			handler = rt.retryHandler
		}

		// Wrap with DLP redaction (audit §3.3.2).
		if rt.dlpConfig != nil && r.dlpRedactor != nil {
			handler = r.dlpRedactor.Wrap(*rt.dlpConfig, handler)
		}

		// Wrap with response caching (audit §3.3).
		if rt.cacheConfig != nil && r.responseCache != nil {
			handler = r.responseCache.Wrap(*rt.cacheConfig, handler)
		}

		handler.ServeHTTP(w, req)
	})
}

// baseProxy returns the base proxy handler (tenant routing or direct proxy).
func (r *Router) baseProxy(rt *route) http.Handler {
	if rt.tenantConfig != nil && r.tenantRouter != nil {
		return r.tenantRouter.Proxy(*rt.tenantConfig, nil)
	}
	if rt.loadBalancer != nil {
		return rt.loadBalancer
	}
	return rt.proxy
}

// isStreamingRequest detects WebSocket upgrade requests and SSE connections.
// These must bypass buffering middleware (DLP, Retry) to function correctly.
func isStreamingRequest(r *http.Request) bool {
	// WebSocket: Connection: Upgrade + Upgrade: websocket
	conn := strings.ToLower(r.Header.Get("Connection"))
	upgrade := strings.ToLower(r.Header.Get("Upgrade"))
	if strings.Contains(conn, "upgrade") && upgrade == "websocket" {
		return true
	}

	// SSE: Accept: text/event-stream
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "text/event-stream") {
		return true
	}

	return false
}

// matchRoute finds the best matching route for the given method and path.
// Priority order: exact match → prefix match → regex match.
func (r *Router) matchRoute(method, path string) (*route, []string) {
	method = strings.ToUpper(method)

	// Try exact match first
	key := throttle.RouteKey(method, path)
	if rt, ok := r.routes[key]; ok {
		return rt, nil
	}

	// Try prefix match: check if any registered path is a prefix
	// e.g. "/api/v1" matches a route registered as "/api/v1"
	// and "/api/v1/foo" matches "/api/v1" if it's a prefix route
	var bestMatch *route
	bestLen := 0

	for routeKey, rt := range r.routes {
		parts := strings.SplitN(routeKey, ":", 2)
		if len(parts) != 2 {
			continue
		}
		routeMethod, routePath := parts[0], parts[1]
		if routeMethod != method {
			continue
		}

		// Match only on path boundaries: exact match OR next char is '/'.
		// This prevents "/api/v1evil" from matching route "/api/v1".
		if strings.HasPrefix(path, routePath) &&
			(len(path) == len(routePath) || path[len(routePath)] == '/') &&
			len(routePath) > bestLen {
			bestMatch = rt
			bestLen = len(routePath)
		}
	}

	if bestMatch != nil {
		return bestMatch, nil
	}

	// Try regex routes (audit §3.2: path rewriting & regex matching)
	for _, rt := range r.regexRoutes {
		if rt.method != method {
			continue
		}
		if matches := rt.pathPattern.FindStringSubmatch(path); matches != nil {
			return rt, matches
		}
	}

	return nil, nil
}

// GetThrottler returns the throttler for a given route key (for observability).
func (r *Router) GetThrottler(method, path string) *throttle.Throttler {
	key := throttle.RouteKey(strings.ToUpper(method), path)
	if rt, ok := r.routes[key]; ok {
		return rt.throttler
	}
	return nil
}

// ThrottleManager returns the shared ThrottleManager so external components
// (e.g. the coordinator client) can dynamically update per-route quotas.
func (r *Router) ThrottleManager() *throttle.ThrottleManager {
	return r.throttleManager
}

// AuthInjector returns the AuthInjector so external components
// (e.g. the coordinator client) can invalidate stale tokens on rotation events.
func (r *Router) AuthInjector() *middleware.AuthInjector {
	return r.authInjector
}

// checkIPAccess returns true if the request is allowed by IP access control.
// Per-route ACL overrides global. If neither is configured, all IPs are allowed.
// trust_proxy is always route-scoped — no global side effects.
func (r *Router) checkIPAccess(rt *route, req *http.Request) bool {
	var cidrs []*net.IPNet
	if rt.hasRouteACL {
		cidrs = rt.allowCIDRs
	} else if r.hasGlobalACL {
		cidrs = r.globalCIDRs
	} else {
		return true // no ACL configured
	}

	clientIP := extractClientIP(req, rt.trustProxy)
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false // unparseable IP is denied
	}

	for _, cidr := range cidrs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// extractClientIP gets the client IP from the request.
// If trustProxy is true, X-Forwarded-For and X-Real-IP are checked first.
//
// SECURITY: We take the RIGHTMOST IP in X-Forwarded-For, because the last
// proxy in the chain appends the real client IP. Taking the leftmost is
// trivially spoofable: an attacker sends "X-Forwarded-For: spoofed, real"
// and the proxy appends the actual IP, making leftmost the spoofed one.
//
// This is a package-level function (not a method) since trust is route-scoped.
func extractClientIP(req *http.Request, trustProxy bool) string {
	if trustProxy {
		// X-Forwarded-For: client, proxy1, proxy2
		// The rightmost IP is the one appended by the last (trusted) proxy.
		if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			// Walk from right to left, take the first non-empty entry.
			for i := len(parts) - 1; i >= 0; i-- {
				ip := strings.TrimSpace(parts[i])
				if ip != "" {
					return ip
				}
			}
		}
		if xri := req.Header.Get("X-Real-IP"); xri != "" {
			return strings.TrimSpace(xri)
		}
	}

	// Fall back to RemoteAddr (host:port)
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr // best effort
	}
	return host
}

// parseCIDRList parses a list of IP addresses and CIDR ranges into []*net.IPNet.
// Plain IPs are converted to /32 (IPv4) or /128 (IPv6).
func parseCIDRList(entries []string) ([]*net.IPNet, error) {
	var nets []*net.IPNet
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		if strings.Contains(entry, "/") {
			_, ipNet, err := net.ParseCIDR(entry)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q: %w", entry, err)
			}
			nets = append(nets, ipNet)
		} else {
			ip := net.ParseIP(entry)
			if ip == nil {
				return nil, fmt.Errorf("invalid IP address %q", entry)
			}
			// Convert plain IP to /32 or /128
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			nets = append(nets, &net.IPNet{
				IP:   ip,
				Mask: net.CIDRMask(bits, bits),
			})
		}
	}
	return nets, nil
}

// maxRegexLength is the maximum allowed length for a compiled regex pattern string.
// This prevents ReDoS attacks from overly complex regex configurations (audit §2.2.4).
const maxRegexLength = 1024

// dangerousPatterns detects regex constructs known to cause catastrophic backtracking.
// These include nested quantifiers like (a+)+, (a*)+, (a+)*, etc.
var dangerousPatterns = regexp.MustCompile(`\([^)]*[+*][^)]*\)[+*]|\(\?[^)]*\)[+*]`)

// compilePathPattern converts a path containing {var:regex} segments into a
// compiled regexp. Returns the regexp and true if the path has regex variables,
// or nil and false for plain paths.
//
// Security audit §2.2.4: Validates regex complexity to prevent ReDoS attacks.
// Rejects patterns that are too long or contain known catastrophic backtracking constructs.
//
// Examples:
//
//	"/api/v1/users/{id:[0-9]+}"       → "^/api/v1/users/([0-9]+)$"
//	"/api/{version:v[0-9]+}/items/{id}" → "^/api/(v[0-9]+)/items/([^/]+)$"
//	"/api/v1/products"                → nil, false (no variables)
func compilePathPattern(path string) (*regexp.Regexp, bool) {
	// Quick check: if no '{' then no variables.
	if !strings.Contains(path, "{") {
		return nil, false
	}

	var b strings.Builder
	b.WriteString("^")

	i := 0
	for i < len(path) {
		brace := strings.IndexByte(path[i:], '{')
		if brace < 0 {
			b.WriteString(regexp.QuoteMeta(path[i:]))
			break
		}
		// Write literal part before the brace
		b.WriteString(regexp.QuoteMeta(path[i : i+brace]))

		// Find closing brace
		rest := path[i+brace:]
		closeBrace := strings.IndexByte(rest, '}')
		if closeBrace < 0 {
			// Malformed — treat rest as literal
			b.WriteString(regexp.QuoteMeta(rest))
			i = len(path)
			break
		}

		// Extract variable content: "name:pattern" or just "name"
		varContent := rest[1:closeBrace]
		if colonIdx := strings.IndexByte(varContent, ':'); colonIdx >= 0 {
			// Has explicit regex: {name:pattern}
			userPattern := varContent[colonIdx+1:]

			// ReDoS protection: reject dangerous patterns (audit §2.2.4).
			if dangerousPatterns.MatchString(userPattern) {
				return nil, false
			}

			b.WriteString("(")
			b.WriteString(userPattern)
			b.WriteString(")")
		} else {
			// Plain variable: {name} → match any non-slash segment
			b.WriteString("([^/]+)")
		}

		i += brace + closeBrace + 1
	}

	b.WriteString("$")

	pattern := b.String()

	// ReDoS protection: reject overly long patterns (audit §2.2.4).
	if len(pattern) > maxRegexLength {
		return nil, false
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, false
	}
	return re, true
}

// statusCapture captures the HTTP status code without blocking the response.
type statusCapture struct {
	http.ResponseWriter
	statusCode int
}

func (s *statusCapture) WriteHeader(code int) {
	s.statusCode = code
	s.ResponseWriter.WriteHeader(code)
}
