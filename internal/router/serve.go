package router

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/ledatu/csar-core/httpmiddleware"
	"github.com/ledatu/csar/internal/apierror"
	"github.com/ledatu/csar/internal/proxy"
	"github.com/ledatu/csar/internal/resilience"
	"github.com/ledatu/csar/internal/throttle"
	"github.com/ledatu/csar/pkg/middleware"
	"github.com/ledatu/csar/pkg/middleware/authzmw"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// ProtocolVersion is the CSAR wire protocol version.
// Bump when breaking changes are made to header semantics.
const ProtocolVersion = "1"

// requestID extracts the request ID from the request using the configured header.
func (r *Router) requestID(req *http.Request) string {
	return req.Header.Get(r.reqIDHeader)
}

// ServeHTTP implements the http.Handler interface.
// Pipeline: match route -> strip sensitive headers -> security inject -> throttle.Wait -> circuit_breaker -> proxy.Forward
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// Emit protocol version on every response so SDK clients can detect compatibility.
	w.Header().Set("X-CSAR-Protocol-Version", ProtocolVersion)

	// Debug/traceability headers: generate X-Request-ID if not present.
	reqIDHeader := r.reqIDHeader
	requestID := req.Header.Get(reqIDHeader)
	if requestID == "" {
		requestID = uuid.New().String()
		req.Header.Set(reqIDHeader, requestID)
	}
	w.Header().Set(reqIDHeader, requestID)

	rt, captures := r.matchRoute(req.Method, req.URL.Path)
	if rt == nil {
		apierror.New(apierror.CodeRouteNotFound, http.StatusNotFound,
			"no route matched").WithDetail(req.Method + " " + req.URL.Path).
			WithRequestID(requestID).Write(w)
		return
	}

	// Build path variable map from regex captures BEFORE path rewrite.
	// captures[0] is the full match; captures[1..n] correspond to pathVarNames.
	if len(rt.pathVarNames) > 0 && len(captures) > len(rt.pathVarNames) {
		pathVars := make(map[string]string, len(rt.pathVarNames))
		for i, name := range rt.pathVarNames {
			pathVars[name] = captures[i+1]
		}
		req = req.WithContext(authzmw.WithPathVars(req.Context(), pathVars))
	}

	// Emit route ID debug header when enabled.
	if r.cfg.DebugHeaders != nil && r.cfg.DebugHeaders.Enabled {
		emitRouteID := r.cfg.DebugHeaders.EmitRouteID == nil || *r.cfg.DebugHeaders.EmitRouteID
		if emitRouteID {
			w.Header().Set("X-CSAR-Route-ID", rt.routeKey)
		}
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
		reqIDHeader := r.reqIDHeader
		if reqIDHeader == "" {
			reqIDHeader = "X-Request-ID"
		}
		csarExposed := []string{
			"X-CSAR-Wait-MS", "X-CSAR-Status", "Retry-After",
			"X-CSAR-Protocol-Version", reqIDHeader, "X-CSAR-Route-ID",
		}
		corsMw := httpmiddleware.CORS(&httpmiddleware.CORSConfig{
			AllowedOrigins:   rt.corsConfig.AllowedOrigins,
			AllowedMethods:   rt.corsConfig.AllowedMethods,
			AllowedHeaders:   rt.corsConfig.AllowedHeaders,
			ExposedHeaders:   append(rt.corsConfig.ExposedHeaders, csarExposed...),
			AllowCredentials: rt.corsConfig.AllowCredentials,
			MaxAge:           rt.corsConfig.MaxAge,
		})

		// For OPTIONS preflight, handle immediately without further pipeline.
		if req.Method == http.MethodOptions && req.Header.Get("Origin") != "" {
			corsMw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(w, req)
			return
		}

		// For normal requests, wrap the remaining pipeline with CORS headers.
		corsMw(http.HandlerFunc(func(cw http.ResponseWriter, cr *http.Request) {
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
		apierror.New(apierror.CodeAccessDenied, http.StatusForbidden,
			"access denied").WithDetail("client_ip: " + clientIP).
			WithRequestID(r.requestID(req)).Write(w)
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
			r.serveAfterJWT(vw, vr, rt)
		}))
		validated.ServeHTTP(w, req)
		return
	}

	r.serveAfterJWT(w, req, rt)
}

// serveAfterJWT runs authz evaluation if configured, then continues to serveAfterAuth.
func (r *Router) serveAfterJWT(w http.ResponseWriter, req *http.Request, rt *route) {
	if rt.authzConfig != nil && r.authzClient != nil {
		mw := authzmw.New(r.authzClient, r.requestID)
		wrapped := mw.Wrap(authzmw.Config{
			RouteConfig: rt.authzConfig,
		}, http.HandlerFunc(func(aw http.ResponseWriter, ar *http.Request) {
			r.serveAfterAuth(aw, ar, rt)
		}))
		wrapped.ServeHTTP(w, req)
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
			apierror.New(apierror.CodeSecurityError, http.StatusInternalServerError,
				"security injection required but not configured").
				WithRequestID(r.requestID(req)).Write(w)
			return
		}

		// Build a handler chain: pipeline <- security[n-1] <- ... <- security[0].
		// Each Wrap call creates a handler that resolves + injects one credential,
		// then calls the next handler in the chain.
		//
		// Query param stripping: To avoid the multi-credential ordering bug where
		// entry A strips a {query.*} param that entry B still needs, we collect
		// ALL referenced query keys first, inject all credentials, then strip once
		// before proxying (at the innermost handler, after all Wraps have run).

		// Collect query params to strip from all security entries that have strip enabled.
		var stripRefs []string
		for _, sec := range rt.config.Security {
			if sec.ShouldStripTokenParams() {
				stripRefs = append(stripRefs, sec.TokenRef)
			}
		}
		stripKeys := middleware.CollectQueryPlaceholders(stripRefs...)

		var handler http.Handler = http.HandlerFunc(func(iw http.ResponseWriter, ir *http.Request) {
			// Snapshot the original query values for throttle key resolution
			// BEFORE stripping. StripQueryKeys mutates ir.URL.RawQuery in
			// place, which would cause DynamicThrottler to resolve
			// {query.id} → "_unknown_" for the shared *url.URL.
			var origQuery = ir.URL.Query() // parsed copy — survives the strip

			// Strip consumed query params ONCE, after all credentials have been resolved.
			middleware.StripQueryKeys(ir, stripKeys)

			// Inject the pre-strip snapshot so DynamicThrottler.resolveKey
			// finds the original values when resolving {query.*} keys.
			ir = ir.WithContext(throttle.WithOriginalQuery(ir.Context(), origQuery))

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
//
// csar-ts protocol: The router emits X-CSAR-Status and X-CSAR-Wait-MS headers
// so the csar-ts client SDK can distinguish throttle vs circuit-breaker vs success.
// See: https://github.com/ledatu/csar-ts
func (r *Router) servePipeline(w http.ResponseWriter, req *http.Request, rt *route) {
	var totalWait time.Duration

	// ── csar-ts observability: handle client-reported RPS hint ──────────
	if clientLimit := req.Header.Get("X-CSAR-Client-Limit"); clientLimit != "" {
		if r.metrics != nil {
			r.metrics.RecordSDKClientLimitPresence(rt.routeKey)
		}
		clientLimitMode := ""
		if rt.config.Traffic != nil {
			clientLimitMode = rt.config.Traffic.ClientLimitMode
		}
		switch clientLimitMode {
		case "enforce":
			if rps, err := strconv.ParseFloat(clientLimit, 64); err == nil && rps > 0 {
				if recv, ok := rt.throttler.(throttle.ClientHintReceiver); ok {
					recv.ApplyClientHint(rps)
				}
			}
			r.logger.Debug("client RPS hint enforced",
				"X-CSAR-Client-Limit", clientLimit,
				"route", rt.routeKey,
			)
		case "advisory":
			r.logger.Info("client RPS hint (advisory)",
				"X-CSAR-Client-Limit", clientLimit,
				"route", rt.routeKey,
			)
		default:
			r.logger.Debug("client RPS hint received",
				"X-CSAR-Client-Limit", clientLimit,
				"route", rt.routeKey,
			)
		}
	}

	// Step 0: Global throttle (fast in-memory counter, checked first)
	if globalT := r.throttleManager.GetGlobal(); globalT != nil {
		waitStart := time.Now()
		if err := globalT.Wait(req.Context()); err != nil {
			r.logger.Warn("request throttled by global limit",
				"path", req.URL.Path,
				"method", req.Method,
				"error", err,
			)
			retryAfterSec := globalT.EstimateRetryAfter()
			w.Header().Set("X-CSAR-Status", "throttled")
			w.Header().Set("Retry-After", strconv.Itoa(retryAfterSec))
			w.Header().Set("X-CSAR-Wait-MS", strconv.FormatInt(time.Since(waitStart).Milliseconds(), 10))
			if r.metrics != nil {
				r.metrics.RecordSDKThrottled(rt.routeKey, "throttled")
			}
			apierror.New(apierror.CodeThrottled, http.StatusServiceUnavailable,
				"global rate limit exceeded").WithRetryAfterMS(int64(retryAfterSec) * 1000).
				WithDetail(err.Error()).WithRequestID(r.requestID(req)).Write(w)
			return
		}
		totalWait += time.Since(waitStart)
	}

	// Step 1: Per-route throttle (smoothing — wait instead of reject)
	if rt.throttler != nil {
		// Check exclude-IPs: skip throttle if client IP is in the exclusion list.
		skipThrottle := false
		if len(rt.excludeIPs) > 0 {
			clientIP := extractClientIP(req, rt.trustProxy)
			ip := net.ParseIP(clientIP)
			if ip != nil {
				for _, cidr := range rt.excludeIPs {
					if cidr.Contains(ip) {
						skipThrottle = true
						break
					}
				}
			}
		}

		if !skipThrottle {
			// Determine which throttler to use: check VIP overrides first.
			activeThrottler := rt.throttler
			for _, vo := range rt.vipOverrides {
				headerVal := req.Header.Get(vo.header)
				if headerVal != "" {
					if altThrottler, ok := vo.values[headerVal]; ok {
						activeThrottler = altThrottler
						break
					}
				}
			}

			// Update queue depth metric
			if r.metrics != nil {
				r.metrics.SetThrottleQueueDepth(rt.routeKey, activeThrottler.Waiting()+1)
			}

			// Store request in context for dynamic key resolution.
			ctx := throttle.WithRequest(req.Context(), req)

			waitStart := time.Now()
			err := activeThrottler.Wait(ctx)
			waitDur := time.Since(waitStart)
			totalWait += waitDur

			if r.metrics != nil {
				r.metrics.SetThrottleQueueDepth(rt.routeKey, activeThrottler.Waiting())
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
				// csar-ts protocol: X-CSAR-Status: throttled + Retry-After.
				// Compute Retry-After from the active throttler's real state
				// (rate, queue depth, suspension). Falls back to max_wait config.
				retryAfter := 1
				if est, ok := activeThrottler.(throttle.RetryEstimator); ok {
					retryAfter = est.EstimateRetryAfter()
				} else if rt.config.Traffic != nil && rt.config.Traffic.MaxWait.Duration > 0 {
					retryAfter = int(rt.config.Traffic.MaxWait.Seconds())
					if retryAfter < 1 {
						retryAfter = 1
					}
				}
				w.Header().Set("X-CSAR-Status", "throttled")
				w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
				w.Header().Set("X-CSAR-Wait-MS", strconv.FormatInt(waitDur.Milliseconds(), 10))
				if r.metrics != nil {
					r.metrics.RecordSDKThrottled(rt.routeKey, "throttled")
				}
				apierror.New(apierror.CodeThrottled, http.StatusServiceUnavailable,
					"service temporarily unavailable").WithRetryAfterMS(int64(retryAfter) * 1000).
					WithDetail(err.Error()).WithRequestID(r.requestID(req)).Write(w)
				return
			}

			if r.metrics != nil {
				r.metrics.RecordThrottleWait(rt.routeKey, waitDur, false)
			}
		}
	}

	// Set X-CSAR-Wait-MS response header with actual wait duration.
	// Also inject into the request context so the value survives through
	// httputil.ReverseProxy (which replaces the ResponseWriter's header map).
	// Always inject protocol version into context for proxy passthrough.
	// Always inject protocol version into context for proxy passthrough.
	{
		ctx := proxy.WithProtocolVersion(req.Context(), ProtocolVersion)
		if totalWait > 0 {
			// Honor per-route protocol policy for wait-MS emission.
			emitWaitMS := true
			if rt.config.Protocol != nil && rt.config.Protocol.EmitWaitMS != nil {
				emitWaitMS = *rt.config.Protocol.EmitWaitMS
			}
			if emitWaitMS {
				waitMS := strconv.FormatInt(totalWait.Milliseconds(), 10)
				w.Header().Set("X-CSAR-Wait-MS", waitMS)
				ctx = proxy.WithCSARHeaders(ctx, waitMS, "", "")
				if r.metrics != nil {
					r.metrics.RecordSDKWaitEmitted(rt.routeKey, float64(totalWait.Milliseconds()))
				}
			}
		}
		req = req.WithContext(ctx)
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
				cbState := rt.circuitBreaker.State()
				csarStatus := "circuit_open"
				if cbState == resilience.StateHalfOpen {
					csarStatus = "circuit_half_open"
				}
				cbTimeout := rt.circuitBreaker.TimeoutDuration()
				retryAfterSecs := int(cbTimeout.Seconds())
				if retryAfterSecs < 1 {
					retryAfterSecs = 1
				}
				w.Header().Set("X-CSAR-Status", csarStatus)
				w.Header().Set("Retry-After", strconv.Itoa(retryAfterSecs))
				if r.metrics != nil {
					r.metrics.RecordSDKCircuitOpen(rt.routeKey)
				}
				apierror.New(apierror.CodeCircuitOpen, http.StatusServiceUnavailable,
					"circuit breaker open").WithRetryAfterMS(int64(retryAfterSecs) * 1000).
					WithDetail(csarStatus).WithRequestID(r.requestID(req)).Write(w)
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
		// Chain: retry → backpressure → proxy (all optional layers).
		handler := r.baseProxy(rt)
		if rt.backpressureHandler != nil {
			handler = rt.backpressureHandler
		}
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
	return strings.Contains(accept, "text/event-stream")
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
