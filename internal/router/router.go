// Package router implements the core stateless API router for CSAR.
// It matches incoming requests to configured routes and applies the pipeline:
// ip_check -> cors -> security_inject -> throttle.Wait -> circuit_breaker -> proxy.Forward.
package router

import (
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strings"

	"github.com/ledatu/csar/internal/authn"
	"github.com/ledatu/csar/internal/authz"
	"github.com/ledatu/csar/internal/cache"
	"github.com/ledatu/csar/internal/config"
	"github.com/ledatu/csar/internal/dlp"
	"github.com/ledatu/csar/internal/loadbalancer"
	"github.com/ledatu/csar/internal/metrics"
	"github.com/ledatu/csar/internal/proxy"
	"github.com/ledatu/csar/internal/resilience"
	"github.com/ledatu/csar/internal/telemetry"
	"github.com/ledatu/csar/internal/tenant"
	"github.com/ledatu/csar/internal/throttle"
	"github.com/ledatu/csar/pkg/middleware"
	"github.com/redis/go-redis/v9"
)

// route holds a compiled route with its proxy and throttler.
type route struct {
	config              config.RouteConfig
	proxy               *proxy.ReverseProxy
	loadBalancer        http.Handler               // nil if no load balancing; otherwise a load-balancing handler
	throttler           throttle.Waiter            // nil if no traffic shaping configured
	circuitBreaker      *resilience.CircuitBreaker // nil if no resilience configured
	backpressureHandler http.Handler               // proxy wrapped with backpressure middleware (nil = disabled)
	retryHandler        http.Handler               // proxy wrapped with retry middleware (nil = use proxy directly)
	routeKey            string                     // "METHOD:PATH"
	injectHeaders       []string                   // headers to strip/inject for security (e.g. ["Authorization", "X-Client-Secret"])
	allowCIDRs          []*net.IPNet               // nil = use global; empty after init = deny all (shouldn't happen)
	hasRouteACL         bool                       // true if this route has its own x-csar-access (overrides global)
	trustProxy          bool                       // route-scoped: trust X-Forwarded-For / X-Real-IP for this route
	pathPattern         *regexp.Regexp             // compiled regex when path contains {var:regex} variables
	pathRewrite         string                     // rewrite template with $1/$2 back-references
	method              string                     // HTTP method for this route (uppercase)
	originalPath        string                     // the original path definition (e.g. "/api/v1/users/{id:[0-9]+}")
	pathVarNames        []string                   // ordered variable names extracted from originalPath (e.g. ["id"])
	jwtConfig           *authn.Config              // nil if no inbound JWT validation
	dlpConfig           *dlp.Config                // nil if no response redaction
	tenantConfig        *tenant.Config             // nil if no multi-tenant routing
	corsConfig          *config.CORSConfig         // nil if no CORS configuration
	cacheConfig         *cache.Config              // nil if no response caching
	authzConfig         *config.AuthzRouteConfig   // nil if no authz authorization
	excludeIPs          []*net.IPNet               // IPs/CIDRs that bypass this route's throttle
	vipOverrides        []vipOverride              // header-based throttle policy swaps
}

// vipOverride associates a header with a map of values → alternate Waiters.
type vipOverride struct {
	header string
	values map[string]throttle.Waiter
}

// Router is the core stateless API router.
// It matches incoming requests to configured routes and applies
// the pipeline: ip_check -> cors -> security_inject -> throttle.Wait -> circuit_breaker -> proxy.Forward.
type Router struct {
	routes           map[string]*route // keyed by "METHOD:PATH" (exact/prefix routes)
	regexRoutes      []*route          // routes with {var:regex} patterns (checked after exact match)
	cfg              *config.Config
	logger           *slog.Logger
	metrics          *metrics.Metrics          // nil if no metrics
	telemetry        *telemetry.Provider       // nil if no telemetry
	authInjector     *middleware.AuthInjector  // nil if no auth injection configured
	jwtValidator     *authn.JWTValidator       // nil if no route uses JWT validation
	authzClient      *authz.Client             // nil if no route uses authz
	dlpRedactor      *dlp.Redactor             // nil if no route uses DLP redaction
	tenantRouter     *tenant.Router            // nil if no route uses tenant routing
	responseCache    *cache.ResponseCache      // nil if no route uses response caching
	ssrfProtection   *proxy.SSRFProtection     // nil if SSRF protection is disabled
	throttleManager  *throttle.ThrottleManager // manages all per-route throttlers
	redisClient      *redis.Client             // shared Redis client for distributed throttling (nil if not configured)
	pools            []*loadbalancer.Pool      // tracked for Close() cleanup on reload
	globalCIDRs      []*net.IPNet              // parsed global access_control.allow_cidrs
	hasGlobalACL     bool                      // true if global access_control is configured
	globalTrustProxy bool                      // global default for trust_proxy (from access_control)
	reqIDHeader      string                    // resolved request ID header name (default: "X-Request-ID")
}

// GetThrottler returns the throttler for a given route key (for observability).
func (r *Router) GetThrottler(method, path string) throttle.Waiter {
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

// RegisteredKeys returns the route keys that were registered with throttlers
// during this router's construction. Use this to prune stale keys from a
// shared ThrottleManager after a SIGHUP reload.
func (r *Router) RegisteredKeys() []string {
	keys := make([]string, 0, len(r.routes)+len(r.regexRoutes))
	for k := range r.routes {
		keys = append(keys, k)
	}
	for _, rt := range r.regexRoutes {
		keys = append(keys, rt.routeKey)
	}
	return keys
}

// Close stops all background goroutines owned by this router (health checks, etc.).
// Call this before discarding a router instance (e.g. on SIGHUP reload) to prevent
// goroutine leaks. Safe to call multiple times.
func (r *Router) Close() {
	for _, p := range r.pools {
		p.Stop()
	}
	r.logger.Debug("router closed, health check goroutines stopped",
		"pools", len(r.pools),
	)
}
