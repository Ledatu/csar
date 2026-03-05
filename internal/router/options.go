package router

import (
	"github.com/ledatu/csar/internal/metrics"
	"github.com/ledatu/csar/internal/proxy"
	"github.com/ledatu/csar/internal/telemetry"
	"github.com/ledatu/csar/internal/throttle"
	"github.com/ledatu/csar/pkg/middleware"
	"github.com/redis/go-redis/v9"
)

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

// WithThrottleManager sets an externally-managed ThrottleManager.
// Use this to share a single manager across router rebuilds (e.g. on SIGHUP)
// so the coordinator client's quota updates continue to apply after reload.
// If not provided, the router creates its own manager internally.
func WithThrottleManager(tm *throttle.ThrottleManager) Option {
	return func(r *Router) { r.throttleManager = tm }
}

// WithRedisClient sets a shared Redis client for distributed throttling.
// Routes with backend: "redis" will use this client for GCRA rate limiting.
func WithRedisClient(client *redis.Client) Option {
	return func(r *Router) { r.redisClient = client }
}
