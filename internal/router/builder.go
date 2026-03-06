package router

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/ledatu/csar/internal/authn"
	"github.com/ledatu/csar/internal/backpressure"
	"github.com/ledatu/csar/internal/cache"
	"github.com/ledatu/csar/internal/config"
	"github.com/ledatu/csar/internal/dlp"
	"github.com/ledatu/csar/internal/loadbalancer"
	"github.com/ledatu/csar/internal/proxy"
	"github.com/ledatu/csar/internal/resilience"
	"github.com/ledatu/csar/internal/retry"
	"github.com/ledatu/csar/internal/tenant"
	"github.com/ledatu/csar/internal/throttle"
)

// New creates a new Router from the given configuration.
func New(cfg *config.Config, logger *slog.Logger, opts ...Option) (*Router, error) {
	r := &Router{
		routes: make(map[string]*route),
		cfg:    cfg,
		logger: logger,
	}

	for _, opt := range opts {
		opt(r)
	}

	// Create a ThrottleManager if one was not injected via WithThrottleManager.
	if r.throttleManager == nil {
		r.throttleManager = throttle.NewManager()
	}

	// Set up global throttle if configured.
	if cfg.GlobalThrottle != nil {
		r.throttleManager.SetGlobal(
			cfg.GlobalThrottle.RPS,
			cfg.GlobalThrottle.Burst,
			cfg.GlobalThrottle.MaxWait.Duration,
		)
		logger.Info("global throttle configured",
			"rps", cfg.GlobalThrottle.RPS,
			"burst", cfg.GlobalThrottle.Burst,
			"max_wait", cfg.GlobalThrottle.MaxWait.Duration,
		)
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
		if err := r.buildRoute(cfg, fr, cbManager, logger); err != nil {
			return nil, err
		}
	}

	return r, nil
}

// buildRoute creates and registers a single route from a FlatRoute definition.
func (r *Router) buildRoute(cfg *config.Config, fr config.FlatRoute, cbManager *resilience.CircuitBreakerManager, logger *slog.Logger) error {
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
	// Apply path_mode: "append" preserves old join behaviour; "replace" (default)
	// makes the target_url path the exact upstream path.
	if fr.Route.Backend.IsAppendPathMode() {
		proxyOpts = append(proxyOpts, proxy.WithPathMode("append"))
	}

	rp, err := proxy.New(fr.Route.Backend.TargetURL, proxyOpts...)
	if err != nil {
		return fmt.Errorf("creating proxy for %s %s: %w", fr.Method, fr.Path, err)
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
		if err := r.setupLoadBalancer(rt, fr, allTargets, key, logger); err != nil {
			return err
		}
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
	if err := r.setupSecurity(rt, fr, key, logger); err != nil {
		return err
	}

	// Parse per-route access control CIDRs.
	if err := r.setupAccess(rt, fr, key, logger); err != nil {
		return err
	}

	// Set up throttler if traffic config is present
	if err := r.setupThrottle(rt, cfg, fr, key, logger); err != nil {
		return err
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

	// Set up backpressure middleware if adaptive_backpressure or auto_retry_429 is enabled.
	// Must come before retry so that retry wraps backpressure in the handler chain:
	//   retry → backpressure → proxy
	r.setupBackpressure(rt, fr, key, logger)

	// Set up retry middleware if retry config is present (audit §3.1).
	if fr.Route.Retry != nil {
		r.setupRetry(rt, fr, key, logger)
	}

	// Set up JWT validation if auth-validate config is present (audit §3.3.1).
	if fr.Route.AuthValidate != nil {
		r.setupJWT(rt, fr, key, logger)
	}

	// Set up DLP redaction if redact config is present (audit §3.3.2).
	if fr.Route.Redact != nil && fr.Route.Redact.IsEnabled() {
		r.setupDLP(rt, fr, key, logger)
	}

	// Set up multi-tenant routing if tenant config is present (audit §3.3.3).
	if fr.Route.Tenant != nil {
		r.setupTenant(rt, fr, key, logger)
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
		r.setupCache(rt, fr, key, logger)
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

	return nil
}

// setupLoadBalancer configures load balancing for a route with multiple targets.
func (r *Router) setupLoadBalancer(rt *route, fr config.FlatRoute, allTargets []string, key string, logger *slog.Logger) error {
	strategy := loadbalancer.RoundRobin
	if fr.Route.Backend.LoadBalancer == "random" {
		strategy = loadbalancer.Random
	}
	var lbOpts []loadbalancer.PoolOption
	if fr.Route.Backend.IsAppendPathMode() {
		lbOpts = append(lbOpts, loadbalancer.WithPathMode("append"))
	}
	lb, err := loadbalancer.New(allTargets, strategy, logger, lbOpts...)
	if err != nil {
		return fmt.Errorf("creating load balancer for %s %s: %w", fr.Method, fr.Path, err)
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
	r.pools = append(r.pools, lb)
	logger.Info("load balancer enabled",
		"route", key,
		"strategy", string(strategy),
		"targets", len(allTargets),
	)
	return nil
}

// setupSecurity configures security header injection for a route.
func (r *Router) setupSecurity(rt *route, fr config.FlatRoute, key string, logger *slog.Logger) error {
	if len(fr.Route.Security) == 0 {
		return nil
	}

	// Fail closed: if a route declares security config but no AuthInjector
	// is provided, refuse to start — never silently proxy without credentials.
	if r.authInjector == nil {
		return fmt.Errorf("route %s has x-csar-security config but no AuthInjector is configured — "+
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
	return nil
}

// setupAccess configures IP access control for a route.
func (r *Router) setupAccess(rt *route, fr config.FlatRoute, key string, logger *slog.Logger) error {
	if fr.Route.Access != nil && len(fr.Route.Access.AllowCIDRs) > 0 {
		nets, err := parseCIDRList(fr.Route.Access.AllowCIDRs)
		if err != nil {
			return fmt.Errorf("route %s x-csar-access: %w", key, err)
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
	return nil
}

// setupThrottle configures throttling for a route.
func (r *Router) setupThrottle(rt *route, cfg *config.Config, fr config.FlatRoute, key string, logger *slog.Logger) error {
	if fr.Route.Traffic == nil {
		logger.Info("registered route (no throttle)",
			"method", strings.ToUpper(fr.Method),
			"path", fr.Path,
		)
		return nil
	}

	t := fr.Route.Traffic
	backend := t.Backend
	if backend == "" {
		backend = "local"
	}

	switch {
	case t.Key != "" && backend == "redis":
		// Dynamic key → per-entity Redis GCRA
		if r.redisClient == nil {
			return fmt.Errorf("route %s has dynamic key but no Redis client configured", key)
		}
		keyPrefix := "csar:rl:"
		if cfg.Redis != nil && cfg.Redis.KeyPrefix != "" {
			keyPrefix = cfg.Redis.KeyPrefix
		}
		dt := throttle.NewDynamicThrottler(r.redisClient, keyPrefix, t.Key, t.RPS, t.Burst, t.MaxWait.Duration)
		r.throttleManager.RegisterWaiter(key, dt)
		logger.Info("registered dynamic-key throttle",
			"route", key,
			"key_template", t.Key,
			"rps", t.RPS,
			"burst", t.Burst,
		)

	case backend == "redis":
		// Static Redis GCRA
		if r.redisClient == nil {
			return fmt.Errorf("route %s has redis backend but no Redis client configured", key)
		}
		keyPrefix := "csar:rl:"
		if cfg.Redis != nil && cfg.Redis.KeyPrefix != "" {
			keyPrefix = cfg.Redis.KeyPrefix
		}
		rth := throttle.NewRedisThrottler(r.redisClient, keyPrefix, key, t.RPS, t.Burst, t.MaxWait.Duration)
		r.throttleManager.RegisterWaiter(key, rth)
		logger.Info("registered redis GCRA throttle",
			"route", key,
			"rps", t.RPS,
			"burst", t.Burst,
		)

	default:
		// Local token bucket (or coordinator-managed local)
		r.throttleManager.Register(key, t.RPS, t.Burst, t.MaxWait.Duration)
		logger.Info("registered local throttle",
			"route", key,
			"backend", backend,
			"rps", t.RPS,
			"burst", t.Burst,
			"max_wait", t.MaxWait.Duration,
		)
	}

	rt.throttler = r.throttleManager.Get(key)

	// Parse exclude_ips for this route's throttle.
	if len(t.ExcludeIPs) > 0 {
		nets, err := parseCIDRList(t.ExcludeIPs)
		if err != nil {
			return fmt.Errorf("route %s x-csar-traffic.exclude_ips: %w", key, err)
		}
		rt.excludeIPs = nets
		logger.Info("throttle IP exclusions configured",
			"route", key,
			"exclude_ips", t.ExcludeIPs,
		)
	}

	// Build VIP overrides for this route's throttle.
	if len(t.VIPOverrides) > 0 {
		for _, vip := range t.VIPOverrides {
			vo := vipOverride{
				header: vip.Header,
				values: make(map[string]throttle.Waiter, len(vip.Values)),
			}
			for val, policyName := range vip.Values {
				policy := cfg.ThrottlingPolicies[policyName]
				vipKey := key + ":vip:" + val
				pBackend := policy.Backend
				if pBackend == "" {
					pBackend = "local"
				}
				switch {
				case policy.Key != "" && pBackend == "redis" && r.redisClient != nil:
					keyPrefix := "csar:rl:"
					if cfg.Redis != nil && cfg.Redis.KeyPrefix != "" {
						keyPrefix = cfg.Redis.KeyPrefix
					}
					dt := throttle.NewDynamicThrottler(r.redisClient, keyPrefix, policy.Key, policy.RPS, policy.Burst, policy.MaxWait.Duration)
					r.throttleManager.RegisterWaiter(vipKey, dt)
				case pBackend == "redis" && r.redisClient != nil:
					keyPrefix := "csar:rl:"
					if cfg.Redis != nil && cfg.Redis.KeyPrefix != "" {
						keyPrefix = cfg.Redis.KeyPrefix
					}
					rth := throttle.NewRedisThrottler(r.redisClient, keyPrefix, vipKey, policy.RPS, policy.Burst, policy.MaxWait.Duration)
					r.throttleManager.RegisterWaiter(vipKey, rth)
				default:
					r.throttleManager.Register(vipKey, policy.RPS, policy.Burst, policy.MaxWait.Duration)
				}
				vo.values[val] = r.throttleManager.Get(vipKey)
			}
			rt.vipOverrides = append(rt.vipOverrides, vo)
		}
		logger.Info("VIP throttle overrides configured",
			"route", key,
			"overrides", len(t.VIPOverrides),
		)
	}

	return nil
}

// setupRetry configures retry middleware for a route.
// If backpressure middleware was already set up, retry wraps it instead of
// the raw proxy — forming the chain: retry → backpressure → proxy.
func (r *Router) setupRetry(rt *route, fr config.FlatRoute, key string, logger *slog.Logger) {
	// Determine the base handler for retry to wrap.
	var baseHandler http.Handler = rt.proxy
	if rt.loadBalancer != nil {
		baseHandler = rt.loadBalancer
	}
	if rt.backpressureHandler != nil {
		baseHandler = rt.backpressureHandler
	}

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
	rt.retryHandler = retry.New(baseHandler, retryCfg, logger)
	logger.Info("retry middleware enabled",
		"route", key,
		"max_attempts", retryCfg.MaxAttempts,
		"backoff", retryCfg.Backoff,
	)
}

// setupBackpressure configures the upstream backpressure middleware for a route.
// Enabled when either adaptive_backpressure (traffic config) or auto_retry_429
// (retry config) is set. Wraps the base proxy handler.
func (r *Router) setupBackpressure(rt *route, fr config.FlatRoute, key string, logger *slog.Logger) {
	hasAdaptive := fr.Route.Traffic != nil &&
		fr.Route.Traffic.AdaptiveBackpressure != nil &&
		fr.Route.Traffic.AdaptiveBackpressure.Enabled
	hasAutoRetry := fr.Route.Retry != nil && fr.Route.Retry.AutoRetry429

	if !hasAdaptive && !hasAutoRetry {
		return
	}

	bpCfg := backpressure.Config{
		Enabled: true,
	}

	if hasAdaptive {
		abp := fr.Route.Traffic.AdaptiveBackpressure
		bpCfg.RespectHeaders = abp.RespectHeaders
		bpCfg.SuspendBucket = abp.SuspendBucket
		if abp.MaxBodyBuffer > 0 {
			bpCfg.MaxBodyBuffer = abp.MaxBodyBuffer
		}
	}

	if hasAutoRetry {
		bpCfg.AutoRetry = true
		bpCfg.MaxInternalWait = fr.Route.Retry.MaxInternalWait.Duration
		if bpCfg.MaxInternalWait == 0 {
			bpCfg.MaxInternalWait = 30 * time.Second
		}
	}

	// Determine the base handler to wrap.
	var baseHandler http.Handler = rt.proxy
	if rt.loadBalancer != nil {
		baseHandler = rt.loadBalancer
	}

	rt.backpressureHandler = backpressure.New(baseHandler, bpCfg, rt.throttler, logger)
	logger.Info("backpressure middleware enabled",
		"route", key,
		"adaptive", hasAdaptive,
		"auto_retry_429", hasAutoRetry,
		"suspend_bucket", bpCfg.SuspendBucket,
		"max_internal_wait", bpCfg.MaxInternalWait,
	)
}

// setupJWT configures JWT validation for a route.
func (r *Router) setupJWT(rt *route, fr config.FlatRoute, key string, logger *slog.Logger) {
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
		CookieName:     fr.Route.AuthValidate.CookieName,
	}
	logger.Info("JWT validation enabled",
		"route", key,
		"jwks_url", fr.Route.AuthValidate.JWKSURL,
	)
}

// setupDLP configures DLP redaction for a route.
func (r *Router) setupDLP(rt *route, fr config.FlatRoute, key string, logger *slog.Logger) {
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

// setupTenant configures multi-tenant routing for a route.
func (r *Router) setupTenant(rt *route, fr config.FlatRoute, key string, logger *slog.Logger) {
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

// setupCache configures response caching for a route.
func (r *Router) setupCache(rt *route, fr config.FlatRoute, key string, logger *slog.Logger) {
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
