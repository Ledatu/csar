// Package simulate provides local request routing simulation for the csar-helper CLI.
// It evaluates which route matches and what middleware would apply without sending
// any real network requests.
//
// Matching precedence mirrors internal/router:
//  1. Exact match (METHOD:PATH key lookup)
//  2. Longest prefix match (path boundary aware)
//  3. Regex/parameterised routes (first match in sorted order)
package simulate

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ledatu/csar/internal/config"
)

// Request describes a simulated inbound request.
type Request struct {
	Path    string
	Method  string
	Headers map[string]string
}

// MatchResult describes the outcome of route matching and middleware resolution.
type MatchResult struct {
	Matched     bool
	RoutePath   string
	RouteMethod string
	TargetURL   string
	MatchType   string // "exact", "prefix", "regex"
	IsRegex     bool
	Middlewares []MiddlewareInfo
	Decision    string // human-readable summary
}

// MiddlewareInfo describes a single middleware that would be applied.
type MiddlewareInfo struct {
	Name    string
	Details string
	Impact  string // e.g. "blocks", "modifies", "observes"
}

// ─── Compiled route table ──────────────────────────────────────────────────────

// compiledRoute is a pre-processed route for matching.
type compiledRoute struct {
	path    string
	method  string
	route   config.RouteConfig
	isRegex bool
	pattern *regexp.Regexp // non-nil for regex routes
}

// buildRouteTable pre-processes config paths into a deterministic sorted table,
// separating exact/prefix routes from regex routes.
func buildRouteTable(cfg *config.Config) (exact map[string]*compiledRoute, prefix []*compiledRoute, regex []*compiledRoute) {
	exact = make(map[string]*compiledRoute)

	for path, methods := range cfg.Paths {
		for method, route := range methods {
			m := strings.ToUpper(method)
			cr := &compiledRoute{
				path:   path,
				method: m,
				route:  route,
			}

			if strings.Contains(path, "{") {
				cr.isRegex = true
				cr.pattern = patternToRegex(path)
				regex = append(regex, cr)
			} else {
				// Exact-match key: "GET:/api/users"
				key := m + ":" + path
				exact[key] = cr
				// Also add to prefix candidates
				prefix = append(prefix, cr)
			}
		}
	}

	// Sort prefix routes by path length descending for longest-prefix-first
	sort.Slice(prefix, func(i, j int) bool {
		return len(prefix[i].path) > len(prefix[j].path)
	})

	// Sort regex routes by path for deterministic order
	sort.Slice(regex, func(i, j int) bool {
		return regex[i].path < regex[j].path
	})

	return exact, prefix, regex
}

// ─── Simulate ──────────────────────────────────────────────────────────────────

// Simulate runs a local route match against the config.
// Matching precedence mirrors internal/router/router.go matchRoute:
//  1. Exact key match
//  2. Longest prefix match (path-boundary aware)
//  3. Regex pattern match
func Simulate(cfg *config.Config, req Request) *MatchResult {
	method := strings.ToUpper(req.Method)
	result := &MatchResult{}

	exact, prefix, regex := buildRouteTable(cfg)

	// 1. Exact match
	key := method + ":" + req.Path
	if cr, ok := exact[key]; ok {
		fillResult(result, cr, "exact")
		result.Middlewares = resolveMiddlewares(cfg, cr.route, cr.path)
		result.Decision = buildDecision(result)
		return result
	}

	// 2. Longest prefix match (path-boundary aware, like the router)
	for _, cr := range prefix {
		if cr.method != method {
			continue
		}
		if strings.HasPrefix(req.Path, cr.path) &&
			(len(req.Path) == len(cr.path) || req.Path[len(cr.path)] == '/') {
			fillResult(result, cr, "prefix")
			result.Middlewares = resolveMiddlewares(cfg, cr.route, cr.path)
			result.Decision = buildDecision(result)
			return result
		}
	}

	// 3. Regex routes
	for _, cr := range regex {
		if cr.method != method {
			continue
		}
		if cr.pattern != nil && cr.pattern.MatchString(req.Path) {
			fillResult(result, cr, "regex")
			result.Middlewares = resolveMiddlewares(cfg, cr.route, cr.path)
			result.Decision = buildDecision(result)
			return result
		}
	}

	result.Decision = fmt.Sprintf("No route matched %s %s", method, req.Path)
	return result
}

func fillResult(result *MatchResult, cr *compiledRoute, matchType string) {
	result.Matched = true
	result.RoutePath = cr.path
	result.RouteMethod = cr.method
	result.TargetURL = cr.route.Backend.TargetURL
	result.IsRegex = cr.isRegex
	result.MatchType = matchType
}

// ─── Path matching ─────────────────────────────────────────────────────────────

func patternToRegex(pattern string) *regexp.Regexp {
	// Convert {name:regex} patterns to regex groups
	re := regexp.MustCompile(`\{[^}]*:([^}]+)\}`)
	regexStr := "^" + re.ReplaceAllString(pattern, "($1)") + "$"

	// Also handle simple {name} patterns (match any non-slash)
	simple := regexp.MustCompile(`\{[^}:]+\}`)
	regexStr = simple.ReplaceAllString(regexStr, "([^/]+)")

	compiled, err := regexp.Compile(regexStr)
	if err != nil {
		return nil
	}
	return compiled
}

// ─── Middleware resolution ──────────────────────────────────────────────────────

func resolveMiddlewares(cfg *config.Config, route config.RouteConfig, path string) []MiddlewareInfo {
	var mws []MiddlewareInfo

	// IP Access Control
	if cfg.AccessControl != nil && len(cfg.AccessControl.AllowCIDRs) > 0 {
		mws = append(mws, MiddlewareInfo{
			Name:    "IP Access Control (global)",
			Details: fmt.Sprintf("%d CIDR(s) allowed", len(cfg.AccessControl.AllowCIDRs)),
			Impact:  "blocks",
		})
	}
	if route.Access != nil && len(route.Access.AllowCIDRs) > 0 {
		mws = append(mws, MiddlewareInfo{
			Name:    "IP Access Control (route)",
			Details: fmt.Sprintf("%d CIDR(s) allowed", len(route.Access.AllowCIDRs)),
			Impact:  "blocks",
		})
	}

	// CORS
	if route.CORS != nil {
		mws = append(mws, MiddlewareInfo{
			Name:    "CORS",
			Details: fmt.Sprintf("origins: %s", strings.Join(route.CORS.AllowedOrigins, ", ")),
			Impact:  "modifies",
		})
	}

	// JWT Validation
	if route.AuthValidate != nil {
		mws = append(mws, MiddlewareInfo{
			Name:    "JWT Validation",
			Details: fmt.Sprintf("jwks: %s", route.AuthValidate.JWKSURL),
			Impact:  "blocks",
		})
	}

	// Security (credential injection)
	for i, sec := range route.Security {
		mws = append(mws, MiddlewareInfo{
			Name:    fmt.Sprintf("Credential Injection [%d]", i),
			Details: fmt.Sprintf("%s → %s (format: %s)", sec.TokenRef, sec.InjectHeader, sec.InjectFormat),
			Impact:  "modifies",
		})
	}

	// Throttle
	if route.Traffic != nil {
		waitStr := "none"
		if route.Traffic.MaxWait.Duration > 0 {
			waitStr = route.Traffic.MaxWait.Duration.String()
		}
		mws = append(mws, MiddlewareInfo{
			Name:    "Rate Limit",
			Details: fmt.Sprintf("%.0f rps, burst %d, max_wait %s, backend %s", route.Traffic.RPS, route.Traffic.Burst, waitStr, coalesce(route.Traffic.Backend, "local")),
			Impact:  "blocks",
		})
	}

	// Circuit Breaker
	if route.Resilience != nil && route.Resilience.CircuitBreaker != "" {
		cb, ok := cfg.CircuitBreakers[route.Resilience.CircuitBreaker]
		details := route.Resilience.CircuitBreaker
		if ok {
			details = fmt.Sprintf("%s (threshold=%d, timeout=%s)",
				route.Resilience.CircuitBreaker,
				cb.FailureThreshold,
				cb.Timeout.Duration.String())
		}
		mws = append(mws, MiddlewareInfo{
			Name:    "Circuit Breaker",
			Details: details,
			Impact:  "blocks",
		})
	}

	// Retry
	if route.Retry != nil {
		mws = append(mws, MiddlewareInfo{
			Name:    "Retry",
			Details: fmt.Sprintf("max_attempts=%d, backoff=%s", route.Retry.MaxAttempts, route.Retry.Backoff.Duration.String()),
			Impact:  "observes",
		})
	}

	// DLP Redaction
	if route.Redact != nil && route.Redact.IsEnabled() {
		mws = append(mws, MiddlewareInfo{
			Name:    "DLP Redaction",
			Details: fmt.Sprintf("fields: %s", strings.Join(route.Redact.Fields, ", ")),
			Impact:  "modifies",
		})
	}

	// Cache
	if route.Cache != nil && route.Cache.IsEnabled() {
		ttl := route.Cache.TTL.Duration
		if ttl == 0 {
			ttl = 5 * time.Minute
		}
		mws = append(mws, MiddlewareInfo{
			Name:    "Response Cache",
			Details: fmt.Sprintf("ttl=%s, max_entries=%d", ttl, route.Cache.MaxEntries),
			Impact:  "observes",
		})
	}

	// Tenant routing
	if route.Tenant != nil {
		mws = append(mws, MiddlewareInfo{
			Name:    "Tenant Routing",
			Details: fmt.Sprintf("header=%s, %d backend(s)", route.Tenant.Header, len(route.Tenant.Backends)),
			Impact:  "modifies",
		})
	}

	// Load Balancer
	targets := route.Backend.AllTargets()
	if len(targets) > 1 {
		lb := coalesce(route.Backend.LoadBalancer, "round_robin")
		mws = append(mws, MiddlewareInfo{
			Name:    "Load Balancer",
			Details: fmt.Sprintf("%s across %d targets", lb, len(targets)),
			Impact:  "modifies",
		})
	}

	return mws
}

func buildDecision(result *MatchResult) string {
	var parts []string
	parts = append(parts, fmt.Sprintf("Matched: %s %s", result.RouteMethod, result.RoutePath))
	parts = append(parts, fmt.Sprintf("Target: %s", result.TargetURL))
	parts = append(parts, fmt.Sprintf("Match type: %s", result.MatchType))

	blockers := 0
	modifiers := 0
	for _, mw := range result.Middlewares {
		switch mw.Impact {
		case "blocks":
			blockers++
		case "modifies":
			modifiers++
		}
	}

	parts = append(parts, fmt.Sprintf("Pipeline: %d middleware(s) — %d blocking, %d modifying",
		len(result.Middlewares), blockers, modifiers))

	return strings.Join(parts, "\n")
}

func coalesce(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
