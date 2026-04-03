// Package loadbalancer provides upstream pool load balancing for CSAR.
//
// Instead of forwarding all traffic to a single target_url, routes can
// define an array of targets and a load balancing strategy. The load
// balancer distributes requests across the pool.
//
// Supported strategies:
//   - round_robin (default): Cycles through targets sequentially.
//   - random: Selects a random target for each request.
//
// Active health checking can be enabled to periodically probe targets
// and remove unhealthy ones from the rotation pool.
package loadbalancer

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

// Strategy defines the load balancing algorithm.
type Strategy string

const (
	// RoundRobin cycles through targets sequentially.
	RoundRobin Strategy = "round_robin"

	// Random selects a random target for each request.
	Random Strategy = "random"
)

// HealthCheckConfig configures active health checking for the pool.
type HealthCheckConfig struct {
	// Enabled turns on active health checking.
	Enabled bool

	// Mode is the health check protocol: "http" (default) or "tcp".
	Mode string

	// Path is the HTTP endpoint to probe (for mode "http"), e.g. "/health".
	Path string

	// Interval is the time between health check probes (default: 10s).
	Interval time.Duration

	// Timeout is the maximum time to wait for a health check response (default: 3s).
	Timeout time.Duration

	// UnhealthyThreshold is the number of consecutive failures before
	// marking a target as unhealthy (default: 3).
	UnhealthyThreshold int

	// HealthyThreshold is the number of consecutive successes before
	// marking a target as healthy again (default: 2).
	HealthyThreshold int
}

// applyDefaults fills in zero-value fields with sensible defaults.
func (hc *HealthCheckConfig) applyDefaults() {
	if hc.Mode == "" {
		hc.Mode = "http"
	}
	if hc.Interval <= 0 {
		hc.Interval = 10 * time.Second
	}
	if hc.Timeout <= 0 {
		hc.Timeout = 3 * time.Second
	}
	if hc.UnhealthyThreshold <= 0 {
		hc.UnhealthyThreshold = 3
	}
	if hc.HealthyThreshold <= 0 {
		hc.HealthyThreshold = 2
	}
}

// Pool manages a set of upstream targets and distributes requests.
type Pool struct {
	targets   []*url.URL
	proxies   []*httputil.ReverseProxy
	strategy  Strategy
	counter   atomic.Uint64
	logger    *slog.Logger
	pathMode  string // "replace" (default) or "append"
	transport http.RoundTripper

	// Health checking state (parallel arrays to targets/proxies).
	healthy   []atomic.Bool      // true = target is healthy (default: all true)
	failures  []atomic.Int32     // consecutive failure count per target
	successes []atomic.Int32     // consecutive success count per target
	hcConfig  *HealthCheckConfig // nil if health checking is disabled
	cancel    context.CancelFunc // cancels the health check goroutines
}

// PoolOption configures the load balancer Pool.
type PoolOption func(*Pool)

// WithPathMode sets the path handling mode for all directors in the pool.
// "replace" (default): target_url path replaces the incoming request path.
// "append": incoming request path is appended to target_url path.
func WithPathMode(mode string) PoolOption {
	return func(p *Pool) { p.pathMode = mode }
}

// WithTransport sets the shared outbound transport used by reverse proxies and
// active health checks.
func WithTransport(rt http.RoundTripper) PoolOption {
	return func(p *Pool) { p.transport = rt }
}

// New creates a new load balancer Pool from the given target URLs.
func New(targetURLs []string, strategy Strategy, logger *slog.Logger, opts ...PoolOption) (*Pool, error) {
	if len(targetURLs) == 0 {
		return nil, fmt.Errorf("loadbalancer: at least one target URL is required")
	}

	if strategy == "" {
		strategy = RoundRobin
	}

	targets := make([]*url.URL, 0, len(targetURLs))
	proxies := make([]*httputil.ReverseProxy, 0, len(targetURLs))

	// Create a temporary pool to apply options (we need pathMode before building directors).
	p := &Pool{
		strategy: strategy,
		logger:   logger,
	}
	for _, opt := range opts {
		opt(p)
	}

	for _, rawURL := range targetURLs {
		target, err := url.Parse(rawURL)
		if err != nil {
			return nil, fmt.Errorf("loadbalancer: invalid target URL %q: %w", rawURL, err)
		}
		targets = append(targets, target)

		rp := &httputil.ReverseProxy{
			Director: newDirector(target, p.pathMode),
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadGateway)
				fmt.Fprintf(w, `{"error":"upstream error","detail":%q}`, err.Error())
			},
		}
		rp.Transport = p.transport
		proxies = append(proxies, rp)
	}

	n := len(targets)
	healthy := make([]atomic.Bool, n)
	failures := make([]atomic.Int32, n)
	successes := make([]atomic.Int32, n)
	// All targets start healthy.
	for i := range healthy {
		healthy[i].Store(true)
	}

	return &Pool{
		targets:   targets,
		proxies:   proxies,
		strategy:  strategy,
		logger:    logger,
		transport: p.transport,
		healthy:   healthy,
		failures:  failures,
		successes: successes,
		pathMode:  p.pathMode,
	}, nil
}

// StartHealthChecks begins active health checking for all targets.
// It launches one goroutine per target that runs checks at the configured interval.
// Call Stop() to cancel the health checks.
func (p *Pool) StartHealthChecks(ctx context.Context, cfg HealthCheckConfig) {
	cfg.applyDefaults()
	p.hcConfig = &cfg

	hcCtx, cancel := context.WithCancel(ctx)
	p.cancel = cancel

	for i := range p.targets {
		go p.healthCheckLoop(hcCtx, i, cfg)
	}

	p.logger.Info("active health checks started",
		"targets", len(p.targets),
		"mode", cfg.Mode,
		"interval", cfg.Interval,
		"timeout", cfg.Timeout,
		"unhealthy_threshold", cfg.UnhealthyThreshold,
		"healthy_threshold", cfg.HealthyThreshold,
	)
}

// Stop cancels all health check goroutines.
func (p *Pool) Stop() {
	if p.cancel != nil {
		p.cancel()
	}
}

// healthCheckLoop runs periodic health checks for a single target.
func (p *Pool) healthCheckLoop(ctx context.Context, idx int, cfg HealthCheckConfig) {
	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()

	target := p.targets[idx]
	p.logger.Debug("starting health check loop",
		"target", target.String(),
		"index", idx,
	)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ok := p.probe(ctx, idx, cfg)
			p.recordResult(idx, ok, cfg)
		}
	}
}

// probe performs a single health check against a target.
func (p *Pool) probe(ctx context.Context, idx int, cfg HealthCheckConfig) bool {
	target := p.targets[idx]

	probeCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	switch cfg.Mode {
	case "tcp":
		return p.probeTCP(probeCtx, target)
	default: // "http"
		return p.probeHTTP(probeCtx, target, cfg.Path)
	}
}

// probeHTTP performs an HTTP health check.
func (p *Pool) probeHTTP(ctx context.Context, target *url.URL, path string) bool {
	checkURL := *target
	if path != "" {
		checkURL.Path = path
	} else {
		checkURL.Path = "/"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, checkURL.String(), nil)
	if err != nil {
		p.logger.Debug("health check: failed to create request",
			"target", target.String(),
			"error", err,
		)
		return false
	}
	req.Header.Set("User-Agent", "csar-healthcheck/1.0")

	client := &http.Client{
		Transport: p.transport,
		Timeout:   0, // Timeout managed via context
	}
	resp, err := client.Do(req)
	if err != nil {
		p.logger.Debug("health check: HTTP request failed",
			"target", target.String(),
			"error", err,
		)
		return false
	}
	defer resp.Body.Close()

	// Healthy if 2xx status.
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

// probeTCP performs a TCP health check.
func (p *Pool) probeTCP(ctx context.Context, target *url.URL) bool {
	host := target.Host
	// Ensure we have a port.
	if _, _, err := net.SplitHostPort(host); err != nil {
		// No port specified, use default based on scheme.
		switch target.Scheme {
		case "https":
			host = net.JoinHostPort(host, "443")
		default:
			host = net.JoinHostPort(host, "80")
		}
	}

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		p.logger.Debug("health check: TCP dial failed",
			"target", target.String(),
			"host", host,
			"error", err,
		)
		return false
	}
	conn.Close()
	return true
}

// recordResult processes the health check outcome and updates target status.
func (p *Pool) recordResult(idx int, ok bool, cfg HealthCheckConfig) {
	target := p.targets[idx]
	wasHealthy := p.healthy[idx].Load()

	if ok {
		p.failures[idx].Store(0)
		s := p.successes[idx].Add(1)

		if !wasHealthy && int(s) >= cfg.HealthyThreshold {
			p.healthy[idx].Store(true)
			p.logger.Info("health check: target recovered",
				"target", target.String(),
				"index", idx,
				"consecutive_successes", s,
			)
		}
	} else {
		p.successes[idx].Store(0)
		f := p.failures[idx].Add(1)

		if wasHealthy && int(f) >= cfg.UnhealthyThreshold {
			p.healthy[idx].Store(false)
			p.logger.Warn("health check: target marked unhealthy",
				"target", target.String(),
				"index", idx,
				"consecutive_failures", f,
			)
		}
	}
}

// ServeHTTP implements http.Handler. Selects a target using the configured
// strategy and proxies the request. Unhealthy targets are skipped.
func (p *Pool) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	idx := p.selectTarget()
	if idx < 0 {
		p.logger.Error("load balancer: no healthy targets available")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprint(w, `{"code":"no_healthy_upstream","status":503,"message":"no healthy upstream targets"}`)
		return
	}
	p.logger.Debug("load balancer routing",
		"strategy", string(p.strategy),
		"target", p.targets[idx].String(),
		"index", idx,
	)
	p.proxies[idx].ServeHTTP(w, r)
}

// selectTarget returns the index of the next target to use, skipping unhealthy targets.
// Returns -1 if no healthy targets are available.
func (p *Pool) selectTarget() int {
	n := len(p.proxies)
	if n == 1 {
		if p.healthy[0].Load() {
			return 0
		}
		return -1
	}

	switch p.strategy {
	case Random:
		return p.selectRandom(n)
	default: // RoundRobin
		return p.selectRoundRobin(n)
	}
}

// selectRoundRobin picks the next healthy target in round-robin order.
func (p *Pool) selectRoundRobin(n int) int {
	start := p.counter.Add(1)
	for i := 0; i < n; i++ {
		idx := int((start - 1 + uint64(i)) % uint64(n)) //nolint:gosec // G115: n is always non-negative (slice length)
		if p.healthy[idx].Load() {
			return idx
		}
	}
	return -1 // all unhealthy
}

// selectRandom picks a random healthy target.
func (p *Pool) selectRandom(n int) int {
	// Try a random target first (fast path).
	idx := rand.IntN(n) //nolint:gosec // G404: non-cryptographic use for load balancing
	if p.healthy[idx].Load() {
		return idx
	}
	// Fallback: scan all targets starting from a random offset.
	for i := 1; i < n; i++ {
		candidate := (idx + i) % n
		if p.healthy[candidate].Load() {
			return candidate
		}
	}
	return -1 // all unhealthy
}

// Targets returns the list of upstream target URLs.
func (p *Pool) Targets() []*url.URL {
	return p.targets
}

// Size returns the number of targets in the pool.
func (p *Pool) Size() int {
	return len(p.targets)
}

// HealthyCount returns the number of currently healthy targets.
func (p *Pool) HealthyCount() int {
	count := 0
	for i := range p.healthy {
		if p.healthy[i].Load() {
			count++
		}
	}
	return count
}

// IsHealthy returns whether a specific target index is healthy.
func (p *Pool) IsHealthy(idx int) bool {
	if idx < 0 || idx >= len(p.healthy) {
		return false
	}
	return p.healthy[idx].Load()
}

// newDirector creates a director function for a given target URL.
//
// Path modes:
//   - "replace" (default): target_url path replaces the incoming request path
//     entirely. Use when target_url contains the full upstream API path.
//   - "append": incoming request path is appended to the target base path.
//     Use when target_url is a base prefix (e.g. "https://api.example.com/v2").
func newDirector(target *url.URL, pathMode string) func(*http.Request) {
	return func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.Host = target.Host

		if pathMode == "append" {
			// Append mode: join target base path + incoming request path.
			req.URL.Path = joinPaths(target.Path, req.URL.Path)
		} else {
			// Replace mode (default): target path IS the upstream path.
			req.URL.Path = target.Path
		}
		req.URL.RawPath = "" // reset encoded path

		// Merge query parameters.
		if target.RawQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = target.RawQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = target.RawQuery + "&" + req.URL.RawQuery
		}

		if _, ok := req.Header["User-Agent"]; !ok {
			req.Header.Set("User-Agent", "")
		}
	}
}

// joinPaths joins a base path and a request path with a single slash separator.
// Ensures no double slashes and handles empty base gracefully.
func joinPaths(base, reqPath string) string {
	if base == "" || base == "/" {
		return reqPath
	}
	if reqPath == "" || reqPath == "/" {
		return base
	}
	return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(reqPath, "/")
}
