package throttle

import (
	"context"
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

// Waiter is the interface satisfied by all throttler implementations.
// The router stores a Waiter for each route, allowing local token-bucket,
// Redis GCRA, and dynamic-key throttlers to be used interchangeably.
type Waiter interface {
	// Wait blocks until the request is allowed or the timeout is exceeded.
	Wait(ctx context.Context) error

	// Waiting returns the number of requests currently in the queue.
	Waiting() int64

	// UpdateLimit changes the rate limit dynamically (coordinator quota redistribution).
	UpdateLimit(rps float64, burst int)
}

// Suspendable is an optional interface for throttlers that support
// upstream backpressure suspension. When the upstream returns 429 with
// a Retry-After header, the router calls SuspendFor to pause token
// generation, preventing queued requests from hitting the upstream.
type Suspendable interface {
	SuspendFor(d time.Duration)
}

// RetryEstimator is an optional interface for throttlers that can compute
// a meaningful Retry-After value from their real internal state (rate,
// queue depth, suspension). The router uses this instead of hardcoded
// fallbacks so that csar-ts clients pace themselves accurately.
type RetryEstimator interface {
	EstimateRetryAfter() int
}

// Compile-time checks: all throttler types must satisfy Waiter.
var _ Waiter = (*Throttler)(nil)
var _ Suspendable = (*Throttler)(nil)
var _ RetryEstimator = (*Throttler)(nil)

// Throttler manages per-route rate limiting with wait-based smoothing.
// Instead of rejecting requests with 429, it queues them up to max_wait.
type Throttler struct {
	limiter *rate.Limiter
	maxWait time.Duration

	// Observability: number of requests currently waiting in the queue.
	waiting atomic.Int64

	// Backpressure suspension: when suspendUntil is in the future, Wait()
	// blocks until the suspension expires before attempting token acquisition.
	suspendMu    sync.Mutex
	suspendUntil time.Time
}

// New creates a new Throttler with the given RPS, burst, and max wait time.
// rps: allowed requests per second
// burst: maximum burst size for the token bucket
// maxWait: maximum time a request can wait in the queue (0 = no waiting, reject immediately)
func New(rps float64, burst int, maxWait time.Duration) *Throttler {
	return &Throttler{
		limiter: rate.NewLimiter(rate.Limit(rps), burst),
		maxWait: maxWait,
	}
}

// SuspendFor pauses the throttler for the given duration.
// While suspended, Wait() blocks all requests until the suspension expires.
// This is triggered by adaptive backpressure when the upstream returns 429
// with a Retry-After header — prevents the router from hammering the upstream.
// If already suspended, the deadline is extended if the new one is later.
func (t *Throttler) SuspendFor(d time.Duration) {
	t.suspendMu.Lock()
	until := time.Now().Add(d)
	if until.After(t.suspendUntil) {
		t.suspendUntil = until
	}
	t.suspendMu.Unlock()
}

// Wait blocks until the request is allowed or the max_wait timeout is exceeded.
// Returns nil if the request is allowed, or an error if the wait timed out.
// This is the core "smoothing" logic: requests queue instead of getting 429s.
//
// If the throttler is suspended (via SuspendFor), Wait first blocks until
// the suspension expires, then proceeds with normal token acquisition.
func (t *Throttler) Wait(ctx context.Context) error {
	t.waiting.Add(1)
	defer t.waiting.Add(-1)

	// ── Backpressure suspension check ─────────────────────────────
	t.suspendMu.Lock()
	suspendEnd := t.suspendUntil
	t.suspendMu.Unlock()

	if !suspendEnd.IsZero() && time.Now().Before(suspendEnd) {
		remaining := time.Until(suspendEnd)
		select {
		case <-time.After(remaining):
			// Suspension over — fall through to normal token acquisition.
		case <-ctx.Done():
			return fmt.Errorf("suspended (upstream backpressure): %w", ctx.Err())
		}
	}

	// ── Normal token acquisition ──────────────────────────────────
	waitCtx := ctx
	if t.maxWait > 0 {
		var cancel context.CancelFunc
		waitCtx, cancel = context.WithTimeout(ctx, t.maxWait)
		defer cancel()
	}

	if err := t.limiter.Wait(waitCtx); err != nil {
		if ctx.Err() != nil {
			// The original request context was cancelled (client disconnected)
			return fmt.Errorf("client cancelled: %w", ctx.Err())
		}
		// The max_wait timeout was exceeded
		return fmt.Errorf("queue timeout exceeded (%s): %w", t.maxWait, err)
	}

	return nil
}

// Waiting returns the number of requests currently waiting in the queue.
func (t *Throttler) Waiting() int64 {
	return t.waiting.Load()
}

// EstimateRetryAfter computes a Retry-After value (in seconds) from the
// real token bucket state. The estimate accounts for:
//
//  1. Suspension: if the bucket is suspended (upstream backpressure), the
//     remaining suspension time is returned — no point retrying before then.
//  2. Queue depth + refill rate: each queued request takes ~1/RPS seconds
//     to drain. A new request joining the queue should wait at least
//     ceil((waiting+1) / RPS) seconds.
//  3. max_wait: if configured, caps the estimate — the client shouldn't
//     wait longer than the queue timeout anyway.
//
// The result is always ≥ 1 second.
func (t *Throttler) EstimateRetryAfter() int {
	// If suspended, return the remaining suspension time.
	t.suspendMu.Lock()
	suspendEnd := t.suspendUntil
	t.suspendMu.Unlock()

	if !suspendEnd.IsZero() && time.Now().Before(suspendEnd) {
		secs := int(math.Ceil(time.Until(suspendEnd).Seconds()))
		if secs < 1 {
			secs = 1
		}
		return secs
	}

	// Compute from the actual token refill rate and current queue depth.
	// rate.Limiter.Limit() returns tokens/sec; 1/Limit() = seconds/token.
	rps := float64(t.limiter.Limit())
	if rps <= 0 {
		// Rate is zero or Inf — can't estimate; fall back to 1s.
		return 1
	}

	waiting := t.waiting.Load()
	// How many seconds until (waiting+1) tokens are available:
	secs := int(math.Ceil(float64(waiting+1) / rps))

	// Cap at max_wait if configured — no point telling the client to wait
	// longer than the queue timeout, they'd get rejected anyway.
	if t.maxWait > 0 {
		maxSecs := int(math.Ceil(t.maxWait.Seconds()))
		if secs > maxSecs {
			secs = maxSecs
		}
	}

	if secs < 1 {
		secs = 1
	}
	return secs
}

// UpdateLimit changes the rate limit dynamically (used for quota redistribution).
func (t *Throttler) UpdateLimit(rps float64, burst int) {
	t.limiter.SetLimit(rate.Limit(rps))
	t.limiter.SetBurst(burst)
}

// ThrottleManager manages throttlers for multiple routes.
type ThrottleManager struct {
	mu         sync.RWMutex
	throttlers map[string]Waiter // keyed by "METHOD:PATH"

	// globalThrottle is the global rate limiter checked before per-route throttles.
	globalThrottle *Throttler
}

// NewManager creates a new ThrottleManager.
func NewManager() *ThrottleManager {
	return &ThrottleManager{
		throttlers: make(map[string]Waiter),
	}
}

// SetGlobal sets the global throttle (fallback applied to all routes).
func (m *ThrottleManager) SetGlobal(rps float64, burst int, maxWait time.Duration) {
	m.globalThrottle = New(rps, burst, maxWait)
}

// GetGlobal returns the global throttle, or nil if not configured.
func (m *ThrottleManager) GetGlobal() *Throttler {
	return m.globalThrottle
}

// Register adds or updates a local throttler for the given route key.
func (m *ThrottleManager) Register(key string, rps float64, burst int, maxWait time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.throttlers[key] = New(rps, burst, maxWait)
}

// RegisterWaiter adds or updates a custom Waiter for the given route key.
// Used for Redis GCRA and dynamic-key throttlers.
func (m *ThrottleManager) RegisterWaiter(key string, w Waiter) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.throttlers[key] = w
}

// Get returns the Waiter for the given route key, or nil if not found.
func (m *ThrottleManager) Get(key string) Waiter {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.throttlers[key]
}

// UpdateQuota dynamically adjusts the rate limit for a route.
// Called by the coordinator client when quota assignments change.
// If the route key does not exist, the update is silently ignored
// (the route may not have traffic shaping configured).
func (m *ThrottleManager) UpdateQuota(key string, rps float64, burst int) bool {
	m.mu.RLock()
	t, ok := m.throttlers[key]
	m.mu.RUnlock()
	if !ok {
		return false
	}
	t.UpdateLimit(rps, burst)
	return true
}

// Keys returns all registered route keys.
func (m *ThrottleManager) Keys() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	keys := make([]string, 0, len(m.throttlers))
	for k := range m.throttlers {
		keys = append(keys, k)
	}
	return keys
}

// SyncKeys prunes throttlers whose keys are not in the active set.
// Call this after a SIGHUP-triggered router rebuild to clean up stale entries.
// Returns the number of pruned throttlers.
func (m *ThrottleManager) SyncKeys(activeKeys []string) int {
	active := make(map[string]struct{}, len(activeKeys))
	for _, k := range activeKeys {
		active[k] = struct{}{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	pruned := 0
	for k := range m.throttlers {
		if _, ok := active[k]; !ok {
			delete(m.throttlers, k)
			pruned++
		}
	}
	return pruned
}

// RouteKey generates a consistent key for a route.
func RouteKey(method, path string) string {
	return method + ":" + path
}
