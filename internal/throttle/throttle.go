package throttle

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

// Throttler manages per-route rate limiting with wait-based smoothing.
// Instead of rejecting requests with 429, it queues them up to max_wait.
type Throttler struct {
	limiter *rate.Limiter
	maxWait time.Duration

	// Observability: number of requests currently waiting in the queue.
	waiting atomic.Int64
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

// Wait blocks until the request is allowed or the max_wait timeout is exceeded.
// Returns nil if the request is allowed, or an error if the wait timed out.
// This is the core "smoothing" logic: requests queue instead of getting 429s.
func (t *Throttler) Wait(ctx context.Context) error {
	t.waiting.Add(1)
	defer t.waiting.Add(-1)

	// Create a context with the max_wait timeout
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

// UpdateLimit changes the rate limit dynamically (used for quota redistribution).
func (t *Throttler) UpdateLimit(rps float64, burst int) {
	t.limiter.SetLimit(rate.Limit(rps))
	t.limiter.SetBurst(burst)
}

// ThrottleManager manages throttlers for multiple routes.
type ThrottleManager struct {
	mu         sync.RWMutex
	throttlers map[string]*Throttler // keyed by "METHOD:PATH"
}

// NewManager creates a new ThrottleManager.
func NewManager() *ThrottleManager {
	return &ThrottleManager{
		throttlers: make(map[string]*Throttler),
	}
}

// Register adds or updates a throttler for the given route key.
func (m *ThrottleManager) Register(key string, rps float64, burst int, maxWait time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.throttlers[key] = New(rps, burst, maxWait)
}

// Get returns the throttler for the given route key, or nil if not found.
func (m *ThrottleManager) Get(key string) *Throttler {
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

// RouteKey generates a consistent key for a route.
func RouteKey(method, path string) string {
	return method + ":" + path
}
