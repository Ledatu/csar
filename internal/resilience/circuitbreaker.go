package resilience

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

// CircuitState represents the state of a circuit breaker.
type CircuitState int

const (
	StateClosed   CircuitState = iota // Normal operation
	StateOpen                         // Failing, rejecting requests
	StateHalfOpen                     // Testing if upstream recovered
)

func (s CircuitState) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateOpen:
		return "open"
	case StateHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// CircuitBreakerConfig configures a circuit breaker.
type CircuitBreakerConfig struct {
	// MaxRequests is the max number of requests allowed in half-open state.
	MaxRequests uint32

	// Interval is the cyclic period of the closed state for clearing internal counts.
	Interval time.Duration

	// Timeout is the period of the open state before switching to half-open.
	Timeout time.Duration

	// FailureThreshold is the number of consecutive failures before opening.
	FailureThreshold uint32
}

// CircuitBreaker implements the circuit breaker pattern.
type CircuitBreaker struct {
	cfg   CircuitBreakerConfig
	name  string

	mu               sync.Mutex
	state            CircuitState
	failures         uint32
	successes        uint32
	halfOpenRequests uint32
	lastStateChange  time.Time
	intervalStart    time.Time
}

// NewCircuitBreaker creates a circuit breaker with the given config.
func NewCircuitBreaker(name string, cfg CircuitBreakerConfig) *CircuitBreaker {
	now := time.Now()
	return &CircuitBreaker{
		name:            name,
		cfg:             cfg,
		state:           StateClosed,
		lastStateChange: now,
		intervalStart:   now,
	}
}

// Execute runs the given function through the circuit breaker.
// Returns an error if the circuit is open or the function fails.
func (cb *CircuitBreaker) Execute(fn func() error) error {
	if err := cb.beforeRequest(); err != nil {
		return err
	}

	err := fn()

	cb.afterRequest(err)
	return err
}

// State returns the current circuit breaker state.
func (cb *CircuitBreaker) State() CircuitState {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.currentState()
}

// Wrap returns an http.Handler that wraps the given handler with circuit breaking.
func (cb *CircuitBreaker) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := cb.beforeRequest(); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, `{"error":"circuit breaker open","breaker":%q,"state":%q}`, cb.name, cb.State())
			return
		}

		// Use a response recorder to check the status code
		rec := &statusRecorder{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(rec, r)

		// Treat 5xx as failure
		if rec.statusCode >= 500 {
			cb.afterRequest(fmt.Errorf("upstream returned %d", rec.statusCode))
		} else {
			cb.afterRequest(nil)
		}
	})
}

func (cb *CircuitBreaker) beforeRequest() error {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	state := cb.currentState()

	switch state {
	case StateClosed:
		return nil
	case StateOpen:
		return fmt.Errorf("circuit breaker %q is open", cb.name)
	case StateHalfOpen:
		if cb.halfOpenRequests >= cb.cfg.MaxRequests {
			return fmt.Errorf("circuit breaker %q is half-open, max requests reached", cb.name)
		}
		cb.halfOpenRequests++
		return nil
	}
	return nil
}

func (cb *CircuitBreaker) afterRequest(err error) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	state := cb.currentState()

	if err != nil {
		cb.onFailure(state)
	} else {
		cb.onSuccess(state)
	}
}

func (cb *CircuitBreaker) onSuccess(state CircuitState) {
	switch state {
	case StateClosed:
		cb.failures = 0
	case StateHalfOpen:
		cb.successes++
		if cb.successes >= cb.cfg.MaxRequests {
			cb.setState(StateClosed)
		}
	}
}

func (cb *CircuitBreaker) onFailure(state CircuitState) {
	switch state {
	case StateClosed:
		cb.failures++
		if cb.failures >= cb.cfg.FailureThreshold {
			cb.setState(StateOpen)
		}
	case StateHalfOpen:
		cb.setState(StateOpen)
	}
}

func (cb *CircuitBreaker) setState(state CircuitState) {
	cb.state = state
	cb.lastStateChange = time.Now()
	cb.failures = 0
	cb.successes = 0
	cb.halfOpenRequests = 0
}

// currentState returns the current state, checking for automatic transitions.
// Must be called with mu held.
func (cb *CircuitBreaker) currentState() CircuitState {
	switch cb.state {
	case StateClosed:
		// Check if the interval has passed — reset failure count
		if cb.cfg.Interval > 0 && time.Since(cb.intervalStart) > cb.cfg.Interval {
			cb.intervalStart = time.Now()
			cb.failures = 0
		}
	case StateOpen:
		// Check if timeout has passed — switch to half-open
		if time.Since(cb.lastStateChange) > cb.cfg.Timeout {
			cb.setState(StateHalfOpen)
		}
	}
	return cb.state
}

// statusRecorder wraps http.ResponseWriter to capture the status code.
type statusRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.statusCode = code
	r.ResponseWriter.WriteHeader(code)
}

// CircuitBreakerManager manages named circuit breakers.
type CircuitBreakerManager struct {
	mu       sync.RWMutex
	breakers map[string]*CircuitBreaker
}

// NewCircuitBreakerManager creates a new manager.
func NewCircuitBreakerManager() *CircuitBreakerManager {
	return &CircuitBreakerManager{
		breakers: make(map[string]*CircuitBreaker),
	}
}

// Register creates and stores a circuit breaker with the given name and config.
func (m *CircuitBreakerManager) Register(name string, cfg CircuitBreakerConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.breakers[name] = NewCircuitBreaker(name, cfg)
}

// Get returns the circuit breaker with the given name, or nil.
func (m *CircuitBreakerManager) Get(name string) *CircuitBreaker {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.breakers[name]
}
