// Package retry provides HTTP middleware for retrying upstream requests
// with exponential backoff and jitter.
//
// Only idempotent methods (GET, HEAD, OPTIONS) are retried by default,
// and only on transient upstream errors (502, 503, 504).
//
// Recommended by security audit §3.1: CSAR has circuit breakers but
// lacked immediate retries for transient failures.
package retry

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"
)

// Config configures the retry behavior.
type Config struct {
	// MaxAttempts is the total number of attempts (1 = no retries).
	// If ≤ 0, defaults to 3.
	MaxAttempts int

	// Backoff is the base delay between retries.
	// If ≤ 0, defaults to 1s.
	Backoff time.Duration

	// MaxBackoff caps the exponential backoff. If ≤ 0, defaults to 10s.
	MaxBackoff time.Duration

	// RetryableStatusCodes is the set of HTTP status codes that trigger a retry.
	// If empty, defaults to {502, 503, 504}.
	RetryableStatusCodes map[int]struct{}

	// RetryableMethods is the set of HTTP methods eligible for retry.
	// If empty, defaults to {GET, HEAD, OPTIONS}.
	RetryableMethods map[string]struct{}
}

// DefaultConfig returns a Config with sane defaults.
func DefaultConfig() Config {
	return Config{
		MaxAttempts: 3,
		Backoff:     1 * time.Second,
		MaxBackoff:  10 * time.Second,
		RetryableStatusCodes: map[int]struct{}{
			http.StatusBadGateway:         {},
			http.StatusServiceUnavailable: {},
			http.StatusGatewayTimeout:     {},
		},
		RetryableMethods: map[string]struct{}{
			http.MethodGet:     {},
			http.MethodHead:    {},
			http.MethodOptions: {},
		},
	}
}

// Middleware wraps an http.Handler and retries failed requests per the Config.
type Middleware struct {
	next   http.Handler
	cfg    Config
	logger *slog.Logger
}

// New creates a retry middleware wrapping the given handler.
// The config is merged with defaults — any zero/nil fields use defaults.
func New(next http.Handler, cfg Config, logger *slog.Logger) *Middleware {
	defaults := DefaultConfig()

	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = defaults.MaxAttempts
	}
	if cfg.Backoff <= 0 {
		cfg.Backoff = defaults.Backoff
	}
	if cfg.MaxBackoff <= 0 {
		cfg.MaxBackoff = defaults.MaxBackoff
	}
	if len(cfg.RetryableStatusCodes) == 0 {
		cfg.RetryableStatusCodes = defaults.RetryableStatusCodes
	}
	if len(cfg.RetryableMethods) == 0 {
		cfg.RetryableMethods = defaults.RetryableMethods
	}

	return &Middleware{
		next:   next,
		cfg:    cfg,
		logger: logger,
	}
}

// ServeHTTP implements http.Handler.
func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// If the method is not retryable, pass through immediately.
	if !m.isRetryableMethod(r.Method) {
		m.next.ServeHTTP(w, r)
		return
	}

	// Buffer the request body so we can replay it.
	// For GET/HEAD/OPTIONS the body is usually nil/empty, so this is cheap.
	var bodyBytes []byte
	if r.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(r.Body)
		r.Body.Close()
		if err != nil {
			m.logger.Error("retry: failed to buffer request body", "error", err)
			m.next.ServeHTTP(w, r)
			return
		}
	}

	var lastRecorder *httptest.ResponseRecorder

retryLoop:
	for attempt := 1; attempt <= m.cfg.MaxAttempts; attempt++ {
		// Check if client context is done.
		if r.Context().Err() != nil {
			break
		}

		// Restore the body for each attempt.
		if bodyBytes != nil {
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		} else {
			r.Body = http.NoBody
		}
		r.ContentLength = int64(len(bodyBytes))

		// Capture the response in a recorder.
		rec := httptest.NewRecorder()
		m.next.ServeHTTP(rec, r)
		lastRecorder = rec

		// If the status code is not retryable, we're done.
		if !m.isRetryableStatus(rec.Code) {
			break
		}

		// If this was the last attempt, don't sleep.
		if attempt == m.cfg.MaxAttempts {
			m.logger.Warn("retry: all attempts exhausted",
				"method", r.Method,
				"path", r.URL.Path,
				"status", rec.Code,
				"attempts", attempt,
			)
			break
		}

		// Calculate backoff with jitter.
		delay := m.backoffDelay(attempt)
		m.logger.Warn("retry: upstream returned retryable status, retrying",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.Code,
			"attempt", attempt,
			"next_delay", delay,
		)

		select {
		case <-time.After(delay):
			// Continue to next attempt.
		case <-r.Context().Done():
			// Client disconnected during backoff.
			break retryLoop
		}
	}

	// Write the last captured response to the real ResponseWriter.
	if lastRecorder != nil {
		copyRecorderToResponse(w, lastRecorder)
	} else {
		// Should not happen, but be safe.
		http.Error(w, `{"error":"retry: no response captured"}`, http.StatusBadGateway)
	}
}

// isRetryableMethod checks if the HTTP method is eligible for retry.
func (m *Middleware) isRetryableMethod(method string) bool {
	_, ok := m.cfg.RetryableMethods[strings.ToUpper(method)]
	return ok
}

// isRetryableStatus checks if the HTTP status code should trigger a retry.
func (m *Middleware) isRetryableStatus(code int) bool {
	_, ok := m.cfg.RetryableStatusCodes[code]
	return ok
}

// backoffDelay calculates the exponential backoff with full jitter for the given attempt.
// attempt is 1-indexed (first retry after the initial attempt).
func (m *Middleware) backoffDelay(attempt int) time.Duration {
	// Exponential: base * 2^(attempt-1)
	exp := math.Pow(2, float64(attempt-1))
	delay := time.Duration(float64(m.cfg.Backoff) * exp)
	if delay > m.cfg.MaxBackoff {
		delay = m.cfg.MaxBackoff
	}
	// Full jitter: uniform random in [0, delay]
	if delay > 0 {
		delay = time.Duration(rand.Int64N(int64(delay))) //nolint:gosec // G404: non-cryptographic use for retry jitter
	}
	return delay
}

// copyRecorderToResponse copies the recorded response to the real writer.
func copyRecorderToResponse(w http.ResponseWriter, rec *httptest.ResponseRecorder) {
	// Copy headers.
	for k, vv := range rec.Header() {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(rec.Code)
	if rec.Body != nil {
		if _, err := io.Copy(w, rec.Body); err != nil {
			// Can't do much if the write fails — response is already started.
			_ = err
		}
	}
}

// String returns a human-readable description of the config.
func (c Config) String() string {
	return fmt.Sprintf("retry{max_attempts=%d, backoff=%s, max_backoff=%s}",
		c.MaxAttempts, c.Backoff, c.MaxBackoff)
}
