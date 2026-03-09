// Package backpressure provides HTTP middleware that intercepts upstream
// 429 (Too Many Requests) responses, reads the upstream-specified wait time,
// and transparently retries the request after sleeping.
//
// This implements the "Upstream Backpressure Awareness" feature described in
// docs/throttle.md. The middleware sits between the retry handler and the
// proxy, giving it the ability to handle 429s with precise upstream-dictated
// delays rather than exponential backoff.
//
// Security: request bodies are capped at MaxBodyBuffer (default 10 MiB) to
// prevent memory DoS. Non-429 responses are streamed directly to the client
// with zero buffering overhead.
//
// Protocol integration with csar-ts:
//   - On successful transparent retry: the client sees 200 (never sees the 429)
//   - On unrecoverable 429 (wait too long): returns 503 + X-CSAR-Status: throttled
//     so csar-ts can handle it with its own retry/circuit-breaker logic
//
// See: https://github.com/ledatu/csar-ts
package backpressure

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ledatu/csar/internal/apierror"
	"github.com/ledatu/csar/internal/throttle"
)

const (
	// DefaultMaxBodyBuffer is the maximum request body size buffered for
	// transparent retry replay. Requests exceeding this are proxied directly
	// without backpressure interception — preventing memory DoS from large
	// uploads or malicious payloads.
	DefaultMaxBodyBuffer int64 = 10 << 20 // 10 MiB
)

// Config configures the backpressure middleware for a single route.
type Config struct {
	// Enabled toggles upstream backpressure handling.
	Enabled bool

	// RespectHeaders is the ordered list of upstream response headers to
	// check for wait-time information. Checked in order; first match wins.
	// Default: ["Retry-After", "X-RateLimit-Reset"].
	RespectHeaders []string

	// SuspendBucket, when true, pauses the route's token bucket for the
	// upstream-dictated wait duration. This prevents queued requests from
	// hitting the upstream during the backoff period.
	SuspendBucket bool

	// AutoRetry, when true, holds the client connection open, sleeps for
	// the upstream-specified delay, and retries the request transparently.
	// The client never sees the 429.
	AutoRetry bool

	// MaxInternalWait is the maximum time the middleware will hold a client
	// connection for a transparent retry. If the upstream asks to wait longer,
	// the middleware returns 503 + X-CSAR-Status: throttled immediately.
	MaxInternalWait time.Duration

	// MaxBodyBuffer caps the request body size buffered for transparent
	// retries. Bodies larger than this bypass backpressure interception
	// entirely — they are proxied directly without 429 detection or replay.
	// Default: 10 MiB (DefaultMaxBodyBuffer).
	MaxBodyBuffer int64
}

// DefaultRespectHeaders are the response headers checked for wait-time.
var DefaultRespectHeaders = []string{"Retry-After", "X-RateLimit-Reset"}

// Middleware intercepts upstream 429 responses and applies backpressure logic.
type Middleware struct {
	next      http.Handler
	cfg       Config
	throttler throttle.Waiter // for bucket suspension (may implement Suspendable)
	logger    *slog.Logger
}

// New creates a backpressure middleware wrapping the given handler.
// The throttler is used for bucket suspension (optional — may be nil).
func New(next http.Handler, cfg Config, throttler throttle.Waiter, logger *slog.Logger) *Middleware {
	if len(cfg.RespectHeaders) == 0 {
		cfg.RespectHeaders = DefaultRespectHeaders
	}
	if cfg.MaxInternalWait == 0 {
		cfg.MaxInternalWait = 30 * time.Second
	}
	if cfg.MaxBodyBuffer <= 0 {
		cfg.MaxBodyBuffer = DefaultMaxBodyBuffer
	}
	return &Middleware{
		next:      next,
		cfg:       cfg,
		throttler: throttler,
		logger:    logger,
	}
}

// ─── peekWriter ──────────────────────────────────────────────────────────────
// peekWriter wraps an http.ResponseWriter to detect upstream 429 responses
// without buffering the full response body in memory. Non-429 responses are
// streamed directly to the client with zero overhead.
//
// For 429 responses, only the response headers are captured (to extract
// Retry-After / X-RateLimit-Reset); the 429 response body is discarded.

type peekWriter struct {
	w          http.ResponseWriter
	code       int
	is429      bool
	headers429 http.Header // captured for 429 only
	decided    bool
}

func newPeekWriter(w http.ResponseWriter) *peekWriter {
	return &peekWriter{w: w, headers429: make(http.Header)}
}

func (p *peekWriter) Header() http.Header {
	if p.is429 {
		// After 429 detection, any further header writes (e.g. trailers)
		// go to the captured map — not to the real client.
		return p.headers429
	}
	return p.w.Header()
}

func (p *peekWriter) WriteHeader(code int) {
	p.code = code
	p.decided = true

	if code == http.StatusTooManyRequests {
		p.is429 = true
		// Snapshot response headers for backpressure wait-time extraction.
		for k, vv := range p.w.Header() {
			p.headers429[k] = append([]string(nil), vv...)
		}
		// Clear the real writer's headers — they belong to the 429 response
		// and must not leak into the retry response or our 503.
		for k := range p.w.Header() {
			p.w.Header().Del(k)
		}
		return // do NOT call the real WriteHeader
	}

	// Non-429: stream directly to client.
	p.w.WriteHeader(code)
}

func (p *peekWriter) Write(data []byte) (int, error) {
	if !p.decided {
		p.WriteHeader(http.StatusOK) // implicit 200
	}
	if p.is429 {
		// Discard 429 body — we only need the headers.
		return len(data), nil
	}
	return p.w.Write(data)
}

// Flush implements http.Flusher for streaming responses (SSE, chunked).
func (p *peekWriter) Flush() {
	if !p.is429 {
		if f, ok := p.w.(http.Flusher); ok {
			f.Flush()
		}
	}
}

// ─── ServeHTTP ───────────────────────────────────────────────────────────────

// ServeHTTP intercepts the upstream response. On 429:
//  1. Extracts wait time from upstream headers
//  2. Suspends the token bucket (if configured)
//  3. If auto-retry is enabled and wait ≤ max_internal_wait:
//     sleeps and retries the request transparently
//  4. Otherwise: converts to 503 + X-CSAR-Status: throttled for csar-ts
//
// Request bodies are capped at MaxBodyBuffer. Oversized bodies bypass
// interception entirely (proxied directly, no 429 detection/replay).
// Non-429 responses are streamed to the client with zero buffering.
func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !m.cfg.Enabled {
		m.next.ServeHTTP(w, r)
		return
	}

	// ── Cap request body for replay (prevents memory DoS) ────────
	maxBody := m.cfg.MaxBodyBuffer

	// Fast path: if Content-Length is known and exceeds cap, skip entirely.
	if r.ContentLength > maxBody {
		m.logger.Debug("backpressure: body exceeds buffer cap (Content-Length), bypassing",
			"content_length", r.ContentLength, "cap", maxBody)
		m.next.ServeHTTP(w, r)
		return
	}

	// Buffer the request body up to maxBody+1 to detect overflow.
	// Do NOT close r.Body yet — if oversized we need the remaining bytes.
	var bodyBytes []byte
	if r.Body != nil {
		lr := io.LimitReader(r.Body, maxBody+1)
		var err error
		bodyBytes, err = io.ReadAll(lr)
		if err != nil {
			r.Body.Close()
			m.logger.Error("backpressure: failed to buffer request body", "error", err)
			// Best-effort: forward what we have.
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			r.ContentLength = int64(len(bodyBytes))
			m.next.ServeHTTP(w, r)
			return
		}
		if int64(len(bodyBytes)) > maxBody {
			// Oversized (chunked transfer or Content-Length was missing/wrong).
			// Reassemble body: what we read + remaining unread data.
			r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(bodyBytes), r.Body))
			r.ContentLength = -1 // total length unknown
			m.logger.Debug("backpressure: body exceeds buffer cap (read), bypassing",
				"buffered", len(bodyBytes), "cap", maxBody)
			m.next.ServeHTTP(w, r)
			return
		}
		r.Body.Close() // fully consumed within cap — safe to close
	}

	// ── First attempt (zero response buffering for non-429) ──────
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	r.ContentLength = int64(len(bodyBytes))

	pw := newPeekWriter(w)
	m.next.ServeHTTP(pw, r)

	if !pw.is429 {
		// Non-429: response already streamed to client by peekWriter.
		return
	}

	// ── Upstream returned 429 — apply backpressure logic ──────────

	waitDur := m.extractWaitTime(pw.headers429)

	m.logger.Warn("upstream returned 429, backpressure detected",
		"wait_ms", waitDur.Milliseconds(),
		"route", r.URL.Path,
	)

	// Step 1: Suspend the token bucket.
	if m.cfg.SuspendBucket && waitDur > 0 && m.throttler != nil {
		if s, ok := m.throttler.(throttle.Suspendable); ok {
			s.SuspendFor(waitDur)
			m.logger.Info("token bucket suspended due to upstream backpressure",
				"duration", waitDur,
				"route", r.URL.Path,
			)
		}
	}

	// Step 2: Transparent retry (if enabled and within max wait).
	if m.cfg.AutoRetry && waitDur > 0 && waitDur <= m.cfg.MaxInternalWait {
		m.logger.Info("backpressure: holding client connection for transparent retry",
			"wait_ms", waitDur.Milliseconds(),
			"route", r.URL.Path,
		)

		// Sleep for the upstream-dictated delay.
		select {
		case <-time.After(waitDur):
			// Suspension over — retry.
		case <-r.Context().Done():
			// Client disconnected during wait.
			m.logger.Debug("backpressure: client disconnected during wait")
			writeThrottledResponse(w, r, waitDur, m.throttler)
			return
		}

		// Replay the request.
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		r.ContentLength = int64(len(bodyBytes))

		retryPW := newPeekWriter(w)
		m.next.ServeHTTP(retryPW, r)

		if retryPW.is429 {
			m.logger.Warn("backpressure: transparent retry also got 429",
				"route", r.URL.Path,
			)
			// Extend suspension if the retry also 429'd.
			retryWait := m.extractWaitTime(retryPW.headers429)
			if m.cfg.SuspendBucket && retryWait > 0 && m.throttler != nil {
				if s, ok := m.throttler.(throttle.Suspendable); ok {
					s.SuspendFor(retryWait)
				}
			}
			// Convert the 429 into a csar-ts-compatible 503.
			writeThrottledResponse(w, r, retryWait, m.throttler)
			return
		}

		// Success or other status — already streamed to client by retryPW.
		return
	}

	// Step 3: Can't retry (disabled, no wait info, or wait too long).
	// Convert to 503 + X-CSAR-Status: throttled for csar-ts protocol.
	if waitDur > m.cfg.MaxInternalWait && waitDur > 0 {
		m.logger.Warn("backpressure: upstream wait exceeds max_internal_wait, returning 503",
			"upstream_wait", waitDur,
			"max_internal_wait", m.cfg.MaxInternalWait,
			"route", r.URL.Path,
		)
	}
	writeThrottledResponse(w, r, waitDur, m.throttler)
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

// extractWaitTime reads the wait duration from upstream response headers.
// Checks headers in the order specified by RespectHeaders.
// Supports:
//   - Retry-After: integer seconds or HTTP-date (RFC 7231)
//   - X-RateLimit-Reset: Unix timestamp (epoch seconds)
func (m *Middleware) extractWaitTime(headers http.Header) time.Duration {
	for _, h := range m.cfg.RespectHeaders {
		val := headers.Get(h)
		if val == "" {
			continue
		}

		lowerH := strings.ToLower(h)

		// X-RateLimit-Reset: Unix epoch timestamp
		if lowerH == "x-ratelimit-reset" {
			epoch, err := strconv.ParseInt(val, 10, 64)
			if err == nil {
				resetTime := time.Unix(epoch, 0)
				d := time.Until(resetTime)
				if d > 0 {
					return d
				}
			}
			continue
		}

		// Retry-After: integer seconds
		seconds, err := strconv.Atoi(val)
		if err == nil && seconds > 0 {
			return time.Duration(seconds) * time.Second
		}

		// Retry-After: HTTP-date (RFC 7231 / RFC 1123)
		t, err := http.ParseTime(val)
		if err == nil {
			d := time.Until(t)
			if d > 0 {
				return d
			}
		}
	}

	return 0
}

// writeThrottledResponse writes a 503 + X-CSAR-Status: throttled response
// that the csar-ts client SDK understands.
// throttler may be nil; when non-nil and no upstream wait was provided,
// we compute Retry-After from the real bucket state.
func writeThrottledResponse(w http.ResponseWriter, r *http.Request, waitDur time.Duration, t throttle.Waiter) {
	w.Header().Set("X-CSAR-Status", "throttled")

	var retryAfterMS int64
	if waitDur > 0 {
		secs := int(waitDur.Seconds())
		if secs < 1 {
			secs = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		w.Header().Set("X-CSAR-Wait-MS", strconv.FormatInt(waitDur.Milliseconds(), 10))
		retryAfterMS = waitDur.Milliseconds()
	} else if est, ok := t.(throttle.RetryEstimator); ok {
		retryAfter := est.EstimateRetryAfter()
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
		retryAfterMS = int64(retryAfter) * 1000
	} else {
		w.Header().Set("Retry-After", "1")
		retryAfterMS = 1000
	}

	resp := apierror.New(apierror.CodeBackpressure, http.StatusServiceUnavailable,
		"upstream rate limit exceeded").WithRetryAfterMS(retryAfterMS)
	if r != nil {
		resp.WithRequestID(r.Header.Get("X-Request-ID"))
	}
	resp.Write(w)
}
