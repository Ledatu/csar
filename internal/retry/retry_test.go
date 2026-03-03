package retry

import (
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestMiddleware_NoRetryOnSuccess(t *testing.T) {
	var calls atomic.Int32
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	})

	m := New(upstream, Config{MaxAttempts: 3, Backoff: 10 * time.Millisecond}, testLogger())
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if calls.Load() != 1 {
		t.Errorf("upstream called %d times, want 1", calls.Load())
	}
}

func TestMiddleware_RetriesOn502(t *testing.T) {
	var calls atomic.Int32
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n < 3 {
			w.WriteHeader(http.StatusBadGateway)
			w.Write([]byte(`{"error":"upstream down"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	})

	m := New(upstream, Config{MaxAttempts: 3, Backoff: 10 * time.Millisecond}, testLogger())
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 after retries", rec.Code)
	}
	if calls.Load() != 3 {
		t.Errorf("upstream called %d times, want 3", calls.Load())
	}
}

func TestMiddleware_RetriesOn503And504(t *testing.T) {
	for _, code := range []int{503, 504} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			var calls atomic.Int32
			upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n := calls.Add(1)
				if n == 1 {
					w.WriteHeader(code)
					return
				}
				w.WriteHeader(http.StatusOK)
			})

			m := New(upstream, Config{MaxAttempts: 2, Backoff: 5 * time.Millisecond}, testLogger())
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			rec := httptest.NewRecorder()
			m.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("status = %d, want 200", rec.Code)
			}
			if calls.Load() != 2 {
				t.Errorf("calls = %d, want 2", calls.Load())
			}
		})
	}
}

func TestMiddleware_NoRetryOnNonIdempotent(t *testing.T) {
	var calls atomic.Int32
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	})

	m := New(upstream, Config{MaxAttempts: 3, Backoff: 5 * time.Millisecond}, testLogger())

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		calls.Store(0)
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/test", strings.NewReader(`{}`))
			rec := httptest.NewRecorder()
			m.ServeHTTP(rec, req)

			if rec.Code != http.StatusBadGateway {
				t.Errorf("status = %d, want 502 (no retry for %s)", rec.Code, method)
			}
			if calls.Load() != 1 {
				t.Errorf("calls = %d, want 1 (no retry for %s)", calls.Load(), method)
			}
		})
	}
}

func TestMiddleware_AllAttemptsExhausted(t *testing.T) {
	var calls atomic.Int32
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte(`{"error":"always fail"}`))
	})

	m := New(upstream, Config{MaxAttempts: 3, Backoff: 5 * time.Millisecond}, testLogger())
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502 after all retries exhausted", rec.Code)
	}
	if calls.Load() != 3 {
		t.Errorf("calls = %d, want 3", calls.Load())
	}
	body := rec.Body.String()
	if body != `{"error":"always fail"}` {
		t.Errorf("body = %q, want last upstream response body", body)
	}
}

func TestMiddleware_CustomRetryableMethods(t *testing.T) {
	var calls atomic.Int32
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	cfg := Config{
		MaxAttempts: 2,
		Backoff:     5 * time.Millisecond,
		RetryableMethods: map[string]struct{}{
			http.MethodPost: {}, // Explicitly allow POST retries
		},
	}
	m := New(upstream, cfg, testLogger())
	req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (POST is retryable via custom config)", rec.Code)
	}
	if calls.Load() != 2 {
		t.Errorf("calls = %d, want 2", calls.Load())
	}
}

func TestMiddleware_NoRetryOnNon5xx(t *testing.T) {
	var calls atomic.Int32
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError) // 500 is not in default set
	})

	m := New(upstream, Config{MaxAttempts: 3, Backoff: 5 * time.Millisecond}, testLogger())
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
	if calls.Load() != 1 {
		t.Errorf("calls = %d, want 1 (500 not retryable by default)", calls.Load())
	}
}

func TestMiddleware_ResponseHeadersPreserved(t *testing.T) {
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom", "hello")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"preserved":true}`))
	})

	m := New(upstream, Config{MaxAttempts: 2, Backoff: 5 * time.Millisecond}, testLogger())
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, req)

	if rec.Header().Get("X-Custom") != "hello" {
		t.Errorf("X-Custom header = %q, want %q", rec.Header().Get("X-Custom"), "hello")
	}
	if rec.Header().Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type = %q, want %q", rec.Header().Get("Content-Type"), "application/json")
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.MaxAttempts != 3 {
		t.Errorf("MaxAttempts = %d, want 3", cfg.MaxAttempts)
	}
	if cfg.Backoff != time.Second {
		t.Errorf("Backoff = %v, want 1s", cfg.Backoff)
	}
	if _, ok := cfg.RetryableStatusCodes[502]; !ok {
		t.Error("502 should be retryable by default")
	}
	if _, ok := cfg.RetryableMethods["GET"]; !ok {
		t.Error("GET should be retryable by default")
	}
}

func TestBackoffDelay_Exponential(t *testing.T) {
	m := &Middleware{
		cfg: Config{
			Backoff:    100 * time.Millisecond,
			MaxBackoff: 5 * time.Second,
		},
	}

	// Run multiple times — with jitter the delay should always be ≤ exponential cap.
	for attempt := 1; attempt <= 5; attempt++ {
		for i := 0; i < 100; i++ {
			delay := m.backoffDelay(attempt)
			maxExpected := time.Duration(float64(100*time.Millisecond) * math.Pow(2, float64(attempt-1)))
			if maxExpected > 5*time.Second {
				maxExpected = 5 * time.Second
			}
			if delay > maxExpected {
				t.Errorf("attempt %d: delay %v > max %v", attempt, delay, maxExpected)
			}
			if delay < 0 {
				t.Errorf("attempt %d: delay %v is negative", attempt, delay)
			}
		}
	}
}
