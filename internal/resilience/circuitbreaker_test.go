package resilience

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCircuitBreaker_ClosedState(t *testing.T) {
	cb := NewCircuitBreaker("test", CircuitBreakerConfig{
		FailureThreshold: 3,
		Timeout:          time.Second,
		MaxRequests:      2,
	})

	if cb.State() != StateClosed {
		t.Errorf("initial state = %v, want closed", cb.State())
	}

	// Successful request should stay closed
	err := cb.Execute(func() error { return nil })
	if err != nil {
		t.Errorf("Execute should succeed in closed state: %v", err)
	}
}

func TestCircuitBreaker_OpensOnFailures(t *testing.T) {
	cb := NewCircuitBreaker("test", CircuitBreakerConfig{
		FailureThreshold: 3,
		Timeout:          time.Second,
		MaxRequests:      2,
	})

	// 3 failures should open the circuit
	for i := 0; i < 3; i++ {
		cb.Execute(func() error { return fmt.Errorf("fail") }) //nolint: errcheck
	}

	if cb.State() != StateOpen {
		t.Errorf("state = %v, want open after %d failures", cb.State(), 3)
	}

	// Next request should be rejected
	err := cb.Execute(func() error { return nil })
	if err == nil {
		t.Error("Execute should fail when circuit is open")
	}
}

func TestCircuitBreaker_TransitionsToHalfOpen(t *testing.T) {
	cb := NewCircuitBreaker("test", CircuitBreakerConfig{
		FailureThreshold: 2,
		Timeout:          50 * time.Millisecond,
		MaxRequests:      2,
	})

	// Open the circuit
	cb.Execute(func() error { return fmt.Errorf("fail") }) //nolint: errcheck
	cb.Execute(func() error { return fmt.Errorf("fail") }) //nolint: errcheck

	if cb.State() != StateOpen {
		t.Fatalf("state = %v, want open", cb.State())
	}

	// Wait for timeout
	time.Sleep(100 * time.Millisecond)

	if cb.State() != StateHalfOpen {
		t.Errorf("state = %v, want half-open after timeout", cb.State())
	}
}

func TestCircuitBreaker_HalfOpenSuccess_CloseCircuit(t *testing.T) {
	cb := NewCircuitBreaker("test", CircuitBreakerConfig{
		FailureThreshold: 2,
		Timeout:          50 * time.Millisecond,
		MaxRequests:      2,
	})

	// Open
	cb.Execute(func() error { return fmt.Errorf("fail") }) //nolint: errcheck
	cb.Execute(func() error { return fmt.Errorf("fail") }) //nolint: errcheck
	time.Sleep(100 * time.Millisecond)

	// Half-open: enough successes should close
	cb.Execute(func() error { return nil }) //nolint: errcheck
	cb.Execute(func() error { return nil }) //nolint: errcheck

	if cb.State() != StateClosed {
		t.Errorf("state = %v, want closed after half-open successes", cb.State())
	}
}

func TestCircuitBreaker_HalfOpenFailure_ReOpensCircuit(t *testing.T) {
	cb := NewCircuitBreaker("test", CircuitBreakerConfig{
		FailureThreshold: 2,
		Timeout:          50 * time.Millisecond,
		MaxRequests:      2,
	})

	// Open
	cb.Execute(func() error { return fmt.Errorf("fail") }) //nolint: errcheck
	cb.Execute(func() error { return fmt.Errorf("fail") }) //nolint: errcheck
	time.Sleep(100 * time.Millisecond)

	// Half-open: one failure should re-open
	cb.Execute(func() error { return fmt.Errorf("still failing") }) //nolint: errcheck

	if cb.State() != StateOpen {
		t.Errorf("state = %v, want open after half-open failure", cb.State())
	}
}

func TestCircuitBreaker_IntervalResetsFailures(t *testing.T) {
	cb := NewCircuitBreaker("test", CircuitBreakerConfig{
		FailureThreshold: 3,
		Timeout:          time.Second,
		MaxRequests:      1,
		Interval:         50 * time.Millisecond,
	})

	// 2 failures (below threshold)
	cb.Execute(func() error { return fmt.Errorf("fail") }) //nolint: errcheck
	cb.Execute(func() error { return fmt.Errorf("fail") }) //nolint: errcheck

	// Wait for interval to reset
	time.Sleep(100 * time.Millisecond)

	// Another failure — should not open because failures were reset
	cb.Execute(func() error { return fmt.Errorf("fail") }) //nolint: errcheck

	if cb.State() != StateClosed {
		t.Errorf("state = %v, want closed (interval should have reset failures)", cb.State())
	}
}

func TestCircuitBreaker_Wrap_HTTP(t *testing.T) {
	cb := NewCircuitBreaker("http-test", CircuitBreakerConfig{
		FailureThreshold: 2,
		Timeout:          50 * time.Millisecond,
		MaxRequests:      1,
	})

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	handler := cb.Wrap(upstream)

	// Two 500s should open the circuit
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}

	// Next request should get 503 from circuit breaker
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d (circuit breaker open)", rec.Code, http.StatusServiceUnavailable)
	}
}

func TestCircuitBreaker_Wrap_HTTP_SuccessDoesNotTrip(t *testing.T) {
	cb := NewCircuitBreaker("http-ok", CircuitBreakerConfig{
		FailureThreshold: 2,
		Timeout:          time.Second,
		MaxRequests:      1,
	})

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	handler := cb.Wrap(upstream)

	for i := 0; i < 10; i++ {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200", i, rec.Code)
		}
	}

	if cb.State() != StateClosed {
		t.Errorf("state = %v, want closed after all successes", cb.State())
	}
}

func TestCircuitBreakerManager(t *testing.T) {
	m := NewCircuitBreakerManager()

	m.Register("api", CircuitBreakerConfig{FailureThreshold: 3})
	m.Register("db", CircuitBreakerConfig{FailureThreshold: 5})

	if m.Get("api") == nil {
		t.Error("Get(api) returned nil")
	}
	if m.Get("db") == nil {
		t.Error("Get(db) returned nil")
	}
	if m.Get("nonexistent") != nil {
		t.Error("Get(nonexistent) should return nil")
	}
}

func TestCircuitState_String(t *testing.T) {
	tests := []struct {
		state CircuitState
		want  string
	}{
		{StateClosed, "closed"},
		{StateOpen, "open"},
		{StateHalfOpen, "half-open"},
		{CircuitState(99), "unknown"},
	}

	for _, tt := range tests {
		if got := tt.state.String(); got != tt.want {
			t.Errorf("State(%d).String() = %q, want %q", tt.state, got, tt.want)
		}
	}
}
