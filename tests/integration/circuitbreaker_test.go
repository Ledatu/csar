package integration

import (
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/ledatu/csar/internal/config"
)

// TestE2E_CircuitBreaker: upstream returns 500s → circuit opens → subsequent
// requests get 503 without hitting upstream.
func TestE2E_CircuitBreaker(t *testing.T) {
	upstream := newUpstreamAPI()
	upstream.setResponse(http.StatusInternalServerError, `{"error":"db down"}`)
	upstreamURL := startUpstream(t, upstream)

	cfg := &config.Config{
		ListenAddr: ":0",
		CircuitBreakers: map[string]config.CircuitBreakerProfile{
			"test_breaker": {
				MaxRequests:      1,
				Interval:         config.Duration{Duration: 60 * time.Second},
				Timeout:          config.Duration{Duration: 100 * time.Millisecond},
				FailureThreshold: 2,
			},
		},
		Paths: map[string]config.PathConfig{
			"/api/products": {
				"get": config.RouteConfig{
					Backend:    config.BackendConfig{TargetURL: upstreamURL},
					Resilience: &config.ResilienceConfig{CircuitBreaker: "test_breaker"},
				},
			},
		},
	}

	routerURL := startRouter(t, cfg)

	// 2 requests with 500 → trips the breaker
	for i := 0; i < 2; i++ {
		resp, err := http.Get(routerURL + "/api/products")
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusInternalServerError {
			t.Errorf("request %d: status = %d, want 500", i, resp.StatusCode)
		}
	}

	countBeforeTrip := upstream.getRequestCount()

	// Next request: circuit should be open → 503, upstream NOT called
	resp, err := http.Get(routerURL + "/api/products")
	if err != nil {
		t.Fatalf("tripped request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("tripped: status = %d, want 503", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !contains(string(body), "circuit breaker open") {
		t.Errorf("body = %q, should mention circuit breaker", string(body))
	}

	// Upstream should NOT have received the tripped request
	if upstream.getRequestCount() != countBeforeTrip {
		t.Errorf("upstream count = %d after trip, want %d (should not be called)", upstream.getRequestCount(), countBeforeTrip)
	}

	// Wait for timeout, circuit should go half-open
	time.Sleep(150 * time.Millisecond)

	// Now fix the upstream
	upstream.setResponse(http.StatusOK, `{"status":"recovered"}`)

	// Request in half-open → should succeed and close the circuit
	resp, err = http.Get(routerURL + "/api/products")
	if err != nil {
		t.Fatalf("recovery request: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("recovery: status = %d, want 200", resp.StatusCode)
	}
}
