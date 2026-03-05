package integration

import (
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ledatu/csar/internal/config"
)

// TestE2E_ThrottleSmoothing: 10 RPS limit, burst 2, fire 5 requests — all should
// succeed (smoothed), not get 429s. Verifies the core CSAR philosophy.
func TestE2E_ThrottleSmoothing(t *testing.T) {
	upstream := newUpstreamAPI()
	upstreamURL := startUpstream(t, upstream)

	cfg := &config.Config{
		ListenAddr: ":0",
		Paths: map[string]config.PathConfig{
			"/api/products": {
				"get": config.RouteConfig{
					Backend: config.BackendConfig{TargetURL: upstreamURL},
					Traffic: &config.TrafficConfig{
						RPS:     10,
						Burst:   2,
						MaxWait: config.Duration{Duration: 5 * time.Second},
					},
				},
			},
		},
	}

	routerURL := startRouter(t, cfg)

	// Fire 5 requests concurrently — all should succeed via smoothing
	var wg sync.WaitGroup
	var succeeded atomic.Int64
	var failed atomic.Int64

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := http.Get(routerURL + "/api/products")
			if err != nil {
				failed.Add(1)
				return
			}
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				succeeded.Add(1)
			} else {
				failed.Add(1)
			}
		}()
	}

	wg.Wait()

	if succeeded.Load() != 5 {
		t.Errorf("succeeded = %d, failed = %d, want all 5 to succeed (smoothing)", succeeded.Load(), failed.Load())
	}

	if upstream.getRequestCount() != 5 {
		t.Errorf("upstream received %d requests, want 5", upstream.getRequestCount())
	}
}

// TestE2E_ThrottleTimeout: 1 RPS, burst 1, max_wait 50ms — second request times out.
func TestE2E_ThrottleTimeout(t *testing.T) {
	upstream := newUpstreamAPI()
	upstreamURL := startUpstream(t, upstream)

	cfg := &config.Config{
		ListenAddr: ":0",
		Paths: map[string]config.PathConfig{
			"/api/products": {
				"get": config.RouteConfig{
					Backend: config.BackendConfig{TargetURL: upstreamURL},
					Traffic: &config.TrafficConfig{
						RPS:     1,
						Burst:   1,
						MaxWait: config.Duration{Duration: 50 * time.Millisecond},
					},
				},
			},
		},
	}

	routerURL := startRouter(t, cfg)

	// First request: consumes burst, succeeds
	resp, err := http.Get(routerURL + "/api/products")
	if err != nil {
		t.Fatalf("first GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first request: status = %d, want 200", resp.StatusCode)
	}

	// Second request: 1 RPS means ~1s wait, but max_wait is 50ms → 503
	resp, err = http.Get(routerURL + "/api/products")
	if err != nil {
		t.Fatalf("second GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("second request: status = %d, want 503", resp.StatusCode)
	}

	if resp.Header.Get("Retry-After") == "" {
		t.Error("missing Retry-After header on 503")
	}
}
