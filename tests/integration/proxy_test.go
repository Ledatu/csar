package integration

import (
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/ledatu/csar-core/health"

	"github.com/ledatu/csar/internal/config"
)

// TestE2E_BasicProxy: client → CSAR router → upstream → response back
func TestE2E_BasicProxy(t *testing.T) {
	upstream := newUpstreamAPI()
	upstreamURL := startUpstream(t, upstream)

	cfg := &config.Config{
		ListenAddr: ":0",
		Paths: map[string]config.PathConfig{
			"/api/products": {
				"get": config.RouteConfig{
					Backend: config.BackendConfig{TargetURL: upstreamURL},
				},
			},
		},
	}

	routerURL := startRouter(t, cfg)

	resp, err := http.Get(routerURL + "/api/products")
	if err != nil {
		t.Fatalf("client GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	var body map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&body)

	products, ok := body["products"]
	if !ok {
		t.Error("response missing 'products' key")
	}
	if arr, ok := products.([]interface{}); !ok || len(arr) != 1 {
		t.Errorf("products = %v, want 1 item", products)
	}

	if upstream.getRequestCount() != 1 {
		t.Errorf("upstream received %d requests, want 1", upstream.getRequestCount())
	}
}

// TestE2E_MultipleRoutes: two different upstream APIs, different methods.
func TestE2E_MultipleRoutes(t *testing.T) {
	upstreamA := newUpstreamAPI()
	upstreamA.setResponse(http.StatusOK, `{"source":"api-a"}`)
	urlA := startUpstream(t, upstreamA)

	upstreamB := newUpstreamAPI()
	upstreamB.setResponse(http.StatusCreated, `{"source":"api-b","created":true}`)
	urlB := startUpstream(t, upstreamB)

	cfg := &config.Config{
		ListenAddr: ":0",
		Paths: map[string]config.PathConfig{
			"/svc-a/products": {
				"get": config.RouteConfig{
					Backend: config.BackendConfig{TargetURL: urlA},
				},
			},
			"/svc-b/products": {
				"post": config.RouteConfig{
					Backend: config.BackendConfig{TargetURL: urlB},
				},
			},
		},
	}

	routerURL := startRouter(t, cfg)

	// GET /svc-a/products → upstream A
	resp, err := http.Get(routerURL + "/svc-a/products")
	if err != nil {
		t.Fatalf("GET svc-a: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("svc-a: status = %d, want 200", resp.StatusCode)
	}
	if !contains(string(body), "api-a") {
		t.Errorf("svc-a: body = %q, want api-a response", body)
	}

	// POST /svc-b/products → upstream B
	resp, err = http.Post(routerURL+"/svc-b/products", "application/json", nil)
	if err != nil {
		t.Fatalf("POST svc-b: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Errorf("svc-b: status = %d, want 201", resp.StatusCode)
	}
	if !contains(string(body), "api-b") {
		t.Errorf("svc-b: body = %q, want api-b response", body)
	}

	// GET /svc-b/products → should 404 (only POST registered)
	resp, err = http.Get(routerURL + "/svc-b/products")
	if err != nil {
		t.Fatalf("GET svc-b: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("svc-b GET: status = %d, want 404", resp.StatusCode)
	}

	if upstreamA.getRequestCount() != 1 {
		t.Errorf("upstream A count = %d, want 1", upstreamA.getRequestCount())
	}
	if upstreamB.getRequestCount() != 1 {
		t.Errorf("upstream B count = %d, want 1", upstreamB.getRequestCount())
	}
}

// TestE2E_HealthEndpoint: /health returns status ok.
func TestE2E_HealthEndpoint(t *testing.T) {
	upstream := newUpstreamAPI()
	upstreamURL := startUpstream(t, upstream)

	cfg := &config.Config{
		ListenAddr: ":0",
		Paths: map[string]config.PathConfig{
			"/api": {
				"get": config.RouteConfig{
					Backend: config.BackendConfig{TargetURL: upstreamURL},
				},
			},
		},
	}

	routerURL := startRouter(t, cfg)

	resp, err := http.Get(routerURL + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	var status health.Status
	json.NewDecoder(resp.Body).Decode(&status)
	if status.Status != "ok" {
		t.Errorf("health status = %q, want ok", status.Status)
	}
}

// TestE2E_UpstreamDown: upstream is unreachable → router returns 502.
func TestE2E_UpstreamDown(t *testing.T) {
	cfg := &config.Config{
		ListenAddr: ":0",
		Paths: map[string]config.PathConfig{
			"/api": {
				"get": config.RouteConfig{
					Backend: config.BackendConfig{TargetURL: "http://127.0.0.1:1"}, // closed port
				},
			},
		},
	}

	routerURL := startRouter(t, cfg)

	resp, err := http.Get(routerURL + "/api")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502 (upstream down)", resp.StatusCode)
	}
}

// TestE2E_ConcurrentLoad: 50 concurrent requests all should succeed via throttle smoothing.
func TestE2E_ConcurrentLoad(t *testing.T) {
	upstream := newUpstreamAPI()
	upstreamURL := startUpstream(t, upstream)

	cfg := &config.Config{
		ListenAddr: ":0",
		Paths: map[string]config.PathConfig{
			"/api/products": {
				"get": config.RouteConfig{
					Backend: config.BackendConfig{TargetURL: upstreamURL},
					Traffic: &config.TrafficConfig{
						RPS:     50,
						Burst:   10,
						MaxWait: config.Duration{Duration: 10 * time.Second},
					},
				},
			},
		},
	}

	routerURL := startRouter(t, cfg)

	const n = 50
	var wg sync.WaitGroup
	results := make([]int, n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			resp, err := http.Get(routerURL + "/api/products")
			if err != nil {
				results[idx] = -1
				return
			}
			resp.Body.Close()
			results[idx] = resp.StatusCode
		}(i)
	}

	wg.Wait()

	okCount := 0
	for _, code := range results {
		if code == http.StatusOK {
			okCount++
		}
	}

	if okCount != n {
		t.Errorf("ok count = %d/%d, want all %d to succeed (smoothing)", okCount, n, n)
	}

	if upstream.getRequestCount() != int64(n) {
		t.Errorf("upstream count = %d, want %d", upstream.getRequestCount(), n)
	}
}
