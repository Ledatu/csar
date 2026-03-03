// Package e2e contains end-to-end tests that run against real Docker containers.
// These tests expect:
//   - CSAR router at CSAR_URL (default http://csar:8080)
//   - Mock upstream at MOCKAPI_URL (default http://mockapi:9999)
package e2e

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func csarURL() string {
	if u := os.Getenv("CSAR_URL"); u != "" {
		return u
	}
	return "http://csar:8080"
}

func mockURL() string {
	if u := os.Getenv("MOCKAPI_URL"); u != "" {
		return u
	}
	return "http://mockapi:9999"
}

var client = &http.Client{Timeout: 30 * time.Second}

// waitForReady polls the health endpoints until both services are up.
func waitForReady(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)

	for _, svc := range []struct {
		name string
		url  string
	}{
		{"mockapi", mockURL() + "/health"},
		{"csar", csarURL() + "/health"},
	} {
		for {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s at %s", svc.name, svc.url)
			}
			resp, err := client.Get(svc.url)
			if err == nil && resp.StatusCode == http.StatusOK {
				resp.Body.Close()
				t.Logf("%s is ready", svc.name)
				break
			}
			if resp != nil {
				resp.Body.Close()
			}
			time.Sleep(500 * time.Millisecond)
		}
	}
}

// ---- Tests ----

func TestE2E_HealthCheck(t *testing.T) {
	waitForReady(t)

	resp, err := client.Get(csarURL() + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	var body map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&body)
	if body["status"] != "ok" {
		t.Errorf("health status = %v, want ok", body["status"])
	}
}

func TestE2E_BasicProxy_GET(t *testing.T) {
	waitForReady(t)

	resp, err := client.Get(csarURL() + "/api/products")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}

	var body map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&body)

	products, ok := body["products"].([]interface{})
	if !ok || len(products) == 0 {
		t.Errorf("expected non-empty products array, got %v", body["products"])
	}
}

func TestE2E_BasicProxy_POST(t *testing.T) {
	waitForReady(t)

	resp, err := client.Post(csarURL()+"/api/products/create", "application/json",
		strings.NewReader(`{"name":"Test Product"}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}

	var body map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&body)
	if body["created"] != true {
		t.Errorf("expected created=true, got %v", body)
	}
}

func TestE2E_ThrottleSmoothing(t *testing.T) {
	waitForReady(t)

	// Fire 8 concurrent requests through the throttled route (10 RPS, burst 3, max_wait 5s)
	// All should succeed — CSAR smooths instead of rejecting
	const n = 8
	var wg sync.WaitGroup
	var succeeded atomic.Int64

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := client.Get(csarURL() + "/api/throttled")
			if err != nil {
				return
			}
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				succeeded.Add(1)
			}
		}()
	}

	wg.Wait()

	if s := succeeded.Load(); s != n {
		t.Errorf("succeeded = %d/%d, want all %d to succeed via smoothing", s, n, n)
	}
}

func TestE2E_ThrottleTimeout(t *testing.T) {
	waitForReady(t)

	// Hit the tight route (1 RPS, burst 1, max_wait 100ms)
	// First request consumes burst, second should get 503

	resp1, err := client.Get(csarURL() + "/api/tight")
	if err != nil {
		t.Fatalf("first GET: %v", err)
	}
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first request: status = %d, want 200", resp1.StatusCode)
	}

	resp2, err := client.Get(csarURL() + "/api/tight")
	if err != nil {
		t.Fatalf("second GET: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("second request: status = %d, want 503 (throttle timeout)", resp2.StatusCode)
	}
	if resp2.Header.Get("Retry-After") == "" {
		t.Error("missing Retry-After header on 503")
	}
}

func TestE2E_CircuitBreaker(t *testing.T) {
	waitForReady(t)

	// /api/flaky → mockapi /flaky?fail_count=2 which returns 500 for first 2 requests, then 200
	// Circuit breaker: failure_threshold=2, timeout=200ms

	// 1) Two 500s → trips the breaker
	for i := 0; i < 2; i++ {
		resp, err := client.Get(csarURL() + "/api/flaky")
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusInternalServerError {
			t.Logf("request %d: status = %d (expected 500)", i, resp.StatusCode)
		}
	}

	// 2) Immediate request → circuit should be open → 503
	resp, err := client.Get(csarURL() + "/api/flaky")
	if err != nil {
		t.Fatalf("tripped GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("tripped: status = %d, want 503, body = %s", resp.StatusCode, body)
	}

	// 3) Wait for circuit timeout (200ms), then request should go through (half-open)
	//    The upstream has exhausted its fail_count=2, so this request returns 200.
	time.Sleep(300 * time.Millisecond)

	resp, err = client.Get(csarURL() + "/api/flaky")
	if err != nil {
		t.Fatalf("recovery GET: %v", err)
	}
	resp.Body.Close()

	// The mockapi /flaky?fail_count=2 returns 500 for first 2, then 200.
	// This is the 3rd actual upstream hit — should succeed.
	if resp.StatusCode != http.StatusOK {
		t.Errorf("recovery: status = %d, want 200", resp.StatusCode)
	}
}

func TestE2E_HeaderPassthrough(t *testing.T) {
	waitForReady(t)

	req, _ := http.NewRequest("GET", csarURL()+"/api/echo-headers", nil)
	req.Header.Set("X-Custom-Header", "test-value-123")
	req.Header.Set("X-Request-Id", "e2e-req-001")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}

	var headers map[string]string
	json.NewDecoder(resp.Body).Decode(&headers)

	if v := headers["X-Custom-Header"]; v != "test-value-123" {
		t.Errorf("X-Custom-Header = %q, want test-value-123", v)
	}
	if v := headers["X-Request-Id"]; v != "e2e-req-001" {
		t.Errorf("X-Request-Id = %q, want e2e-req-001", v)
	}
}

func TestE2E_NotFound(t *testing.T) {
	waitForReady(t)

	resp, err := client.Get(csarURL() + "/nonexistent/route")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func TestE2E_ConcurrentLoad(t *testing.T) {
	waitForReady(t)

	const n = 30
	var wg sync.WaitGroup
	var ok, fail atomic.Int64

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := client.Get(csarURL() + "/api/throttled")
			if err != nil {
				fail.Add(1)
				return
			}
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				ok.Add(1)
			} else {
				fail.Add(1)
			}
		}()
	}

	wg.Wait()

	t.Logf("concurrent load: ok=%d fail=%d total=%d", ok.Load(), fail.Load(), n)
	if ok.Load() != int64(n) {
		t.Errorf("ok = %d/%d, want all to succeed via smoothing", ok.Load(), n)
	}
}

func TestE2E_MockAPIDirectly(t *testing.T) {
	waitForReady(t)

	// Verify the mockapi is working independently
	resp, err := client.Get(mockURL() + "/products")
	if err != nil {
		t.Fatalf("GET mockapi /products: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("mockapi status = %d, want 200", resp.StatusCode)
	}

	// Check stats endpoint
	resp2, err := client.Get(mockURL() + "/stats")
	if err != nil {
		t.Fatalf("GET mockapi /stats: %v", err)
	}
	defer resp2.Body.Close()

	var stats map[string]interface{}
	json.NewDecoder(resp2.Body).Decode(&stats)
	count := stats["total_requests"].(float64)
	if count < 1 {
		t.Errorf("mockapi total_requests = %v, want >= 1", count)
	}
	fmt.Printf("mockapi handled %.0f total requests\n", count)
}

// ==========================================================================
// Coordinated Auth Injection Tests
// ==========================================================================

// TestE2E_Coordinator_AuthInjection_Bearer verifies the full coordinator flow:
// coordinator serves encrypted token → router fetches via gRPC → decrypts with
// local KMS → injects "Authorization: Bearer <plaintext>" into the upstream request.
func TestE2E_Coordinator_AuthInjection_Bearer(t *testing.T) {
	waitForReady(t)

	resp, err := client.Get(csarURL() + "/api/secured")
	if err != nil {
		t.Fatalf("GET /api/secured: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200, body = %s", resp.StatusCode, body)
	}

	// The mockapi echo-headers endpoint returns all received headers as JSON.
	var headers map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&headers); err != nil {
		t.Fatalf("decoding echo-headers response: %v", err)
	}

	// The token plaintext is "super-secret-bearer-token-12345" (from gen_coord_tokens).
	want := "Bearer super-secret-bearer-token-12345"
	if got := headers["Authorization"]; got != want {
		t.Errorf("Authorization header = %q, want %q", got, want)
	}
}

// TestE2E_Coordinator_AuthInjection_ApiKey verifies injection with a different
// header (Api-Key) and no "Bearer" prefix — just the raw decrypted token.
func TestE2E_Coordinator_AuthInjection_ApiKey(t *testing.T) {
	waitForReady(t)

	resp, err := client.Get(csarURL() + "/api/secured-apikey")
	if err != nil {
		t.Fatalf("GET /api/secured-apikey: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200, body = %s", resp.StatusCode, body)
	}

	var headers map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&headers); err != nil {
		t.Fatalf("decoding echo-headers response: %v", err)
	}

	// The token plaintext is "another-secret-key-67890" (from gen_coord_tokens).
	want := "another-secret-key-67890"
	if got := headers["Api-Key"]; got != want {
		t.Errorf("Api-Key header = %q, want %q", got, want)
	}
}

// TestE2E_Coordinator_SecuredRoute_NoLeakedCiphertext ensures the upstream
// never sees the raw encrypted blob — only the decrypted plaintext.
func TestE2E_Coordinator_SecuredRoute_NoLeakedCiphertext(t *testing.T) {
	waitForReady(t)

	resp, err := client.Get(csarURL() + "/api/secured")
	if err != nil {
		t.Fatalf("GET /api/secured: %v", err)
	}
	defer resp.Body.Close()

	var headers map[string]string
	json.NewDecoder(resp.Body).Decode(&headers)

	auth := headers["Authorization"]
	if auth == "" {
		t.Fatal("Authorization header is empty — auth injection may have failed")
	}

	// Ciphertext is base64-encoded; the plaintext should NOT contain base64 padding
	// or match the encrypted blob pattern. Simple sanity check:
	if strings.Contains(auth, "==") {
		t.Errorf("Authorization looks like it might contain base64 ciphertext: %q", auth)
	}

	// The injected value must be the expected decrypted plaintext.
	want := "Bearer super-secret-bearer-token-12345"
	if auth != want {
		t.Errorf("Authorization = %q, want %q", auth, want)
	}
}
