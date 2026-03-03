package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	grpcinsecure "google.golang.org/grpc/credentials/insecure"

	"github.com/ledatu/csar/internal/config"
	"github.com/ledatu/csar/internal/coordinator"
	"github.com/ledatu/csar/internal/kms"
	"github.com/ledatu/csar/internal/router"
	"github.com/ledatu/csar/pkg/health"
	"github.com/ledatu/csar/pkg/middleware"
	csarv1 "github.com/ledatu/csar/proto/csar/v1"
)

// ============================================================================
// Mock upstream API server
// ============================================================================

// upstreamAPI simulates a real upstream API with configurable behavior.
type upstreamAPI struct {
	srv *http.Server

	mu            sync.Mutex
	requestCount  atomic.Int64
	lastHeaders   http.Header
	responseCode  int
	responseBody  string
	responseDelay time.Duration
}

func newUpstreamAPI() *upstreamAPI {
	return &upstreamAPI{
		responseCode: http.StatusOK,
		responseBody: `{"products":[{"id":1,"name":"Test Product"}]}`,
	}
}

func (u *upstreamAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u.requestCount.Add(1)

	u.mu.Lock()
	u.lastHeaders = r.Header.Clone()
	delay := u.responseDelay
	code := u.responseCode
	body := u.responseBody
	u.mu.Unlock()

	if delay > 0 {
		time.Sleep(delay)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	fmt.Fprint(w, body)
}

func (u *upstreamAPI) setResponse(code int, body string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.responseCode = code
	u.responseBody = body
}

func (u *upstreamAPI) setDelay(d time.Duration) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.responseDelay = d
}

func (u *upstreamAPI) getLastHeaders() http.Header {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.lastHeaders.Clone()
}

func (u *upstreamAPI) getRequestCount() int64 {
	return u.requestCount.Load()
}

// startUpstream starts the mock upstream on a random port and returns the URL.
func startUpstream(t *testing.T, api *upstreamAPI) string {
	t.Helper()

	mux := http.NewServeMux()
	mux.Handle("/", api)

	srv := &http.Server{Handler: mux}
	api.srv = srv

	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}

	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	return "http://" + ln.Addr().String()
}

// ============================================================================
// CSAR Router server
// ============================================================================

func startRouter(t *testing.T, cfg *config.Config, opts ...router.Option) string {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	r, err := router.New(cfg, logger, opts...)
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/health", health.Handler("test"))
	mux.Handle("/", r)

	srv := &http.Server{Handler: mux}

	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("router listen: %v", err)
	}

	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	return "http://" + ln.Addr().String()
}

// ============================================================================
// Integration tests
// ============================================================================

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

	// Client makes a request to the router
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

// TestE2E_AuthTokenInjection: verifies encrypted token is decrypted and injected
// into the upstream request header.
func TestE2E_AuthTokenInjection(t *testing.T) {
	upstream := newUpstreamAPI()
	upstreamURL := startUpstream(t, upstream)

	// Set up KMS + encrypted token
	kmsProvider, _ := kms.NewLocalProvider(map[string]string{"test-key": "integration-passphrase"})
	encToken, _ := kmsProvider.Encrypt(context.Background(), "test-key", []byte("super-secret-api-token"))

	fetcher := middleware.NewStaticTokenFetcher()
	fetcher.Add("api_main", encToken, "test-key")

	injector := middleware.NewAuthInjector(
		fetcher,
		kmsProvider,
		slog.New(slog.NewTextHandler(os.Stderr, nil)),
	)

	cfg := &config.Config{
		ListenAddr: ":0",
		Paths: map[string]config.PathConfig{
			"/api/products": {
				"get": config.RouteConfig{
					Backend: config.BackendConfig{TargetURL: upstreamURL},
				Security: config.SecurityConfigs{
					{
						KMSKeyID:     "test-key",
						TokenRef:     "api_main",
						InjectHeader: "Authorization",
						InjectFormat: "Bearer {token}",
					},
				},
			},
		},
	},
}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	r, err := router.New(cfg, logger, router.WithAuthInjector(injector))
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", r)

	srv := &http.Server{Handler: mux}
	ln, _ := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	routerURL := "http://" + ln.Addr().String()

	// Client request — no Authorization header set by client
	resp, err := http.Get(routerURL + "/api/products")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	// Check the upstream received the injected header
	headers := upstream.getLastHeaders()
	auth := headers.Get("Authorization")
	if auth != "Bearer super-secret-api-token" {
		t.Errorf("upstream Authorization = %q, want %q", auth, "Bearer super-secret-api-token")
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

	// Verify each upstream got exactly 1 request
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

// TestE2E_ConcurrentLoad: hit the router with 50 concurrent requests, all should
// be handled correctly with throttle smoothing.
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

// TestE2E_SecureRoute_CoordinatorGRPC: full end-to-end test proving that
// a secure route can fetch tokens via the coordinator's gRPC AuthService,
// decrypt them with KMS, and inject them into the upstream request.
func TestE2E_SecureRoute_CoordinatorGRPC(t *testing.T) {
	// 1. Set up KMS provider (local for test)
	kmsProvider, err := kms.NewLocalProvider(map[string]string{"test-key": "e2e-passphrase"})
	if err != nil {
		t.Fatalf("NewLocalProvider: %v", err)
	}

	// Encrypt a token
	plainToken := "coordinator-provided-secret-token"
	encToken, err := kmsProvider.Encrypt(context.Background(), "test-key", []byte(plainToken))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// 2. Start coordinator gRPC server with AuthService
	coordLogger := slog.New(slog.NewTextHandler(io.Discard, nil))
	authSvc := coordinator.NewAuthService(coordLogger)
	authSvc.LoadToken("api_main", coordinator.TokenEntry{
		EncryptedToken: encToken,
		KMSKeyID:       "test-key",
	})

	grpcSrv := grpc.NewServer()
	csarv1.RegisterAuthServiceServer(grpcSrv, authSvc)

	grpcLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("grpc listen: %v", err)
	}
	go grpcSrv.Serve(grpcLn)
	t.Cleanup(func() { grpcSrv.Stop() })

	coordAddr := grpcLn.Addr().String()

	// 3. Connect router to the coordinator's AuthService
	conn, err := grpc.NewClient(coordAddr, grpc.WithTransportCredentials(grpcinsecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	authClient := csarv1.NewAuthServiceClient(conn)
	fetcher := middleware.NewCoordinatorTokenFetcher(authClient)
	injector := middleware.NewAuthInjector(fetcher, kmsProvider, coordLogger)

	// 4. Start upstream
	upstream := newUpstreamAPI()
	upstreamURL := startUpstream(t, upstream)

	// 5. Create router config with a secure route
	cfg := &config.Config{
		ListenAddr: ":0",
		Paths: map[string]config.PathConfig{
			"/api/products": {
				"get": config.RouteConfig{
					Backend: config.BackendConfig{TargetURL: upstreamURL},
				Security: config.SecurityConfigs{
					{
						KMSKeyID:     "test-key",
						TokenRef:     "api_main",
						InjectHeader: "Authorization",
						InjectFormat: "Bearer {token}",
					},
				},
			},
		},
	},
}

	routerURL := startRouter(t, cfg, router.WithAuthInjector(injector))

	// 6. Client request — no Authorization header
	resp, err := http.Get(routerURL + "/api/products")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	// 7. Verify the upstream received the decrypted token
	headers := upstream.getLastHeaders()
	auth := headers.Get("Authorization")
	want := "Bearer " + plainToken
	if auth != want {
		t.Errorf("upstream Authorization = %q, want %q", auth, want)
	}
}

// --- helpers ---

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsImpl(s, substr))
}

func containsImpl(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
