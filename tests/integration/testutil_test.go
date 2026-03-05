package integration

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ledatu/csar/internal/config"
	"github.com/ledatu/csar/internal/router"
	"github.com/ledatu/csar/pkg/health"
)

// ============================================================================
// Mock upstream API server
// ============================================================================

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

// startRouter starts the CSAR router on a random port and returns the URL.
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
