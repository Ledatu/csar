package coordinator

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	credentialv1 "github.com/ledatu/csar-proto/csar/credential/v1"
	"github.com/ledatu/csar/internal/proxy"
	"github.com/ledatu/csar/pkg/middleware"
	csarv1 "github.com/ledatu/csar/proto/csar/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

func newCredentialRPCFetcher(t *testing.T, e *lifetimeEnv) *middleware.CoordinatorTokenFetcher {
	t.Helper()
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	csarv1.RegisterAuthServiceServer(server, e.auth[0])
	credentialv1.RegisterCredentialServiceServer(server, e.reports)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	conn, err := grpc.NewClient("passthrough:///fixture", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return middleware.NewCoordinatorTokenFetcher(csarv1.NewAuthServiceClient(conn), credentialv1.NewCredentialServiceClient(conn))
}

func TestActualProxy401ReportsExactCredentialWithoutReplayingPOST(t *testing.T) {
	e := newLifetimeEnv(t)
	deadline := time.Now().Add(24 * time.Hour)
	e.put(t, "seller/a", "old", &deadline)
	fetcher := newCredentialRPCFetcher(t, e)
	injector := middleware.NewAuthInjector(fetcher, &mockKMSProvider{}, quietLogger())
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") == "Bearer old" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	rp, err := proxy.New(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	handler := injector.Wrap(middleware.AuthInjectorConfig{RejectOnUnauthorized: true, TokenRef: "seller/a", InjectHeader: "Authorization", InjectFormat: "Bearer {token}", OnKMSError: "serve_stale"}, rp)
	observed := 0
	req := httptest.NewRequest(http.MethodPost, "/external/action", strings.NewReader(`{"value":1}`))
	req = req.WithContext(proxy.WithResponseObserver(req.Context(), func(code int) { observed = code }))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized || calls.Load() != 1 || observed != http.StatusUnauthorized {
		t.Fatalf("POST replayed or upstream provenance lost: code=%d calls=%d observed=%d", rec.Code, calls.Load(), observed)
	}
	// Rejected-version propagation is synchronous. A stale fallback must not
	// return the old header on the next credential-resolution failure.
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/external/action", nil))
	if rec.Code != http.StatusBadGateway || calls.Load() != 1 {
		t.Fatalf("rejected value or serve_stale reached upstream: %d calls=%d", rec.Code, calls.Load())
	}
	e.put(t, "seller/a", "replacement", &deadline)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/external/action", nil))
	if rec.Code != http.StatusOK || calls.Load() != 2 {
		t.Fatalf("replacement did not resume demand: %d calls=%d", rec.Code, calls.Load())
	}
}

type observingFetcher struct{ reports atomic.Int32 }

func (f *observingFetcher) GetEncryptedToken(context.Context, string) ([]byte, string, string, error) {
	return []byte("fixture"), "", "v1", nil
}
func (f *observingFetcher) ReportCredentialRejection(context.Context, string, string, string) error {
	f.reports.Add(1)
	return nil
}
func TestLocalAuthentication401DoesNotReportProviderRejection(t *testing.T) {
	fetcher := &observingFetcher{}
	injector := middleware.NewAuthInjector(fetcher, &mockKMSProvider{}, quietLogger())
	handler := injector.Wrap(middleware.AuthInjectorConfig{RejectOnUnauthorized: true, TokenRef: "seller/a", InjectHeader: "Authorization"}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-CSAR-Upstream-Status", "401")
		w.WriteHeader(http.StatusUnauthorized)
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusUnauthorized || fetcher.reports.Load() != 0 {
		t.Fatal("local 401 or spoofed provenance header poisoned a credential")
	}
}
