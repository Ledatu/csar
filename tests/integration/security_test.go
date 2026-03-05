package integration

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"testing"

	"google.golang.org/grpc"
	grpcinsecure "google.golang.org/grpc/credentials/insecure"

	"github.com/ledatu/csar/internal/config"
	"github.com/ledatu/csar/internal/coordinator"
	"github.com/ledatu/csar/internal/kms"
	"github.com/ledatu/csar/internal/router"
	"github.com/ledatu/csar/pkg/middleware"
	csarv1 "github.com/ledatu/csar/proto/csar/v1"
)

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
