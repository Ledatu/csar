package crypto

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// DevServerOptions configures the development JWKS HTTP server.
type DevServerOptions struct {
	// PubKeyPath is the path to a PEM-encoded public key file.
	// Used to generate JWKS on the fly. Mutually exclusive with JWKSFile.
	PubKeyPath string

	// JWKSFile is the path to an existing jwks.json file to serve directly.
	JWKSFile string

	// Addr is the listen address (default ":8080").
	Addr string

	Logger *slog.Logger
}

// RunDevJWKSServer starts an HTTP server that serves JWKS at /.well-known/jwks.json.
// It blocks until interrupted (SIGINT/SIGTERM) and performs graceful shutdown.
func RunDevJWKSServer(opts DevServerOptions) error {
	var jwksBytes []byte
	var err error

	switch {
	case opts.JWKSFile != "":
		jwksBytes, err = os.ReadFile(opts.JWKSFile)
		if err != nil {
			return fmt.Errorf("reading JWKS file: %w", err)
		}
	case opts.PubKeyPath != "":
		jwksBytes, err = PublicKeyToJWKS(opts.PubKeyPath)
		if err != nil {
			return fmt.Errorf("converting public key to JWKS: %w", err)
		}
	default:
		return fmt.Errorf("either --pub-key or --jwks-file is required")
	}

	if opts.Addr == "" {
		opts.Addr = ":8080"
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-cache, no-store")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		_, _ = w.Write(jwksBytes)
	})

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "ok")
	})

	srv := &http.Server{
		Addr:              opts.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ln, err := net.Listen("tcp", opts.Addr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", opts.Addr, err)
	}

	jwksURL := fmt.Sprintf("http://%s/.well-known/jwks.json", ln.Addr())
	opts.Logger.Info("dev JWKS server started",
		"addr", ln.Addr().String(),
		"jwks_url", jwksURL,
	)
	fmt.Printf("\n  JWKS endpoint: %s\n  Health check:  http://%s/health\n\n  Press Ctrl+C to stop.\n\n", jwksURL, ln.Addr())

	go func() {
		<-ctx.Done()
		opts.Logger.Info("shutting down dev JWKS server")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}
