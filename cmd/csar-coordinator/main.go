package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"gopkg.in/yaml.v3"

	"github.com/ledatu/csar/internal/coordinator"
	"github.com/ledatu/csar/internal/statestore"
	csarv1 "github.com/ledatu/csar/proto/csar/v1"
)

var (
	version = "dev"
)

func main() {
	listenAddr := flag.String("listen", ":9090", "gRPC listen address")
	tlsCert := flag.String("tls-cert", "", "path to TLS server certificate (PEM)")
	tlsKey := flag.String("tls-key", "", "path to TLS server private key (PEM)")
	clientCA := flag.String("client-ca", "", "path to client CA certificate for mTLS (PEM)")
	allowedRouters := flag.String("allowed-routers", "", "comma-separated list of allowed router CN/SAN identities (empty = allow all authenticated)")
	allowInsecureDev := flag.Bool("allow-insecure-dev", false, "allow running without TLS (development only — NEVER use in production)")
	tokenFile := flag.String("token-file", "", "path to YAML file with pre-encrypted token entries for AuthService")

	// State store flags
	storeType := flag.String("store", "memory", "state store backend: memory, etcd")
	etcdEndpoints := flag.String("etcd-endpoints", "localhost:2379", "comma-separated etcd endpoints")
	etcdPrefix := flag.String("etcd-prefix", "/csar", "etcd key prefix")
	etcdRouterTTL := flag.Int64("etcd-router-ttl", 30, "etcd lease TTL in seconds for router entries")

	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	logger.Info("starting csar-coordinator",
		"version", version,
		"listen", *listenAddr,
		"store", *storeType,
	)

	// Initialize state store
	var store statestore.StateStore
	switch *storeType {
	case "memory":
		store = statestore.NewMemoryStore()
		logger.Info("using in-memory state store (non-persistent)")
	case "etcd":
		endpoints := strings.Split(*etcdEndpoints, ",")
		es, err := statestore.NewEtcdStore(statestore.EtcdConfig{
			Endpoints:      endpoints,
			Prefix:         *etcdPrefix,
			RouterLeaseTTL: *etcdRouterTTL,
		})
		if err != nil {
			logger.Error("failed to create etcd state store",
				"endpoints", endpoints,
				"error", err,
			)
			os.Exit(1)
		}
		store = es
		logger.Info("using etcd state store",
			"endpoints", endpoints,
			"prefix", *etcdPrefix,
			"router_lease_ttl", *etcdRouterTTL,
		)
	default:
		logger.Error("unknown state store type", "store", *storeType)
		os.Exit(1)
	}
	defer store.Close()

	// Create coordinator
	coord := coordinator.New(store, logger)

	// Create AuthService for token delivery to routers
	authSvc := coordinator.NewAuthService(logger)

	if *tokenFile != "" {
		entries, err := loadCoordinatorTokenFile(*tokenFile)
		if err != nil {
			logger.Error("failed to load coordinator token file", "error", err)
			os.Exit(1)
		}
		loaded := authSvc.LoadTokensFromMap(entries)
		logger.Info("loaded tokens into AuthService", "file", *tokenFile, "count", loaded)

		if err := authSvc.Validate(); err != nil {
			logger.Error("AuthService token store is empty after loading token file — "+
				"check file format and contents", "file", *tokenFile, "error", err)
			os.Exit(1)
		}
	} else {
		// No token file provided. Behavior depends on security mode.
		logger.Warn("WARNING: no --token-file provided — AuthService has no tokens loaded. " +
			"All GetEncryptedToken RPCs will return NotFound. " +
			"Provide --token-file to load pre-encrypted tokens for routers.")
	}

	// Build gRPC server options
	var serverOpts []grpc.ServerOption

	// Startup flag validation
	allowlist := parseAllowlist(*allowedRouters)
	if len(allowlist) > 0 && (*tlsCert == "" || *tlsKey == "" || *clientCA == "") {
		logger.Error("--allowed-routers requires --tls-cert, --tls-key, and --client-ca to be set (mTLS must be enabled for identity verification)")
		os.Exit(1)
	}

	if *tlsCert != "" && *tlsKey != "" {
		tlsCfg, err := buildTLSConfig(*tlsCert, *tlsKey, *clientCA)
		if err != nil {
			logger.Error("failed to build TLS config", "error", err)
			os.Exit(1)
		}
		serverOpts = append(serverOpts, grpc.Creds(credentials.NewTLS(tlsCfg)))
		logger.Info("TLS enabled for gRPC server",
			"cert", *tlsCert,
			"mtls", *clientCA != "",
		)

		if len(allowlist) > 0 {
			logger.Info("router identity allowlist configured", "identities", allowlist)
		}

		serverOpts = append(serverOpts,
			grpc.UnaryInterceptor(authUnaryInterceptor(logger, allowlist)),
			grpc.StreamInterceptor(authStreamInterceptor(logger, allowlist)),
		)
	} else {
		if !*allowInsecureDev {
			logger.Error("TLS is required by default. Provide --tls-cert and --tls-key, " +
				"or pass --allow-insecure-dev to run without TLS (development only).")
			os.Exit(1)
		}
		logger.Warn("WARNING: gRPC server running WITHOUT TLS — secrets will be transmitted in plaintext. " +
			"This mode is for development only. Set --tls-cert and --tls-key for production use.")
	}

	// In production mode (TLS enabled), enforce that AuthService has tokens loaded.
	// An empty AuthService in production is almost certainly a misconfiguration.
	isTLSEnabled := *tlsCert != "" && *tlsKey != ""
	if isTLSEnabled && authSvc.TokenCount() == 0 {
		logger.Error("AuthService has no tokens loaded in production mode (TLS enabled). " +
			"Provide --token-file with pre-encrypted token entries. " +
			"This prevents runtime failures when routers request tokens.")
		os.Exit(1)
	}

	// Set up gRPC server
	srv := grpc.NewServer(serverOpts...)
	csarv1.RegisterCoordinatorServiceServer(srv, coord)
	csarv1.RegisterAuthServiceServer(srv, authSvc)
	logger.Info("registered gRPC services: CoordinatorService, AuthService")

	lis, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		logger.Error("failed to listen", "error", err)
		os.Exit(1)
	}

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigCh

		logger.Info("received signal, shutting down", "signal", sig)
		srv.GracefulStop()
	}()

	logger.Info(fmt.Sprintf("coordinator listening on %s", *listenAddr))
	if err := srv.Serve(lis); err != nil {
		logger.Error("gRPC server error", "error", err)
		os.Exit(1)
	}
}

// buildTLSConfig creates a TLS configuration for the gRPC server.
// If clientCAFile is non-empty, mTLS is enforced.
func buildTLSConfig(certFile, keyFile, clientCAFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("loading server cert/key: %w", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}

	if clientCAFile != "" {
		caCert, err := os.ReadFile(clientCAFile)
		if err != nil {
			return nil, fmt.Errorf("reading client CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("client CA file contains no valid certificates")
		}
		tlsCfg.ClientCAs = pool
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return tlsCfg, nil
}

// parseAllowlist parses a comma-separated list of allowed router identities.
func parseAllowlist(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// extractPeerIdentity returns the CN and DNS SANs from the peer's TLS certificate.
func extractPeerIdentity(ctx context.Context) (cn string, sans []string, ok bool) {
	p, exists := peer.FromContext(ctx)
	if !exists {
		return "", nil, false
	}

	tlsInfo, isTLS := p.AuthInfo.(credentials.TLSInfo)
	if !isTLS {
		return "", nil, false
	}

	if len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.VerifiedChains[0]) == 0 {
		return "", nil, false
	}

	leaf := tlsInfo.State.VerifiedChains[0][0]
	return leaf.Subject.CommonName, leaf.DNSNames, true
}

// checkIdentity verifies the peer identity against the allowlist.
// If allowlist is empty, any authenticated peer is accepted.
// If allowlist is non-empty and no verified identity is present, access is denied.
func checkIdentity(ctx context.Context, allowlist []string) error {
	cn, sans, ok := extractPeerIdentity(ctx)

	if len(allowlist) == 0 {
		// No allowlist configured — accept any peer (including unauthenticated in dev mode).
		return nil
	}

	// Allowlist is set — verified identity is mandatory.
	if !ok {
		return status.Error(codes.Unauthenticated, "allowlist is configured but no verified client certificate was presented")
	}

	// Check CN and SANs against allowlist
	for _, allowed := range allowlist {
		if cn == allowed {
			return nil
		}
		for _, san := range sans {
			if san == allowed {
				return nil
			}
		}
	}

	return status.Errorf(codes.PermissionDenied, "router identity %q not in allowlist", cn)
}

// authUnaryInterceptor checks peer identity on unary RPCs.
func authUnaryInterceptor(logger *slog.Logger, allowlist []string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if err := checkIdentity(ctx, allowlist); err != nil {
			logger.Warn("rejected unary RPC: identity check failed",
				"method", info.FullMethod,
				"error", err,
			)
			return nil, err
		}
		return handler(ctx, req)
	}
}

// authStreamInterceptor checks peer identity on streaming RPCs.
func authStreamInterceptor(logger *slog.Logger, allowlist []string) grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if err := checkIdentity(ss.Context(), allowlist); err != nil {
			logger.Warn("rejected stream RPC: identity check failed",
				"method", info.FullMethod,
				"error", err,
			)
			return err
		}
		return handler(srv, ss)
	}
}

// coordinatorTokenFileEntry is the on-disk format for pre-encrypted tokens.
type coordinatorTokenFileEntry struct {
	EncryptedToken string `yaml:"encrypted_token"` // base64-encoded
	KMSKeyID       string `yaml:"kms_key_id"`
}

// loadCoordinatorTokenFile reads a YAML file of pre-encrypted token entries.
//
// File format:
//
//	my_api_token:
//	  encrypted_token: "<base64-encoded ciphertext>"
//	  kms_key_id: "key-1"
func loadCoordinatorTokenFile(path string) (map[string]coordinator.TokenEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading token file %s: %w", path, err)
	}

	var raw map[string]coordinatorTokenFileEntry
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing token file %s: %w", path, err)
	}

	if len(raw) == 0 {
		return nil, fmt.Errorf("token file %s contains no entries", path)
	}

	entries := make(map[string]coordinator.TokenEntry, len(raw))
	for ref, e := range raw {
		if e.EncryptedToken == "" {
			return nil, fmt.Errorf("token file: token_ref %q has empty encrypted_token", ref)
		}
		if e.KMSKeyID == "" {
			return nil, fmt.Errorf("token file: token_ref %q has empty kms_key_id", ref)
		}

		decoded, err := base64.StdEncoding.DecodeString(e.EncryptedToken)
		if err != nil {
			return nil, fmt.Errorf("token file: token_ref %q: invalid base64 in encrypted_token: %w", ref, err)
		}

		entries[ref] = coordinator.TokenEntry{
			EncryptedToken: decoded,
			KMSKeyID:       e.KMSKeyID,
		}
	}

	return entries, nil
}
