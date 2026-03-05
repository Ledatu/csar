package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	grpcinsecure "google.golang.org/grpc/credentials/insecure"

	"github.com/ledatu/csar/internal/config"
	"github.com/ledatu/csar/internal/coordclient"
	"github.com/ledatu/csar/internal/kms"
	"github.com/ledatu/csar/internal/logging"
	"github.com/ledatu/csar/internal/metrics"
	"github.com/ledatu/csar/internal/proxy"
	"github.com/ledatu/csar/internal/router"
	"github.com/ledatu/csar/internal/telemetry"
	"github.com/ledatu/csar/internal/throttle"
	"github.com/ledatu/csar/pkg/health"
	"github.com/ledatu/csar/pkg/middleware"
	csarv1 "github.com/ledatu/csar/proto/csar/v1"
)

// Version is set at build time via ldflags.
var Version = "dev"

func main() {
	fmt.Println("CSAR - Coordinated Stateless API Router")
	fmt.Println("========================================")

	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// CLI flags
	configPath := flag.String("config", "config.example.yaml", "path to config file")
	metricsAddr := flag.String("metrics-addr", ":9100", "Prometheus metrics listen address (empty to disable)")
	otlpEndpoint := flag.String("otlp-endpoint", "", "OTLP gRPC endpoint for tracing (empty to disable)")
	otlpInsecure := flag.Bool("otlp-insecure", false, "use insecure connection for OTLP (default: TLS required)")

	// KMS / auth injection flags (required when config has x-csar-security routes)
	kmsProvider := flag.String("kms-provider", "", "KMS provider: \"local\" (dev), \"yandexapi\" (production)")
	kmsLocalKeys := flag.String("kms-local-keys", "", "local KMS key=passphrase pairs (comma-separated, e.g. \"key1=pass1,key2=pass2\")")

	// Yandex KMS flags (used when --kms-provider=yandexapi)
	yandexKMSEndpoint := flag.String("yandex-kms-endpoint", "", "Yandex Cloud KMS API endpoint (default: https://kms.api.cloud.yandex.net/kms/v1/keys)")
	yandexAuthMode := flag.String("yandex-auth-mode", "metadata", "auth mode for Yandex KMS: \"iam_token\", \"oauth_token\", \"metadata\"")
	yandexIAMToken := flag.String("yandex-iam-token", "", "static IAM token for Yandex KMS (dev only)")
	yandexOAuthToken := flag.String("yandex-oauth-token", "", "OAuth token for IAM token exchange (Yandex KMS)")

	// KMS cache flags
	kmsCacheTTL := flag.Duration("kms-cache-ttl", 0, "TTL for KMS decrypt cache (0 to disable, e.g. \"60s\")")

	// Token source flags (one required when secure routes exist)
	tokenFile := flag.String("token-file", "", "path to YAML file with token_ref -> plaintext mappings (local dev)")

	flag.Parse()

	// Structured logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Load configuration
	logger.Info("loading configuration", "path", *configPath)
	cfg, err := config.Load(*configPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// If redact_sensitive_logs is enabled, wrap the logger with a redacting handler
	// that scrubs keys like Authorization, Token, Password, Secret, etc.
	if cfg.SecurityPolicy != nil && cfg.SecurityPolicy.RedactSensitiveLogs {
		jsonHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		})
		logger = slog.New(logging.NewRedactingHandler(jsonHandler))
		logger.Info("sensitive log redaction enabled")
	}

	// --- Telemetry ---
	tp, err := telemetry.Init(context.Background(), telemetry.Config{
		ServiceName:    "csar-router",
		ServiceVersion: Version,
		OTLPEndpoint:   *otlpEndpoint,
		SampleRate:     1.0,
		Insecure:       *otlpInsecure,
	})
	if err != nil {
		return fmt.Errorf("initializing telemetry: %w", err)
	}
	defer tp.Close()

	// --- Metrics ---
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)

	// --- SSRF Protection (audit §2.3.2) ---
	// Build SSRF protection from config or use secure defaults.
	ssrfP := proxy.DefaultSSRFProtection()
	if cfg.SSRF != nil {
		ssrfP.BlockPrivate = cfg.SSRF.IsBlockPrivate()
		ssrfP.BlockLoopback = cfg.SSRF.IsBlockLoopback()
		ssrfP.BlockLinkLocal = cfg.SSRF.IsBlockLinkLocal()
		ssrfP.BlockMetadata = cfg.SSRF.IsBlockMetadata()
		for _, host := range cfg.SSRF.AllowedInternalHosts {
			ssrfP.AllowedHosts[host] = true
		}
	}
	logger.Info("SSRF protection enabled",
		"block_private", ssrfP.BlockPrivate,
		"block_loopback", ssrfP.BlockLoopback,
		"block_link_local", ssrfP.BlockLinkLocal,
		"block_metadata", ssrfP.BlockMetadata,
		"allowed_hosts", len(ssrfP.AllowedHosts),
	)

	// --- Shared ThrottleManager (audit: survives SIGHUP reload) ---
	// Create a single ThrottleManager that lives across router rebuilds.
	// The coordinator client holds a reference to this manager, so quota
	// updates continue to apply after SIGHUP-triggered router replacements.
	sharedTM := throttle.NewManager()

	// --- Auth Injection (KMS + Token Fetcher) ---
	var routerOpts []router.Option
	routerOpts = append(routerOpts, router.WithMetrics(m), router.WithTelemetry(tp), router.WithSSRFProtection(ssrfP), router.WithThrottleManager(sharedTM))

	// --- Redis client for distributed throttling ---
	if cfg.Redis != nil && cfg.Redis.Address != "" {
		redisClient := throttle.NewRedisClient(throttle.RedisConfig{
			Address:   cfg.Redis.Address,
			Password:  cfg.Redis.Password.Plaintext(),
			DB:        cfg.Redis.DB,
			KeyPrefix: cfg.Redis.KeyPrefix,
		})
		defer redisClient.Close()
		routerOpts = append(routerOpts, router.WithRedisClient(redisClient))
		logger.Info("Redis client for distributed throttling configured",
			"address", cfg.Redis.Address,
			"db", cfg.Redis.DB,
		)
	}

	if cfg.HasSecureRoutes() {
		// Resolve KMS provider: CLI flag takes precedence, then config.
		providerName := *kmsProvider
		if providerName == "" && cfg.KMS != nil && cfg.KMS.Provider != "" {
			providerName = cfg.KMS.Provider
		}
		if providerName == "" {
			return fmt.Errorf("configuration contains x-csar-security routes but no --kms-provider is set; " +
				"use --kms-provider=local for development or --kms-provider=yandexapi for production")
		}

		// Enforce profile KMS rules against the *resolved* provider, not just the
		// config-declared value. This prevents bypassing prod profile guardrails
		// via --kms-provider=local when kms.provider is unset in YAML.
		if err := cfg.ValidateResolvedKMSProvider(providerName); err != nil {
			return err
		}

		kmsP, err := initKMSProvider(providerName, *kmsLocalKeys, cfg,
			*yandexKMSEndpoint, *yandexAuthMode, *yandexIAMToken, *yandexOAuthToken)
		if err != nil {
			return fmt.Errorf("initializing KMS provider: %w", err)
		}
		defer kmsP.Close()

		// Wrap with caching if configured.
		cacheTTL := *kmsCacheTTL
		cacheMaxEntries := 0
		if cacheTTL == 0 && cfg.KMS != nil && cfg.KMS.Cache != nil && cfg.KMS.Cache.Enabled {
			cacheTTL = cfg.KMS.Cache.TTL.Duration
			cacheMaxEntries = cfg.KMS.Cache.MaxEntries
		}
		if cfg.KMS != nil && cfg.KMS.Cache != nil && cfg.KMS.Cache.MaxEntries > 0 && cacheMaxEntries == 0 {
			cacheMaxEntries = cfg.KMS.Cache.MaxEntries
		}
		if cacheTTL > 0 {
			kmsP = kms.NewCachingProvider(kmsP, cacheTTL, cacheMaxEntries)
			logger.Info("KMS decrypt cache enabled", "ttl", cacheTTL, "max_entries", cacheMaxEntries)
		}

		// Resolve the token source.
		// Priority: --token-file (local dev) > coordinator gRPC (production).
		var fetcher middleware.TokenFetcher

		switch {
		case *tokenFile != "":
			// Local dev: load plaintext tokens from YAML file, encrypt at startup.
			fileFetcher, err := middleware.LoadTokenFile(*tokenFile, kmsP)
			if err != nil {
				return fmt.Errorf("loading token file: %w", err)
			}
			fetcher = fileFetcher
			logger.Info("token source: file", "path", *tokenFile)

		case cfg.Coordinator.Enabled && cfg.Coordinator.Address != "":
			// Production: use coordinator gRPC AuthService with TLS.
			// The coordinator manages the token store (PostgreSQL, file, etc.)
			// and pushes invalidation events to all routers.
			conn, err := dialCoordinator(cfg.Coordinator, logger)
			if err != nil {
				return fmt.Errorf("connecting to coordinator: %w", err)
			}
			defer conn.Close()
			authClient := csarv1.NewAuthServiceClient(conn)
			fetcher = middleware.NewCoordinatorTokenFetcher(authClient)
			logger.Info("token source: coordinator gRPC", "address", cfg.Coordinator.Address)

		default:
			return fmt.Errorf("secure routes require a token source: " +
				"use --token-file for local dev, or enable coordinator with an address for production")
		}

		injector := middleware.NewAuthInjector(fetcher, kmsP, logger)
		routerOpts = append(routerOpts, router.WithAuthInjector(injector))

		logger.Info("auth injection enabled",
			"kms_provider", providerName,
		)
	}

	// Create the router with metrics, telemetry, and optional auth injector
	r, err := router.New(cfg, logger, routerOpts...)
	if err != nil {
		return fmt.Errorf("creating router: %w", err)
	}

	// Wrap the router in a reloadable handler so SIGHUP can swap it atomically
	// without dropping active connections (audit §3.1: dynamic live-reloading).
	rh := newReloadableHandler(tp.HTTPMiddleware("csar", r))

	// Build the HTTP mux
	mux := http.NewServeMux()
	mux.Handle("/health", health.Handler(Version))
	mux.Handle("/", rh)

	// Create HTTP server
	srv := &http.Server{
		Addr:           cfg.ListenAddr,
		Handler:        mux,
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   60 * time.Second,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1 MB
	}

	// Configure inbound TLS if specified
	if cfg.TLS != nil {
		tlsCfg := &tls.Config{
			MinVersion: tls.VersionTLS12,
		}

		// Set minimum TLS version
		if cfg.TLS.MinVersion == "1.3" {
			tlsCfg.MinVersion = tls.VersionTLS13
		}

		// Mutual TLS: require and verify client certificates
		if cfg.TLS.ClientCAFile != "" {
			caCert, err := os.ReadFile(cfg.TLS.ClientCAFile)
			if err != nil {
				return fmt.Errorf("reading client CA file: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(caCert) {
				return fmt.Errorf("client CA file contains no valid certificates")
			}
			tlsCfg.ClientCAs = pool
			tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
			logger.Info("mTLS enabled for inbound connections", "client_ca", cfg.TLS.ClientCAFile)
		}

		srv.TLSConfig = tlsCfg
	}

	// Log security warnings from config validation
	for _, w := range cfg.Warnings {
		logger.Warn(w)
	}

	// Start metrics server if configured
	if *metricsAddr != "" {
		metricsMux := http.NewServeMux()
		metricsMux.Handle("/metrics", m.Handler())
		metricsMux.Handle("/health", health.Handler(Version))

		metricsSrv := &http.Server{
			Addr:           *metricsAddr,
			Handler:        metricsMux,
			ReadTimeout:    10 * time.Second,
			WriteTimeout:   10 * time.Second,
			IdleTimeout:    60 * time.Second,
			MaxHeaderBytes: 1 << 20, // 1 MB
		}
		go func() {
			logger.Info("starting metrics server", "addr", *metricsAddr)
			if err := metricsSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Error("metrics server error", "error", err)
			}
		}()
	}

	// Graceful shutdown context
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// --- Coordinator subscription (distributed quota + token invalidation) ---
	// When the coordinator is enabled, start a background subscription client
	// that receives quota assignments and token invalidation events.
	if cfg.Coordinator.Enabled && cfg.Coordinator.Address != "" {
		conn, err := dialCoordinator(cfg.Coordinator, logger)
		if err != nil {
			logger.Warn("failed to connect to coordinator for quota subscription — continuing without distributed rate limiting",
				"error", err,
			)
		} else {
			coordSvcClient := csarv1.NewCoordinatorServiceClient(conn)
			hostname, _ := os.Hostname()
			var ccOpts []coordclient.Option
			if r.AuthInjector() != nil {
				ccOpts = append(ccOpts, coordclient.WithAuthInjector(r.AuthInjector()))
			}
		cc := coordclient.New(
			coordSvcClient,
			hostname,
			cfg.ListenAddr,
			sharedTM,
			logger.With("component", "coordclient"),
			ccOpts...,
		)
			go cc.Run(ctx)
			logger.Info("coordinator subscription client started",
				"router_id", hostname,
				"coordinator_address", cfg.Coordinator.Address,
			)
		}
	}

	// Snapshot restart-required fields for reload-awareness.
	restartSnapshot := snapshotRestartRequiredFields(cfg)

	// Log startup summary.
	logStartupSummary(logger, cfg, r)

	// SIGHUP listener for config hot-reload (audit §3.1).
	// Reloads paths, access control, circuit breakers, and retry policies
	// without dropping active HTTP connections.
	sighupCh := make(chan os.Signal, 1)
	signal.Notify(sighupCh, syscall.SIGHUP)
	// currentRouter tracks the active router so we can close it on reload.
	currentRouter := r
	go func() {
		for range sighupCh {
			logger.Info("SIGHUP received — reloading configuration", "path", *configPath)
			newCfg, err := config.Load(*configPath)
			if err != nil {
				logger.Error("config reload failed — keeping current config", "error", err)
				continue
			}
			// Log any new warnings.
			for _, w := range newCfg.Warnings {
				logger.Warn("(reload) " + w)
			}

			// Check for restart-required field changes.
			checkRestartRequiredChanges(logger, restartSnapshot, newCfg)

			// Rebuild the router with the same options (metrics, telemetry, auth injector).
			newRouter, err := router.New(newCfg, logger, routerOpts...)
			if err != nil {
				logger.Error("router rebuild failed — keeping current router", "error", err)
				continue
			}
			// Atomically swap the handler — in-flight requests finish on the old router.
			rh.swap(tp.HTTPMiddleware("csar", newRouter))

			// Stop health-check goroutines on the old router to prevent leaks.
			// The new router starts its own health checks during construction.
			currentRouter.Close()
			currentRouter = newRouter

			// Prune stale throttle keys from the shared manager.
			pruned := sharedTM.SyncKeys(newRouter.RegisteredKeys())
			if pruned > 0 {
				logger.Info("pruned stale throttle keys after reload",
					"pruned", pruned,
				)
			}

			logger.Info("configuration reloaded successfully",
				"routes", len(newCfg.Paths),
			)
		}
	}()

	// Start the server in a goroutine
	errCh := make(chan error, 1)
	go func() {
		if cfg.TLS != nil {
			logger.Info("starting HTTPS server", "addr", cfg.ListenAddr, "version", Version)
			if err := srv.ListenAndServeTLS(cfg.TLS.CertFile, cfg.TLS.KeyFile); err != nil && err != http.ErrServerClosed {
				errCh <- err
			}
		} else {
			logger.Info("starting HTTP server", "addr", cfg.ListenAddr, "version", Version)
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				errCh <- err
			}
		}
		close(errCh)
	}()

	// Wait for shutdown signal or server error
	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received, draining connections...")
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("server error: %w", err)
		}
	}

	// Graceful shutdown with timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("graceful shutdown failed: %w", err)
	}

	logger.Info("server stopped gracefully")
	return nil
}

// initKMSProvider creates a KMS provider based on the resolved provider name.
func initKMSProvider(provider, localKeys string, cfg *config.Config,
	yandexEndpoint, yandexAuthMode, yandexIAMToken, yandexOAuthToken string,
) (kms.Provider, error) {
	switch provider {
	case "local":
		keys := localKeys
		if keys == "" && cfg.KMS != nil && len(cfg.KMS.LocalKeys) > 0 {
			return kms.NewLocalProvider(cfg.KMS.LocalKeys)
		}
		if keys == "" {
			return nil, fmt.Errorf("--kms-local-keys is required when --kms-provider=local " +
				"(format: \"keyID1=passphrase1,keyID2=passphrase2\")")
		}
		passphrases, err := parseLocalKeys(keys)
		if err != nil {
			return nil, err
		}
		return kms.NewLocalProvider(passphrases)

	case "yandexapi":
		yCfg := kms.YandexAPIConfig{
			Endpoint:   yandexEndpoint,
			AuthMode:   yandexAuthMode,
			IAMToken:   logging.NewSecret(yandexIAMToken),
			OAuthToken: logging.NewSecret(yandexOAuthToken),
		}
		// Merge with YAML config if present.
		if cfg.KMS != nil && cfg.KMS.Yandex != nil {
			y := cfg.KMS.Yandex
			if yCfg.Endpoint == "" {
				yCfg.Endpoint = y.Endpoint
			}
			if yCfg.AuthMode == "metadata" && y.AuthMode != "" {
				yCfg.AuthMode = y.AuthMode
			}
			if yCfg.IAMToken.IsEmpty() {
				yCfg.IAMToken = y.IAMToken
			}
			if yCfg.OAuthToken.IsEmpty() {
				yCfg.OAuthToken = y.OAuthToken
			}
		}
		if cfg.KMS != nil && cfg.KMS.OperationTimeout.Duration > 0 {
			yCfg.Timeout = cfg.KMS.OperationTimeout.Duration
		}
		return kms.NewYandexAPIProvider(yCfg)

	case "yandex":
		return nil, fmt.Errorf("--kms-provider=yandex is deprecated; use --kms-provider=yandexapi instead")

	default:
		return nil, fmt.Errorf("unknown KMS provider %q; supported: \"local\", \"yandexapi\"", provider)
	}
}

// dialCoordinator creates a gRPC client connection to the coordinator.
// It enforces TLS by default — plaintext requires explicit allow_insecure: true.
func dialCoordinator(coordCfg config.CoordinatorConfig, logger *slog.Logger) (*grpc.ClientConn, error) {
	var dialOpt grpc.DialOption

	switch {
	case coordCfg.CAFile != "":
		// TLS (or mTLS) to the coordinator.
		caCert, err := os.ReadFile(coordCfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("reading coordinator CA file %s: %w", coordCfg.CAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("coordinator CA file %s contains no valid certificates", coordCfg.CAFile)
		}

		tlsCfg := &tls.Config{
			RootCAs:    pool,
			MinVersion: tls.VersionTLS13,
		}

		// If client cert+key are provided, enable mTLS.
		if coordCfg.CertFile != "" && coordCfg.KeyFile != "" {
			clientCert, err := tls.LoadX509KeyPair(coordCfg.CertFile, coordCfg.KeyFile)
			if err != nil {
				return nil, fmt.Errorf("loading coordinator client cert/key: %w", err)
			}
			tlsCfg.Certificates = []tls.Certificate{clientCert}
			logger.Info("coordinator gRPC: mTLS enabled",
				"ca", coordCfg.CAFile,
				"cert", coordCfg.CertFile,
			)
		} else {
			logger.Info("coordinator gRPC: TLS enabled (server-auth only)",
				"ca", coordCfg.CAFile,
			)
		}

		dialOpt = grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg))

	case coordCfg.AllowInsecure:
		// Explicit dev-mode opt-in for plaintext.
		logger.Warn("WARNING: coordinator gRPC connection is INSECURE (plaintext). " +
			"Set coordinator.ca_file for production use.")
		dialOpt = grpc.WithTransportCredentials(grpcinsecure.NewCredentials())

	default:
		return nil, fmt.Errorf("coordinator.ca_file is required for secure gRPC transport; " +
			"set coordinator.allow_insecure: true only for local development")
	}

	conn, err := grpc.NewClient(coordCfg.Address, dialOpt)
	if err != nil {
		return nil, fmt.Errorf("dialing coordinator at %s: %w", coordCfg.Address, err)
	}
	return conn, nil
}

// reloadableHandler wraps an http.Handler with an atomic pointer so it can be
// swapped at runtime (on SIGHUP) without dropping in-flight connections.
type reloadableHandler struct {
	handler atomic.Pointer[http.Handler]
}

// newReloadableHandler creates a reloadableHandler with the given initial handler.
func newReloadableHandler(h http.Handler) *reloadableHandler {
	rh := &reloadableHandler{}
	rh.handler.Store(&h)
	return rh
}

// ServeHTTP delegates to the current handler.
func (rh *reloadableHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	(*rh.handler.Load()).ServeHTTP(w, r)
}

// swap atomically replaces the current handler.
func (rh *reloadableHandler) swap(h http.Handler) {
	rh.handler.Store(&h)
}

// parseLocalKeys parses "key1=pass1,key2=pass2" into a map.
func parseLocalKeys(raw string) (map[string]string, error) {
	result := make(map[string]string)
	for _, pair := range strings.Split(raw, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return nil, fmt.Errorf("invalid key=passphrase pair: %q (expected format: keyID=passphrase)", pair)
		}
		result[parts[0]] = parts[1]
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("no valid key=passphrase pairs found in %q", raw)
	}
	return result, nil
}

// ---------------------------------------------------------------------------
// Restart-required field detection (reload-awareness)
// ---------------------------------------------------------------------------

// restartRequiredSnapshot captures config field values that cannot be changed
// at runtime and require a full process restart.
type restartRequiredSnapshot struct {
	ListenAddr   string
	KMSProvider  string
	TLSCertFile  string
	TLSKeyFile   string
	Profile      string
}

// snapshotRestartRequiredFields takes a snapshot of fields that need a restart
// to take effect. Compare with the new config on SIGHUP.
func snapshotRestartRequiredFields(cfg *config.Config) restartRequiredSnapshot {
	snap := restartRequiredSnapshot{
		ListenAddr: cfg.ListenAddr,
		Profile:    cfg.Profile,
	}
	if cfg.KMS != nil {
		snap.KMSProvider = cfg.KMS.Provider
	}
	if cfg.TLS != nil {
		snap.TLSCertFile = cfg.TLS.CertFile
		snap.TLSKeyFile = cfg.TLS.KeyFile
	}
	return snap
}

// checkRestartRequiredChanges compares the snapshot with the new config and
// logs warnings for fields that changed but require a restart to take effect.
func checkRestartRequiredChanges(logger *slog.Logger, snap restartRequiredSnapshot, newCfg *config.Config) {
	if newCfg.ListenAddr != snap.ListenAddr {
		logger.Warn("field 'listen_addr' changed but requires restart to take effect",
			"old", snap.ListenAddr, "new", newCfg.ListenAddr)
	}
	if newCfg.Profile != snap.Profile {
		logger.Warn("field 'profile' changed but requires restart to take effect",
			"old", snap.Profile, "new", newCfg.Profile)
	}

	newKMS := ""
	if newCfg.KMS != nil {
		newKMS = newCfg.KMS.Provider
	}
	if newKMS != snap.KMSProvider {
		logger.Warn("field 'kms.provider' changed but requires restart to take effect",
			"old", snap.KMSProvider, "new", newKMS)
	}

	newCert, newKey := "", ""
	if newCfg.TLS != nil {
		newCert = newCfg.TLS.CertFile
		newKey = newCfg.TLS.KeyFile
	}
	if newCert != snap.TLSCertFile || newKey != snap.TLSKeyFile {
		logger.Warn("TLS certificate paths changed but require restart to take effect",
			"old_cert", snap.TLSCertFile, "new_cert", newCert)
	}
}

// ---------------------------------------------------------------------------
// Startup summary log
// ---------------------------------------------------------------------------

// logStartupSummary prints a structured summary of the CSAR configuration at startup.
func logStartupSummary(logger *slog.Logger, cfg *config.Config, r *router.Router) {
	profile := cfg.Profile
	if profile == "" {
		profile = "(none)"
	}

	tlsStatus := "disabled"
	if cfg.TLS != nil {
		minVer := "TLS 1.2"
		if cfg.TLS.MinVersion == "1.3" {
			minVer = "TLS 1.3"
		}
		tlsStatus = fmt.Sprintf("enabled (%s)", minVer)
	}

	kmsProvider := "(none)"
	if cfg.KMS != nil && cfg.KMS.Provider != "" {
		kmsProvider = cfg.KMS.Provider
	}

	tokenSource := "file"
	if cfg.Coordinator.Enabled && cfg.Coordinator.Address != "" {
		tokenSource = "coordinator"
	}

	coordStatus := "disabled"
	if cfg.Coordinator.Enabled {
		transport := "plaintext"
		if cfg.Coordinator.CAFile != "" {
			transport = "mTLS"
		}
		coordStatus = fmt.Sprintf("enabled (grpc://%s, %s)", cfg.Coordinator.Address, transport)
	}

	// Count routes with security and throttle
	totalRoutes := 0
	secureRoutes := 0
	throttledRoutes := 0
	for _, pathCfg := range cfg.Paths {
		for _, routeCfg := range pathCfg {
			totalRoutes++
			if len(routeCfg.Security) > 0 {
				secureRoutes++
			}
			if routeCfg.Traffic != nil {
				throttledRoutes++
			}
		}
	}

	_ = r // router reference for future use

	logger.Info("csar startup summary",
		"profile", profile,
		"listen", cfg.ListenAddr,
		"tls", tlsStatus,
		"kms_provider", kmsProvider,
		"token_source", tokenSource,
		"coordinator", coordStatus,
		"routes", fmt.Sprintf("%d (%d with security, %d with throttle)", totalRoutes, secureRoutes, throttledRoutes),
	)
}
