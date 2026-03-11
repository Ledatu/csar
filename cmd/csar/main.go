package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/ledatu/csar-core/health"
	"github.com/ledatu/csar-core/httpserver"
	"github.com/ledatu/csar-core/tlsx"

	"github.com/ledatu/csar/internal/config"
	"github.com/ledatu/csar/internal/coordclient"
	"github.com/ledatu/csar/internal/kms"
	"github.com/ledatu/csar/internal/logging"
	"github.com/ledatu/csar/internal/metrics"
	"github.com/ledatu/csar/internal/proxy"
	"github.com/ledatu/csar/internal/router"
	"github.com/ledatu/csar/internal/telemetry"
	"github.com/ledatu/csar/internal/throttle"
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
	yandexSAKeyFile := flag.String("yandex-sa-key-file", "", "Service account key file for Yandex KMS")

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
			*yandexKMSEndpoint, *yandexAuthMode, *yandexIAMToken, *yandexOAuthToken, *yandexSAKeyFile)
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

	// Mount readiness endpoint when configured.
	var readinessChecker *health.ReadinessChecker
	if cfg.Readiness != nil && cfg.Readiness.Enabled {
		includeDetails := cfg.Readiness.IncludeDetails == nil || *cfg.Readiness.IncludeDetails
		readinessChecker = health.NewReadinessChecker(Version, includeDetails)
		readinessPath := cfg.Readiness.Path
		if readinessPath == "" {
			readinessPath = "/readiness"
		}
		mux.Handle(readinessPath, readinessChecker.Handler())
		logger.Info("readiness endpoint mounted", "path", readinessPath)
	}

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
		tc, err := tlsx.NewServerTLSConfig(tlsx.ServerConfig{
			CertFile:     cfg.TLS.CertFile,
			KeyFile:      cfg.TLS.KeyFile,
			ClientCAFile: cfg.TLS.ClientCAFile,
			MinVersion:   cfg.TLS.MinVersion,
		})
		if err != nil {
			return fmt.Errorf("TLS config: %w", err)
		}
		srv.TLSConfig = tc
		if cfg.TLS.ClientCAFile != "" {
			logger.Info("mTLS enabled for inbound connections", "client_ca", cfg.TLS.ClientCAFile)
		}
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
		if readinessChecker != nil {
			readinessPath := "/readiness"
			if cfg.Readiness != nil && cfg.Readiness.Path != "" {
				readinessPath = cfg.Readiness.Path
			}
			metricsMux.Handle(readinessPath, readinessChecker.Handler())
		}

		metricsSrv, err := httpserver.New(&httpserver.Config{
			Addr:         *metricsAddr,
			Handler:      metricsMux,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
		}, logger.With("component", "metrics"))
		if err != nil {
			return fmt.Errorf("creating metrics server: %w", err)
		}
		go func() {
			if err := metricsSrv.ListenAndServe(); err != nil {
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
			if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
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
