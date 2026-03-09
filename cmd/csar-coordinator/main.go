package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	// PostgreSQL driver — imported for side-effect registration with database/sql.
	_ "github.com/lib/pq"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"gopkg.in/yaml.v3"

	"github.com/Ledatu/csar-core/s3store"
	"github.com/Ledatu/csar-core/ycloud"

	"github.com/ledatu/csar/internal/configsource"
	"github.com/ledatu/csar/internal/coordinator"
	"github.com/ledatu/csar/internal/kms"
	"github.com/ledatu/csar/internal/logging"
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

	// Token source flags — choose one: --token-file (dev), --token-source=postgres, or --token-source=s3.
	tokenFile := flag.String("token-file", "", "path to YAML file with pre-encrypted token entries for AuthService")
	tokenSourceFlag := flag.String("token-source", "", "token backend: \"file\" (default, uses --token-file), \"postgres\", \"s3\"")

	// PostgreSQL flags (used when --token-source=postgres)
	postgresDSN := flag.String("postgres-dsn", "", "PostgreSQL connection string (e.g. \"postgres://user:pass@host:5432/db?sslmode=require\")")
	postgresMaxConns := flag.Int("postgres-max-conns", 10, "max open database connections")
	postgresRefreshInterval := flag.Duration("postgres-refresh-interval", 30*time.Second, "how often to poll PostgreSQL for token changes (e.g. \"30s\")")

	// S3 flags (used when --token-source=s3)
	s3Bucket := flag.String("s3-bucket", "", "S3 bucket name for token storage")
	s3Endpoint := flag.String("s3-endpoint", "https://storage.yandexcloud.net", "S3-compatible endpoint URL")
	s3Region := flag.String("s3-region", "ru-central1", "S3 region for signing")
	s3Prefix := flag.String("s3-prefix", "tokens/", "S3 key prefix for token objects")
	s3AuthMode := flag.String("s3-auth-mode", "static", "S3 auth mode: static, iam_token, oauth_token, metadata, service_account")
	s3AccessKeyID := flag.String("s3-access-key-id", "", "S3 access key ID (static auth)")
	s3SecretAccessKey := flag.String("s3-secret-access-key", "", "S3 secret access key (static auth)")
	s3IAMToken := flag.String("s3-iam-token", "", "IAM token for S3 (iam_token auth)")
	s3OAuthToken := flag.String("s3-oauth-token", "", "OAuth token for S3 IAM exchange (oauth_token auth)")
	s3SAKeyFile := flag.String("s3-sa-key-file", "", "Service account key JSON file for S3 (service_account auth)")
	s3KMSMode := flag.String("s3-kms-mode", "kms", "S3 KMS mode: passthrough (SSE only), kms (CSAR KMS encrypted)")

	// State store flags
	storeType := flag.String("store", "memory", "state store backend: memory, etcd")
	etcdEndpoints := flag.String("etcd-endpoints", "localhost:2379", "comma-separated etcd endpoints")
	etcdPrefix := flag.String("etcd-prefix", "/csar", "etcd key prefix")
	etcdRouterTTL := flag.Int64("etcd-router-ttl", 30, "etcd lease TTL in seconds for router entries")

	// Config source flags — load route configuration from file, S3, or HTTP.
	configSource := flag.String("config-source", "", "config source: file, s3, http (empty = no config loading)")
	configRefreshInterval := flag.Duration("config-refresh-interval", 60*time.Second, "config source polling interval")
	configSHA256 := flag.String("config-sha256", "", "expected SHA-256 hash of config (hex); empty = TOFU mode")

	// Config source: file
	configFile := flag.String("config-file", "", "path to YAML config file (config-source=file)")

	// Config source: HTTP
	configURL := flag.String("config-url", "", "URL to fetch config from (config-source=http)")
	configHTTPHeader := flag.String("config-http-header", "", "extra HTTP headers for config fetch (key=value, comma-separated)")
	configHTTPBearer := flag.String("config-http-bearer", "", "bearer token for HTTP config source")

	// Config source: S3 (prefixed with config-s3- to avoid conflict with token S3 flags)
	configS3Bucket := flag.String("config-s3-bucket", "", "S3 bucket for config (config-source=s3)")
	configS3Key := flag.String("config-s3-key", "config.yaml", "S3 object key for config")
	configS3Endpoint := flag.String("config-s3-endpoint", "https://storage.yandexcloud.net", "S3 endpoint for config")
	configS3Region := flag.String("config-s3-region", "ru-central1", "S3 region for config")
	configS3AuthMode := flag.String("config-s3-auth-mode", "static", "S3 auth mode for config: static, iam_token, oauth_token, metadata, service_account")
	configS3AccessKeyID := flag.String("config-s3-access-key-id", "", "S3 access key ID for config (static auth)")
	configS3SecretAccessKey := flag.String("config-s3-secret-access-key", "", "S3 secret access key for config (static auth)")
	configS3IAMToken := flag.String("config-s3-iam-token", "", "IAM token for config S3 (iam_token auth)")
	configS3OAuthToken := flag.String("config-s3-oauth-token", "", "OAuth token for config S3 (oauth_token auth)")
	configS3SAKeyFile := flag.String("config-s3-sa-key-file", "", "SA key JSON file for config S3 (service_account auth)")

	// Admin API flags
	adminEnabled := flag.Bool("admin-enabled", false, "enable the admin HTTP API for token lifecycle management")
	adminListen := flag.String("admin-listen", ":9443", "admin API listen address")
	adminTLSCert := flag.String("admin-tls-cert", "", "path to TLS cert for admin API (PEM)")
	adminTLSKey := flag.String("admin-tls-key", "", "path to TLS key for admin API (PEM)")
	adminClientCA := flag.String("admin-client-ca", "", "path to client CA for admin API mTLS (PEM)")
	adminJWKSUrl := flag.String("admin-jwks-url", "", "JWKS URL for admin JWT validation (from csar-auth)")
	adminIssuer := flag.String("admin-issuer", "", "expected JWT issuer for admin API")
	adminAudience := flag.String("admin-audience", "csar-coordinator-admin", "expected JWT audience for admin API")
	adminS3ManagesEncryptionStr := flag.String("admin-s3-manages-encryption", "", "REQUIRED: 'true' = S3 SSE handles encryption, 'false' = CSAR KMS encrypts before S3 write")
	adminMaxTokenSize := flag.Int64("admin-max-token-size", 16384, "maximum token value size in bytes")
	adminRequestTimeout := flag.Duration("admin-request-timeout", 5*time.Second, "per-request timeout for admin API")
	adminEnforceTokenPrefix := flag.Bool("admin-enforce-token-prefix", true, "enforce token_prefix claim in JWT for namespace RBAC")
	adminEnforceAllowedKMSKeys := flag.Bool("admin-enforce-allowed-kms-keys", true, "enforce allowed_kms_keys claim in JWT")
	adminAllowedKMSKeys := flag.String("admin-allowed-kms-keys", "", "server-side allowed KMS key IDs (comma-separated)")
	adminAllowInsecure := flag.Bool("admin-allow-insecure", false, "allow admin API to start without TLS (local development only)")

	// KMS flags for coordinator (used when admin API encrypts tokens)
	adminKMSProvider := flag.String("admin-kms-provider", "local", "KMS provider for admin API encryption: local, yandexapi")
	adminKMSLocalKeys := flag.String("admin-kms-local-keys", "", "local KMS keys (keyID=passphrase,keyID2=passphrase2)")
	adminKMSYandexEndpoint := flag.String("admin-kms-yandex-endpoint", "", "Yandex KMS API endpoint")
	adminKMSYandexAuthMode := flag.String("admin-kms-yandex-auth-mode", "metadata", "Yandex KMS auth mode")
	adminKMSYandexIAMToken := flag.String("admin-kms-yandex-iam-token", "", "Yandex KMS IAM token")
	adminKMSYandexOAuthToken := flag.String("admin-kms-yandex-oauth-token", "", "Yandex KMS OAuth token")
	adminKMSYandexSAKeyFile := flag.String("admin-kms-yandex-sa-key-file", "", "Yandex KMS service account key file")

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

	// Initialize config source watcher (loads route configuration into StateStore).
	var configWatcher *configsource.ConfigWatcher
	if *configSource != "" {
		var src configsource.ConfigSource
		switch *configSource {
		case "file":
			if *configFile == "" {
				logger.Error("--config-source=file requires --config-file")
				os.Exit(1)
			}
			src = configsource.NewFileSource(*configFile)
			logger.Info("config source: file", "path", *configFile)

		case "s3":
			if *configS3Bucket == "" {
				logger.Error("--config-source=s3 requires --config-s3-bucket")
				os.Exit(1)
			}
			cfgS3Client, err := s3store.NewClient(s3store.Config{
				Bucket:   *configS3Bucket,
				Endpoint: *configS3Endpoint,
				Region:   *configS3Region,
				Prefix:   "", // S3Source uses full key, not prefix
				Auth: ycloud.AuthConfig{
					AuthMode:        *configS3AuthMode,
					IAMToken:        logging.NewSecret(*configS3IAMToken),
					OAuthToken:      logging.NewSecret(*configS3OAuthToken),
					SAKeyFile:       *configS3SAKeyFile,
					AccessKeyID:     logging.NewSecret(*configS3AccessKeyID),
					SecretAccessKey: logging.NewSecret(*configS3SecretAccessKey),
				},
			}, logger)
			if err != nil {
				logger.Error("failed to create config S3 client", "error", err)
				os.Exit(1)
			}
			src = configsource.NewS3Source(cfgS3Client, *configS3Key)
			logger.Info("config source: s3", "bucket", *configS3Bucket, "key", *configS3Key)

		case "http":
			if *configURL == "" {
				logger.Error("--config-source=http requires --config-url")
				os.Exit(1)
			}
			headers := parseConfigHTTPHeaders(*configHTTPHeader, *configHTTPBearer)
			src = configsource.NewHTTPSource(*configURL, headers, nil)
			logger.Info("config source: http", "url", *configURL)

		default:
			logger.Error("unknown --config-source value; supported: \"file\", \"s3\", \"http\"",
				"config_source", *configSource,
			)
			os.Exit(1)
		}

		var opts []configsource.WatcherOption
		if *configSHA256 != "" {
			opts = append(opts,
				configsource.WithHashPolicy(configsource.HashPinned),
				configsource.WithPinnedHash(*configSHA256),
			)
			logger.Info("config hash policy: pinned", "sha256", *configSHA256)
		} else {
			opts = append(opts, configsource.WithHashPolicy(configsource.HashTOFU))
			logger.Info("config hash policy: TOFU (Trust On First Use)")
		}

		configWatcher = configsource.NewConfigWatcher(
			src, store,
			logger.With("component", "config_watcher"),
			opts...,
		)

		// Initial config load — fatal on failure.
		initCtx, initCancel := context.WithTimeout(context.Background(), 30*time.Second)
		if _, err := configWatcher.Apply(initCtx); err != nil {
			initCancel()
			logger.Error("initial config load failed", "error", err)
			os.Exit(1)
		}
		initCancel()
		logger.Info("initial config loaded from source")
	}

	// Create coordinator
	coord := coordinator.New(store, logger)

	// Create AuthService for token delivery to routers
	authSvc := coordinator.NewAuthService(logger)

	// Resolve token source: explicit flag > auto-detect from other flags.
	resolvedTokenSource := *tokenSourceFlag
	if resolvedTokenSource == "" {
		switch {
		case *postgresDSN != "":
			resolvedTokenSource = "postgres"
		case *s3Bucket != "":
			resolvedTokenSource = "s3"
		case *tokenFile != "":
			resolvedTokenSource = "file"
		}
	}

	// tokenStore + refresher are kept in scope so we can start the refresh
	// loop after the gRPC server is set up (it needs the coordinator
	// reference for invalidation broadcasts).
	var tokenStore coordinator.TokenStore
	var refresher *coordinator.TokenRefresher
	var refreshInterval time.Duration

	switch resolvedTokenSource {
	case "postgres":
		if *postgresDSN == "" {
			logger.Error("--token-source=postgres requires --postgres-dsn")
			os.Exit(1)
		}
		db, err := sql.Open("postgres", *postgresDSN)
		if err != nil {
			logger.Error("failed to open postgres connection", "error", err)
			os.Exit(1)
		}
		db.SetMaxOpenConns(*postgresMaxConns)
		db.SetMaxIdleConns(*postgresMaxConns / 2)
		db.SetConnMaxLifetime(5 * time.Minute)

		// Verify connectivity.
		pingCtx, pingCancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := db.PingContext(pingCtx); err != nil {
			pingCancel()
			db.Close()
			logger.Error("postgres ping failed", "error", err)
			os.Exit(1)
		}
		pingCancel()

		pgStore := coordinator.NewPostgresTokenStore(db, logger)
		tokenStore = pgStore

		// Initial load.
		entries, err := pgStore.LoadAll(context.Background())
		if err != nil {
			logger.Error("failed to load tokens from token store", "error", err)
			os.Exit(1)
		}
		loaded := authSvc.LoadTokensFromMap(entries)
		logger.Info("loaded tokens from token store into AuthService",
			"backend", "postgres",
			"count", loaded,
			"refresh_interval", *postgresRefreshInterval,
		)

		// Enable read-through: on cache miss the AuthService queries the
		// store directly instead of returning NotFound. Critical when the
		// polling interval is long (e.g. 4h) and new tokens appear between
		// polls.
		authSvc.SetBackend(tokenStore)

		// Set up the backend-agnostic refresher.
		refresher = coordinator.NewTokenRefresher(tokenStore, logger.With("component", "token_refresher"))
		refresher.SeedVersions(entries)
		refreshInterval = *postgresRefreshInterval

	case "s3":
		if *s3Bucket == "" {
			logger.Error("--token-source=s3 requires --s3-bucket")
			os.Exit(1)
		}

		s3Client, err := s3store.NewClient(s3store.Config{
			Bucket:   *s3Bucket,
			Endpoint: *s3Endpoint,
			Region:   *s3Region,
			Prefix:   *s3Prefix,
			Auth: ycloud.AuthConfig{
				AuthMode:        *s3AuthMode,
				IAMToken:        logging.NewSecret(*s3IAMToken),
				OAuthToken:      logging.NewSecret(*s3OAuthToken),
				SAKeyFile:       *s3SAKeyFile,
				AccessKeyID:     logging.NewSecret(*s3AccessKeyID),
				SecretAccessKey: logging.NewSecret(*s3SecretAccessKey),
			},
		}, logger)
		if err != nil {
			logger.Error("failed to create S3 client", "error", err)
			os.Exit(1)
		}

		s3Store := coordinator.NewS3TokenStore(s3Client, *s3KMSMode, logger)
		tokenStore = s3Store

		// S3 backend uses on-demand fetching: no initial LoadAll, no periodic
		// refresh loop. Tokens are fetched individually via FetchOne when
		// first requested through the AuthService read-through path.
		// This avoids S3 ListObjects calls entirely, preventing silent data
		// truncation and eliminating unnecessary bulk fetches.
		authSvc.SetBackend(tokenStore)

		logger.Info("S3 token store configured (on-demand mode — no listing)",
			"bucket", *s3Bucket,
			"prefix", *s3Prefix,
			"kms_mode", *s3KMSMode,
		)

	case "file", "":
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
			logger.Warn("WARNING: no token source configured — AuthService has no tokens loaded. " +
				"All GetEncryptedToken RPCs will return NotFound. " +
				"Use --token-source=postgres with --postgres-dsn, --token-source=s3 with --s3-bucket, or --token-file to load pre-encrypted tokens.")
		}

	default:
		logger.Error("unknown --token-source value; supported: \"file\", \"postgres\", \"s3\"",
			"token_source", resolvedTokenSource,
		)
		os.Exit(1)
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
			grpc.UnaryInterceptor(authUnaryInterceptor(logger, allowlist, true)),
			grpc.StreamInterceptor(authStreamInterceptor(logger, allowlist, true)),
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

	// In production mode (TLS enabled), enforce that AuthService has tokens loaded
	// (or a backend configured for on-demand fetching).
	// An empty AuthService with no backend in production is almost certainly a misconfiguration.
	isTLSEnabled := *tlsCert != "" && *tlsKey != ""
	isOnDemandBackend := resolvedTokenSource == "s3"
	if isTLSEnabled && authSvc.TokenCount() == 0 && !isOnDemandBackend {
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

	// Start periodic token store refresh (if a backing store is configured).
	// This polls the store for version changes and broadcasts invalidation
	// events to all connected routers when tokens are rotated or removed.
	ctx, ctxCancel := context.WithCancel(context.Background())
	defer ctxCancel()

	// Start admin API server (if enabled).
	var adminSrv *coordinator.AdminServer
	if *adminEnabled {
		var s3ManagesEncryption *bool
		switch strings.ToLower(strings.TrimSpace(*adminS3ManagesEncryptionStr)) {
		case "true":
			v := true
			s3ManagesEncryption = &v
		case "false":
			v := false
			s3ManagesEncryption = &v
		case "":
			logger.Error("--admin-s3-manages-encryption is REQUIRED when admin API is enabled. " +
				"Set to 'true' (S3 SSE handles encryption) or 'false' (CSAR KMS encrypts before S3 write).")
			os.Exit(1)
		default:
			logger.Error("--admin-s3-manages-encryption must be 'true' or 'false'",
				"value", *adminS3ManagesEncryptionStr)
			os.Exit(1)
		}

		var allowedKeys []string
		if *adminAllowedKMSKeys != "" {
			for _, k := range strings.Split(*adminAllowedKMSKeys, ",") {
				k = strings.TrimSpace(k)
				if k != "" {
					allowedKeys = append(allowedKeys, k)
				}
			}
		}

		adminCfg := coordinator.AdminAPIConfig{
			Enabled:             true,
			ListenAddr:          *adminListen,
			S3ManagesEncryption: s3ManagesEncryption,
			AllowInsecure:       *adminAllowInsecure,
			TLS: coordinator.AdminTLSConfig{
				CertFile:     *adminTLSCert,
				KeyFile:      *adminTLSKey,
				ClientCAFile: *adminClientCA,
			},
			Auth: coordinator.AdminAuthConfig{
				JWKSUrl:   *adminJWKSUrl,
				Issuer:    *adminIssuer,
				Audiences: strings.Split(*adminAudience, ","),
			},
			Authorization: coordinator.AdminAuthzConfig{
				EnforceTokenPrefixClaim: *adminEnforceTokenPrefix,
				EnforceAllowedKMSKeys:   *adminEnforceAllowedKMSKeys,
				AllowedKMSKeys:          allowedKeys,
			},
			Limits: coordinator.AdminLimitsConfig{
				MaxTokenSize:   *adminMaxTokenSize,
				RequestTimeout: *adminRequestTimeout,
			},
		}

		if err := adminCfg.Validate(); err != nil {
			logger.Error("admin API configuration invalid", "error", err)
			os.Exit(1)
		}

		// Ensure we have a mutable token store.
		mutableStore, ok := tokenStore.(coordinator.MutableTokenStore)
		if !ok || tokenStore == nil {
			logger.Error("admin API requires a mutable token store backend (currently only S3 is supported). " +
				"Use --token-source=s3 with --s3-bucket.")
			os.Exit(1)
		}

		// Initialize KMS provider for admin API (only needed when S3 doesn't manage encryption).
		var kmsProvider kms.Provider
		if !*s3ManagesEncryption {
			var err error
			kmsProvider, err = initCoordinatorKMS(*adminKMSProvider, *adminKMSLocalKeys,
				*adminKMSYandexEndpoint, *adminKMSYandexAuthMode,
				*adminKMSYandexIAMToken, *adminKMSYandexOAuthToken,
				*adminKMSYandexSAKeyFile)
			if err != nil {
				logger.Error("failed to initialize KMS provider for admin API", "error", err)
				os.Exit(1)
			}
			defer kmsProvider.Close()
			logger.Info("KMS provider initialized for admin API", "provider", kmsProvider.Name())
		}

		adminSrv = coordinator.NewAdminServer(
			adminCfg, authSvc, coord, mutableStore, kmsProvider,
			logger.With("component", "admin_api"),
		)

		go func() {
			if err := adminSrv.ListenAndServe(); err != nil {
				logger.Error("admin API server error", "error", err)
			}
		}()

		logger.Info("admin API server started",
			"listen", *adminListen,
			"s3_manages_encryption", *s3ManagesEncryption,
		)
	}

	if refresher != nil {
		go refresher.RunPeriodicRefresh(ctx, refreshInterval, authSvc, coord)
		logger.Info("token store refresh loop started", "interval", refreshInterval)
	}

	// Start config source watcher (if configured).
	if configWatcher != nil {
		go configWatcher.RunPeriodicWatch(ctx, *configRefreshInterval)
		logger.Info("config watcher started", "interval", *configRefreshInterval)
	}

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigCh

		logger.Info("received signal, shutting down", "signal", sig)
		ctxCancel() // stop refresh loop
		if adminSrv != nil {
			adminSrv.Shutdown() //nolint:errcheck
		}
		if tokenStore != nil {
			tokenStore.Close()
		}
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
//
// When requirePeerCert is true (TLS enabled), a verified client certificate
// is always required — even when no allowlist is configured. This prevents
// the TLS-only path from silently accepting unauthenticated callers.
//
// When requirePeerCert is false (insecure dev mode), any caller is accepted.
func checkIdentity(ctx context.Context, allowlist []string, requirePeerCert bool) error {
	cn, sans, ok := extractPeerIdentity(ctx)

	if !requirePeerCert && len(allowlist) == 0 {
		return nil
	}

	if !ok {
		return status.Error(codes.Unauthenticated, "no verified client certificate was presented")
	}

	if len(allowlist) == 0 {
		// TLS with mTLS enforced but no allowlist — accept any authenticated peer.
		return nil
	}

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
func authUnaryInterceptor(logger *slog.Logger, allowlist []string, requirePeerCert bool) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if err := checkIdentity(ctx, allowlist, requirePeerCert); err != nil {
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
func authStreamInterceptor(logger *slog.Logger, allowlist []string, requirePeerCert bool) grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if err := checkIdentity(ss.Context(), allowlist, requirePeerCert); err != nil {
			logger.Warn("rejected stream RPC: identity check failed",
				"method", info.FullMethod,
				"error", err,
			)
			return err
		}
		return handler(srv, ss)
	}
}

// parseConfigHTTPHeaders parses comma-separated "key=value" pairs and an
// optional bearer token into a headers map for HTTPSource.
func parseConfigHTTPHeaders(raw, bearer string) map[string]string {
	headers := make(map[string]string)
	if bearer != "" {
		headers["Authorization"] = "Bearer " + bearer
	}
	if raw != "" {
		for _, pair := range strings.Split(raw, ",") {
			pair = strings.TrimSpace(pair)
			if k, v, ok := strings.Cut(pair, "="); ok {
				headers[strings.TrimSpace(k)] = strings.TrimSpace(v)
			}
		}
	}
	return headers
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

// initCoordinatorKMS creates a KMS provider for the coordinator admin API.
func initCoordinatorKMS(
	provider, localKeys string,
	yandexEndpoint, yandexAuthMode, yandexIAMToken, yandexOAuthToken, yandexSAKeyFile string,
) (kms.Provider, error) {
	switch provider {
	case "local":
		if localKeys == "" {
			return nil, fmt.Errorf("--admin-kms-local-keys is required when --admin-kms-provider=local")
		}
		passphrases, err := parseLocalKeys(localKeys)
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
			SAKeyFile:  yandexSAKeyFile,
		}
		return kms.NewYandexAPIProvider(yCfg)

	default:
		return nil, fmt.Errorf("unknown admin KMS provider %q; supported: \"local\", \"yandexapi\"", provider)
	}
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
			return nil, fmt.Errorf("invalid key=passphrase pair: %q", pair)
		}
		result[parts[0]] = parts[1]
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("no valid key=passphrase pairs found in %q", raw)
	}
	return result, nil
}
