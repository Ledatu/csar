package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql" // MySQL driver
	_ "github.com/lib/pq"              // PostgreSQL driver
	_ "modernc.org/sqlite"             // SQLite driver (pure Go)

	"github.com/ledatu/csar/internal/config"
	"github.com/ledatu/csar/internal/helper"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	cmd := os.Args[1]
	// For subcommands like "db init", join them.
	if len(os.Args) >= 3 && cmd == "db" {
		cmd = "db " + os.Args[2]
		os.Args = append(os.Args[:2], os.Args[3:]...)
	}

	var err error
	switch cmd {
	case "db init":
		err = runDBInit(logger)
	case "db migrate":
		err = runDBMigrate(logger)
	case "token encrypt":
		// Handle "token encrypt" as two-word subcommand
		if len(os.Args) >= 3 && os.Args[1] == "token" {
			os.Args = append(os.Args[:1], os.Args[2:]...)
		}
		err = runTokenEncrypt(logger)
	case "token":
		if len(os.Args) >= 3 && os.Args[2] == "encrypt" {
			os.Args = append(os.Args[:2], os.Args[3:]...)
			err = runTokenEncrypt(logger)
		} else {
			fmt.Fprintf(os.Stderr, "unknown token subcommand; use: token encrypt\n")
			os.Exit(1)
		}
	case "init":
		err = runInit(logger)
	case "validate":
		err = runValidate(logger)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`csar-helper — CSAR database and migration tool

Usage:
  csar-helper <command> [flags]

Commands:
  db init         Create csar_tokens table in the target database
  db migrate      Import tokens from various sources into csar_tokens
  token encrypt   Encrypt a single plaintext token using KMS
  init            Generate config scaffolding from a profile template
  validate        Validate config against its declared profile

Run "csar-helper <command> --help" for more information.`)
}

// ─── db init ───────────────────────────────────────────────────────────────────

func runDBInit(logger *slog.Logger) error {
	fs := flag.NewFlagSet("db init", flag.ExitOnError)
	dsn := fs.String("dsn", "", "target database DSN (required; e.g. postgres://user:pass@host/db)")
	table := fs.String("table", "csar_tokens", "table name for tokens")
	ifNotExists := fs.Bool("if-not-exists", true, "use IF NOT EXISTS in CREATE TABLE")
	stateStore := fs.Bool("state-store", false, "also create state store tables (csar_routers, csar_quotas)")
	if err := fs.Parse(os.Args[2:]); err != nil {
		return err
	}

	if *dsn == "" {
		return fmt.Errorf("--dsn is required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	return helper.DBInit(ctx, helper.DBInitOptions{
		DSN:         *dsn,
		Table:       *table,
		IfNotExists: *ifNotExists,
		StateStore:  *stateStore,
	}, logger)
}

// ─── db migrate ────────────────────────────────────────────────────────────────

func runDBMigrate(logger *slog.Logger) error {
	fs := flag.NewFlagSet("db migrate", flag.ExitOnError)

	// Source config
	source := fs.String("source", "", "source type: sql, yaml, json, env, vault, http (required)")
	targetDSN := fs.String("target-dsn", "", "target database DSN (required)")
	table := fs.String("table", "csar_tokens", "target table name")

	// Encryption
	encrypt := fs.Bool("encrypt", false, "encrypt plaintext tokens before inserting")
	kmsProvider := fs.String("kms-provider", "local", "KMS provider for encryption (local, yandexapi)")
	kmsKeyID := fs.String("kms-key-id", "", "KMS key ID for encryption")
	kmsLocalKeys := fs.String("kms-local-keys", "", "local KMS keys (keyID=passphrase,...)")

	// Yandex KMS flags (used when --kms-provider=yandexapi)
	yandexEndpoint := fs.String("yandex-kms-endpoint", "", "Yandex Cloud KMS API endpoint")
	yandexAuthMode := fs.String("yandex-auth-mode", "metadata", "Yandex KMS auth mode: iam_token, oauth_token, metadata")
	yandexIAMToken := fs.String("yandex-iam-token", "", "static IAM token for Yandex KMS")
	yandexOAuthToken := fs.String("yandex-oauth-token", "", "OAuth token for IAM token exchange")

	// Behavior
	dryRun := fs.Bool("dry-run", false, "show what would be migrated without writing")
	upsert := fs.Bool("upsert", true, "update existing tokens (false = skip/error)")

	// SQL source flags
	sourceDSN := fs.String("source-dsn", "", "SQL source database DSN")
	sourceQuery := fs.String("source-query", "", "custom SQL query for source")
	refColumn := fs.String("ref-column", "token_ref", "column name for token_ref in source")
	tokenColumn := fs.String("token-column", "token", "column name for token value in source")
	kmsKeyColumn := fs.String("kms-key-column", "", "column for kms_key_id (empty = plaintext)")

	// YAML/JSON source flags
	sourceFile := fs.String("source-file", "", "path to YAML/JSON token file")

	// Env source flags
	envPrefix := fs.String("env-prefix", "", "environment variable prefix (e.g. TOKEN_)")

	// Vault source flags
	vaultAddr := fs.String("vault-addr", "", "Vault address (e.g. http://127.0.0.1:8200)")
	vaultToken := fs.String("vault-token", "", "Vault authentication token")
	vaultPath := fs.String("vault-path", "", "Vault secret path")
	vaultMount := fs.String("vault-mount", "secret", "Vault KV mount")

	// HTTP source flags
	httpURL := fs.String("http-url", "", "HTTP API URL for token fetch")
	jqPath := fs.String("jq", "", "dot-separated path to extract tokens from JSON response")
	var httpHeaders multiFlag
	fs.Var(&httpHeaders, "http-header", "repeatable HTTP header in \"Key: Value\" format for HTTP source")

	if err := fs.Parse(os.Args[2:]); err != nil {
		return err
	}

	if *source == "" {
		return fmt.Errorf("--source is required (sql, yaml, json, env, vault, http)")
	}
	if *targetDSN == "" {
		return fmt.Errorf("--target-dsn is required")
	}

	// Build the token source
	var tokenSource helper.TokenSource
	switch *source {
	case "sql":
		if *sourceDSN == "" {
			return fmt.Errorf("--source-dsn is required for SQL source")
		}
		tokenSource = helper.NewSQLSource(helper.SQLSourceConfig{
			DSN:          *sourceDSN,
			Query:        *sourceQuery,
			RefColumn:    *refColumn,
			TokenColumn:  *tokenColumn,
			KMSKeyColumn: *kmsKeyColumn,
		})

	case "yaml", "json":
		if *sourceFile == "" {
			return fmt.Errorf("--source-file is required for YAML/JSON source")
		}
		tokenSource = helper.NewYAMLSource(helper.YAMLSourceConfig{
			File: *sourceFile,
		})

	case "env":
		if *envPrefix == "" {
			return fmt.Errorf("--env-prefix is required for env source")
		}
		tokenSource = helper.NewEnvSource(helper.EnvSourceConfig{
			Prefix: *envPrefix,
		})

	case "vault":
		tokenSource = helper.NewVaultSource(helper.VaultSourceConfig{
			VaultAddr:  *vaultAddr,
			VaultToken: *vaultToken,
			VaultPath:  *vaultPath,
			VaultMount: *vaultMount,
		})

	case "http":
		if *httpURL == "" {
			return fmt.Errorf("--http-url is required for HTTP source")
		}
		tokenSource = helper.NewVaultSource(helper.VaultSourceConfig{
			HTTPURL:     *httpURL,
			HTTPHeaders: []string(httpHeaders),
			JQPath:      *jqPath,
		})

	default:
		return fmt.Errorf("unknown source type %q; supported: sql, yaml, json, env, vault, http", *source)
	}

	// Parse local keys
	var localKeys map[string]string
	if *kmsLocalKeys != "" {
		localKeys = make(map[string]string)
		for _, pair := range strings.Split(*kmsLocalKeys, ",") {
			pair = strings.TrimSpace(pair)
			if pair == "" {
				continue
			}
			parts := strings.SplitN(pair, "=", 2)
			if len(parts) != 2 || parts[0] == "" {
				return fmt.Errorf("invalid key=passphrase pair: %q", pair)
			}
			localKeys[parts[0]] = parts[1]
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	result, err := helper.Migrate(ctx, helper.MigrateOptions{
		Source:           tokenSource,
		TargetDSN:       *targetDSN,
		Table:            *table,
		Encrypt:         *encrypt,
		KMSProvider:      *kmsProvider,
		KMSKeyID:        *kmsKeyID,
		LocalKeys:       localKeys,
		DryRun:          *dryRun,
		Upsert:          *upsert,
		YandexEndpoint:   *yandexEndpoint,
		YandexAuthMode:   *yandexAuthMode,
		YandexIAMToken:   *yandexIAMToken,
		YandexOAuthToken: *yandexOAuthToken,
	}, logger)
	if err != nil {
		return err
	}

	fmt.Printf("\nMigration complete: %d total, %d inserted, %d encrypted\n",
		result.Total, result.Inserted, result.Encrypted)
	return nil
}

// ─── token encrypt ─────────────────────────────────────────────────────────────

func runTokenEncrypt(logger *slog.Logger) error {
	fs := flag.NewFlagSet("token encrypt", flag.ExitOnError)
	plaintext := fs.String("plaintext", "", "plaintext token to encrypt (or read from stdin)")
	kmsProvider := fs.String("kms-provider", "local", "KMS provider (local, yandexapi)")
	kmsKeyID := fs.String("kms-key-id", "", "KMS key ID (required)")
	kmsLocalKeys := fs.String("kms-local-keys", "", "local KMS keys (keyID=passphrase,...)")
	yandexEndpoint := fs.String("yandex-kms-endpoint", "", "Yandex Cloud KMS API endpoint")
	yandexAuthMode := fs.String("yandex-auth-mode", "metadata", "Yandex KMS auth mode: iam_token, oauth_token, metadata")
	yandexIAMToken := fs.String("yandex-iam-token", "", "static IAM token for Yandex KMS")
	yandexOAuthToken := fs.String("yandex-oauth-token", "", "OAuth token for IAM token exchange")
	if err := fs.Parse(os.Args[2:]); err != nil {
		return err
	}

	// Read from stdin if --plaintext is not set
	input := *plaintext
	if input == "" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("reading from stdin: %w", err)
		}
		input = strings.TrimSpace(string(data))
	}
	if input == "" {
		return fmt.Errorf("--plaintext is required (or pipe to stdin)")
	}
	if *kmsKeyID == "" {
		return fmt.Errorf("--kms-key-id is required")
	}

	// Parse local keys
	localKeys := make(map[string]string)
	if *kmsLocalKeys != "" {
		for _, pair := range strings.Split(*kmsLocalKeys, ",") {
			pair = strings.TrimSpace(pair)
			if pair == "" {
				continue
			}
			parts := strings.SplitN(pair, "=", 2)
			if len(parts) != 2 || parts[0] == "" {
				return fmt.Errorf("invalid key=passphrase pair: %q", pair)
			}
			localKeys[parts[0]] = parts[1]
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	encrypted, err := helper.EncryptToken(ctx, helper.EncryptOptions{
		Plaintext:        input,
		KMSProvider:      *kmsProvider,
		KMSKeyID:         *kmsKeyID,
		LocalKeys:        localKeys,
		YandexEndpoint:   *yandexEndpoint,
		YandexAuthMode:   *yandexAuthMode,
		YandexIAMToken:   *yandexIAMToken,
		YandexOAuthToken: *yandexOAuthToken,
	})
	if err != nil {
		return err
	}

	_ = logger // suppress unused
	fmt.Println(base64.StdEncoding.EncodeToString(encrypted))
	return nil
}

// ─── init ──────────────────────────────────────────────────────────────────────

func runInit(logger *slog.Logger) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	profile := fs.String("profile", "", "deployment profile: dev-local, prod-single, prod-distributed (required)")
	outputDir := fs.String("output", ".", "output directory for generated files")
	force := fs.Bool("force", false, "overwrite existing files (default: fail if file exists)")
	if err := fs.Parse(os.Args[2:]); err != nil {
		return err
	}

	if *profile == "" {
		return fmt.Errorf("--profile is required; valid profiles: dev-local, prod-single, prod-distributed")
	}

	_ = logger // suppress unused
	fmt.Printf("Generating %q config scaffolding in %s...\n", *profile, *outputDir)
	return helper.InitProfile(helper.Profile(*profile), *outputDir, *force)
}

// ─── validate ──────────────────────────────────────────────────────────────────

func runValidate(logger *slog.Logger) error {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	configPath := fs.String("config", "config.yaml", "path to config file")
	if err := fs.Parse(os.Args[2:]); err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Check profile field
	if cfg.Profile == "" {
		fmt.Println("No profile declared in config — skipping profile validation.")
		fmt.Println("Config loaded successfully.")
		return nil
	}

	if !helper.IsValidProfile(cfg.Profile) {
		return fmt.Errorf("unknown profile %q in config", cfg.Profile)
	}

	// Build check input
	input := helper.ProfileCheckInput{
		Profile:            cfg.Profile,
		CoordinatorEnabled: cfg.Coordinator.Enabled,
		CoordinatorAddress: cfg.Coordinator.Address,
		CoordinatorCAFile:  cfg.Coordinator.CAFile,
		CoordinatorInsecure: cfg.Coordinator.AllowInsecure,
		HasSecureRoutes:    cfg.HasSecureRoutes(),
		TLSEnabled:         cfg.TLS != nil,
	}
	if cfg.KMS != nil {
		input.KMSProvider = cfg.KMS.Provider
	}
	if cfg.SecurityPolicy != nil {
		input.SecurityEnvironment = cfg.SecurityPolicy.Environment
	}

	violations := helper.ValidateProfile(input)
	if len(violations) > 0 {
		fmt.Printf("Profile %q validation failed with %d violation(s):\n", cfg.Profile, len(violations))
		for _, v := range violations {
			fmt.Printf("  ✗ %s\n", v.Error())
		}
		return fmt.Errorf("config validation failed")
	}

	// Also log any warnings from config validation
	for _, w := range cfg.Warnings {
		logger.Warn(w)
	}

	fmt.Printf("Config validated successfully (profile: %s)\n", cfg.Profile)
	return nil
}

// multiFlag implements flag.Value for repeatable string flags (e.g. --http-header).
type multiFlag []string

func (f *multiFlag) String() string { return strings.Join(*f, ", ") }
func (f *multiFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}
