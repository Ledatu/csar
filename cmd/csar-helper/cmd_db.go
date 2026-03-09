package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Ledatu/csar-core/s3store"
	"github.com/Ledatu/csar-core/ycloud"

	"github.com/ledatu/csar/internal/helper"
	"github.com/ledatu/csar/internal/logging"
	"github.com/spf13/cobra"
)

// ─── db ────────────────────────────────────────────────────────────────────────

var dbCmd = &cobra.Command{
	Use:   "db",
	Short: "Database initialization and token migration",
}

// ─── db init ───────────────────────────────────────────────────────────────────

var dbInitDSN string
var dbInitTable string
var dbInitIfNotExists bool
var dbInitStateStore bool

var dbInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Create csar_tokens table in the target database",
	Long:  `Creates the csar_tokens table (and optionally state store tables) in the target database.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if dbInitDSN == "" {
			return fmt.Errorf("--dsn is required")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		return helper.DBInit(ctx, helper.DBInitOptions{
			DSN:         dbInitDSN,
			Table:       dbInitTable,
			IfNotExists: dbInitIfNotExists,
			StateStore:  dbInitStateStore,
		}, logger)
	},
}

// ─── db migrate ────────────────────────────────────────────────────────────────

var (
	migrateSource       string
	migrateTargetDSN    string
	migrateTable        string
	migrateEncrypt      bool
	migrateKMSProvider  string
	migrateKMSKeyID     string
	migrateKMSLocalKeys string
	migrateDryRun       bool
	migrateUpsert       bool

	// SQL source
	migrateSourceDSN    string
	migrateSourceQuery  string
	migrateRefColumn    string
	migrateTokenColumn  string
	migrateKMSKeyColumn string

	// YAML/JSON source
	migrateSourceFile string

	// Env source
	migrateEnvPrefix string

	// Vault source
	migrateVaultAddr  string
	migrateVaultToken string
	migrateVaultPath  string
	migrateVaultMount string

	// HTTP source
	migrateHTTPURL     string
	migrateJQPath      string
	migrateHTTPHeaders []string

	// S3 source
	migrateS3Bucket         string
	migrateS3Endpoint       string
	migrateS3Region         string
	migrateS3Prefix         string
	migrateS3AuthMode       string
	migrateS3AccessKeyID    string
	migrateS3SecretAccessKey string
	migrateS3IAMToken       string
	migrateS3OAuthToken     string
	migrateS3SAKeyFile      string
	migrateS3KMSMode        string

	// Yandex KMS
	migrateYandexEndpoint   string
	migrateYandexAuthMode   string
	migrateYandexIAMToken   string
	migrateYandexOAuthToken string
	migrateYandexSAKeyFile  string
)

var dbMigrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Import tokens from various sources into csar_tokens",
	Long: `Reads tokens from an external source (SQL, YAML, JSON, env, Vault, HTTP),
optionally encrypts them, and inserts/upserts them into the target database.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if migrateSource == "" {
			return fmt.Errorf("--source is required (sql, yaml, json, env, vault, http)")
		}
		if migrateTargetDSN == "" {
			return fmt.Errorf("--target-dsn is required")
		}

		// Build the token source
		var tokenSource helper.TokenSource
		switch migrateSource {
		case "sql":
			if migrateSourceDSN == "" {
				return fmt.Errorf("--source-dsn is required for SQL source")
			}
			tokenSource = helper.NewSQLSource(helper.SQLSourceConfig{
				DSN:          migrateSourceDSN,
				Query:        migrateSourceQuery,
				RefColumn:    migrateRefColumn,
				TokenColumn:  migrateTokenColumn,
				KMSKeyColumn: migrateKMSKeyColumn,
			})

		case "yaml", "json":
			if migrateSourceFile == "" {
				return fmt.Errorf("--source-file is required for YAML/JSON source")
			}
			tokenSource = helper.NewYAMLSource(helper.YAMLSourceConfig{
				File: migrateSourceFile,
			})

		case "env":
			if migrateEnvPrefix == "" {
				return fmt.Errorf("--env-prefix is required for env source")
			}
			tokenSource = helper.NewEnvSource(helper.EnvSourceConfig{
				Prefix: migrateEnvPrefix,
			})

		case "vault":
			tokenSource = helper.NewVaultSource(helper.VaultSourceConfig{
				VaultAddr:  migrateVaultAddr,
				VaultToken: migrateVaultToken,
				VaultPath:  migrateVaultPath,
				VaultMount: migrateVaultMount,
			})

		case "http":
			if migrateHTTPURL == "" {
				return fmt.Errorf("--http-url is required for HTTP source")
			}
			tokenSource = helper.NewVaultSource(helper.VaultSourceConfig{
				HTTPURL:     migrateHTTPURL,
				HTTPHeaders: migrateHTTPHeaders,
				JQPath:      migrateJQPath,
			})

		case "s3":
			if migrateS3Bucket == "" {
				return fmt.Errorf("--s3-bucket is required for S3 source")
			}
			s3Client, err := s3store.NewClient(s3store.Config{
				Bucket:   migrateS3Bucket,
				Endpoint: migrateS3Endpoint,
				Region:   migrateS3Region,
				Prefix:   migrateS3Prefix,
				Auth: ycloud.AuthConfig{
					AuthMode:       migrateS3AuthMode,
					IAMToken:       logging.NewSecret(migrateS3IAMToken),
					OAuthToken:     logging.NewSecret(migrateS3OAuthToken),
					SAKeyFile:      migrateS3SAKeyFile,
					AccessKeyID:    logging.NewSecret(migrateS3AccessKeyID),
					SecretAccessKey: logging.NewSecret(migrateS3SecretAccessKey),
				},
			}, logger)
			if err != nil {
				return fmt.Errorf("creating S3 client: %w", err)
			}
			kmsMode := migrateS3KMSMode
			if kmsMode == "" {
				kmsMode = "kms"
			}
			tokenSource = helper.NewS3Source(helper.S3SourceConfig{
				Client:  s3Client,
				KMSMode: kmsMode,
			})

		default:
			return fmt.Errorf("unknown source type %q; supported: sql, yaml, json, env, vault, http, s3", migrateSource)
		}

		// Parse local keys
		var localKeys map[string]string
		if migrateKMSLocalKeys != "" {
			localKeys = make(map[string]string)
			for _, pair := range strings.Split(migrateKMSLocalKeys, ",") {
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
			TargetDSN:        migrateTargetDSN,
			Table:            migrateTable,
			Encrypt:          migrateEncrypt,
			KMSProvider:      migrateKMSProvider,
			KMSKeyID:         migrateKMSKeyID,
			LocalKeys:        localKeys,
			DryRun:           migrateDryRun,
			Upsert:           migrateUpsert,
			YandexEndpoint:   migrateYandexEndpoint,
			YandexAuthMode:   migrateYandexAuthMode,
			YandexIAMToken:   migrateYandexIAMToken,
			YandexOAuthToken: migrateYandexOAuthToken,
		}, logger)
		if err != nil {
			return err
		}

		fmt.Printf("\nMigration complete: %d total, %d inserted, %d encrypted\n",
			result.Total, result.Inserted, result.Encrypted)
		return nil
	},
}

// ─── token ─────────────────────────────────────────────────────────────────────

var tokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Token operations",
}

var (
	tokenEncryptPlaintext        string
	tokenEncryptKMSProvider      string
	tokenEncryptKMSKeyID         string
	tokenEncryptKMSLocalKeys     string
	tokenEncryptYandexEndpoint   string
	tokenEncryptYandexAuthMode   string
	tokenEncryptYandexIAMToken   string
	tokenEncryptYandexOAuthToken string
)

var tokenEncryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "Encrypt a single plaintext token using KMS",
	Long:  `Encrypts a plaintext token and outputs the base64-encoded ciphertext.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		input := tokenEncryptPlaintext
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
		if tokenEncryptKMSKeyID == "" {
			return fmt.Errorf("--kms-key-id is required")
		}

		localKeys := make(map[string]string)
		if tokenEncryptKMSLocalKeys != "" {
			for _, pair := range strings.Split(tokenEncryptKMSLocalKeys, ",") {
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
			KMSProvider:      tokenEncryptKMSProvider,
			KMSKeyID:         tokenEncryptKMSKeyID,
			LocalKeys:        localKeys,
			YandexEndpoint:   tokenEncryptYandexEndpoint,
			YandexAuthMode:   tokenEncryptYandexAuthMode,
			YandexIAMToken:   tokenEncryptYandexIAMToken,
			YandexOAuthToken: tokenEncryptYandexOAuthToken,
		})
		if err != nil {
			return err
		}

		fmt.Println(base64.StdEncoding.EncodeToString(encrypted))
		return nil
	},
}

func init() {
	// db init flags
	dbInitCmd.Flags().StringVar(&dbInitDSN, "dsn", "", "target database DSN (required; e.g. postgres://user:pass@host/db)")
	dbInitCmd.Flags().StringVar(&dbInitTable, "table", "csar_tokens", "table name for tokens")
	dbInitCmd.Flags().BoolVar(&dbInitIfNotExists, "if-not-exists", true, "use IF NOT EXISTS in CREATE TABLE")
	dbInitCmd.Flags().BoolVar(&dbInitStateStore, "state-store", false, "also create state store tables (csar_routers, csar_quotas)")

	// db migrate flags
	dbMigrateCmd.Flags().StringVar(&migrateSource, "source", "", "source type: sql, yaml, json, env, vault, http, s3 (required)")
	dbMigrateCmd.Flags().StringVar(&migrateTargetDSN, "target-dsn", "", "target database DSN (required)")
	dbMigrateCmd.Flags().StringVar(&migrateTable, "table", "csar_tokens", "target table name")
	dbMigrateCmd.Flags().BoolVar(&migrateEncrypt, "encrypt", false, "encrypt plaintext tokens before inserting")
	dbMigrateCmd.Flags().StringVar(&migrateKMSProvider, "kms-provider", "local", "KMS provider for encryption (local, yandexapi)")
	dbMigrateCmd.Flags().StringVar(&migrateKMSKeyID, "kms-key-id", "", "KMS key ID for encryption")
	dbMigrateCmd.Flags().StringVar(&migrateKMSLocalKeys, "kms-local-keys", "", "local KMS keys (keyID=passphrase,...)")
	dbMigrateCmd.Flags().BoolVar(&migrateDryRun, "dry-run", false, "show what would be migrated without writing")
	dbMigrateCmd.Flags().BoolVar(&migrateUpsert, "upsert", true, "update existing tokens (false = skip/error)")

	// SQL source flags
	dbMigrateCmd.Flags().StringVar(&migrateSourceDSN, "source-dsn", "", "SQL source database DSN")
	dbMigrateCmd.Flags().StringVar(&migrateSourceQuery, "source-query", "", "custom SQL query for source")
	dbMigrateCmd.Flags().StringVar(&migrateRefColumn, "ref-column", "token_ref", "column name for token_ref in source")
	dbMigrateCmd.Flags().StringVar(&migrateTokenColumn, "token-column", "token", "column name for token value in source")
	dbMigrateCmd.Flags().StringVar(&migrateKMSKeyColumn, "kms-key-column", "", "column for kms_key_id (empty = plaintext)")

	// YAML/JSON source flags
	dbMigrateCmd.Flags().StringVar(&migrateSourceFile, "source-file", "", "path to YAML/JSON token file")

	// Env source flags
	dbMigrateCmd.Flags().StringVar(&migrateEnvPrefix, "env-prefix", "", "environment variable prefix (e.g. TOKEN_)")

	// Vault source flags
	dbMigrateCmd.Flags().StringVar(&migrateVaultAddr, "vault-addr", "", "Vault address (e.g. http://127.0.0.1:8200)")
	dbMigrateCmd.Flags().StringVar(&migrateVaultToken, "vault-token", "", "Vault authentication token")
	dbMigrateCmd.Flags().StringVar(&migrateVaultPath, "vault-path", "", "Vault secret path")
	dbMigrateCmd.Flags().StringVar(&migrateVaultMount, "vault-mount", "secret", "Vault KV mount")

	// HTTP source flags
	dbMigrateCmd.Flags().StringVar(&migrateHTTPURL, "http-url", "", "HTTP API URL for token fetch")
	dbMigrateCmd.Flags().StringVar(&migrateJQPath, "jq", "", "dot-separated path to extract tokens from JSON response")
	dbMigrateCmd.Flags().StringSliceVar(&migrateHTTPHeaders, "http-header", nil, "HTTP headers in \"Key: Value\" format (repeatable)")

	// S3 source flags
	dbMigrateCmd.Flags().StringVar(&migrateS3Bucket, "s3-bucket", "", "S3 bucket name for token storage")
	dbMigrateCmd.Flags().StringVar(&migrateS3Endpoint, "s3-endpoint", "https://storage.yandexcloud.net", "S3-compatible endpoint URL")
	dbMigrateCmd.Flags().StringVar(&migrateS3Region, "s3-region", "ru-central1", "S3 region")
	dbMigrateCmd.Flags().StringVar(&migrateS3Prefix, "s3-prefix", "tokens/", "S3 key prefix for token objects")
	dbMigrateCmd.Flags().StringVar(&migrateS3AuthMode, "s3-auth-mode", "static", "S3 auth mode: static, iam_token, oauth_token, metadata, service_account")
	dbMigrateCmd.Flags().StringVar(&migrateS3AccessKeyID, "s3-access-key-id", "", "S3 access key ID (static auth)")
	dbMigrateCmd.Flags().StringVar(&migrateS3SecretAccessKey, "s3-secret-access-key", "", "S3 secret access key (static auth)")
	dbMigrateCmd.Flags().StringVar(&migrateS3IAMToken, "s3-iam-token", "", "IAM token for S3 (iam_token auth)")
	dbMigrateCmd.Flags().StringVar(&migrateS3OAuthToken, "s3-oauth-token", "", "OAuth token for S3 IAM exchange (oauth_token auth)")
	dbMigrateCmd.Flags().StringVar(&migrateS3SAKeyFile, "s3-sa-key-file", "", "SA key file for S3 (service_account auth)")
	dbMigrateCmd.Flags().StringVar(&migrateS3KMSMode, "s3-kms-mode", "kms", "S3 KMS mode: passthrough (SSE only), kms (CSAR KMS encrypted)")

	// Yandex KMS flags
	dbMigrateCmd.Flags().StringVar(&migrateYandexEndpoint, "yandex-kms-endpoint", "", "Yandex Cloud KMS API endpoint")
	dbMigrateCmd.Flags().StringVar(&migrateYandexAuthMode, "yandex-auth-mode", "metadata", "Yandex KMS auth mode: iam_token, oauth_token, metadata")
	dbMigrateCmd.Flags().StringVar(&migrateYandexIAMToken, "yandex-iam-token", "", "static IAM token for Yandex KMS")
	dbMigrateCmd.Flags().StringVar(&migrateYandexOAuthToken, "yandex-oauth-token", "", "OAuth token for IAM token exchange")
	dbMigrateCmd.Flags().StringVar(&migrateYandexSAKeyFile, "yandex-sa-key-file", "", "Service account key file for Yandex KMS")

	// token encrypt flags
	tokenEncryptCmd.Flags().StringVar(&tokenEncryptPlaintext, "plaintext", "", "plaintext token to encrypt (or read from stdin)")
	tokenEncryptCmd.Flags().StringVar(&tokenEncryptKMSProvider, "kms-provider", "local", "KMS provider (local, yandexapi)")
	tokenEncryptCmd.Flags().StringVar(&tokenEncryptKMSKeyID, "kms-key-id", "", "KMS key ID (required)")
	tokenEncryptCmd.Flags().StringVar(&tokenEncryptKMSLocalKeys, "kms-local-keys", "", "local KMS keys (keyID=passphrase,...)")
	tokenEncryptCmd.Flags().StringVar(&tokenEncryptYandexEndpoint, "yandex-kms-endpoint", "", "Yandex Cloud KMS API endpoint")
	tokenEncryptCmd.Flags().StringVar(&tokenEncryptYandexAuthMode, "yandex-auth-mode", "metadata", "Yandex KMS auth mode: iam_token, oauth_token, metadata")
	tokenEncryptCmd.Flags().StringVar(&tokenEncryptYandexIAMToken, "yandex-iam-token", "", "static IAM token for Yandex KMS")
	tokenEncryptCmd.Flags().StringVar(&tokenEncryptYandexOAuthToken, "yandex-oauth-token", "", "OAuth token for IAM token exchange")

	// Wire command hierarchy
	dbCmd.AddCommand(dbInitCmd, dbMigrateCmd)
	tokenCmd.AddCommand(tokenEncryptCmd)
	rootCmd.AddCommand(dbCmd, tokenCmd)
}
