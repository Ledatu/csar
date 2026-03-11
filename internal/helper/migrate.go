package helper

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strings"
)

// MigrateOptions configures the db migrate command.
type MigrateOptions struct {
	Source      TokenSource
	TargetDSN   string
	Table       string // default: "csar_tokens"
	Encrypt     bool   // whether to encrypt plaintext tokens before inserting
	KMSProvider string
	KMSKeyID    string
	LocalKeys   map[string]string
	DryRun      bool // show what would be done without writing
	Upsert      bool // update existing tokens (default: true)

	// Yandex KMS options (used when KMSProvider == "yandexapi")
	YandexEndpoint   string
	YandexAuthMode   string
	YandexIAMToken   string
	YandexOAuthToken string
}

// MigrateResult contains the outcome of a migration.
type MigrateResult struct {
	Total     int
	Inserted  int
	Updated   int
	Skipped   int
	Encrypted int
}

// Migrate orchestrates reading tokens from a source, optionally encrypting them,
// and inserting/upserting them into the target database.
func Migrate(ctx context.Context, opts MigrateOptions, logger *slog.Logger) (*MigrateResult, error) {
	// Load tokens from source
	logger.Info("loading tokens from source")
	tokens, err := opts.Source.Load(ctx)
	if err != nil {
		return nil, fmt.Errorf("loading tokens from source: %w", err)
	}
	logger.Info("loaded tokens from source", "count", len(tokens))

	if len(tokens) == 0 {
		return &MigrateResult{}, nil
	}

	// Encrypt plaintext tokens if requested
	result := &MigrateResult{Total: len(tokens)}
	if opts.Encrypt {
		provider, err := initProvider(opts.KMSProvider, opts.LocalKeys, &EncryptOptions{
			YandexEndpoint:   opts.YandexEndpoint,
			YandexAuthMode:   opts.YandexAuthMode,
			YandexIAMToken:   opts.YandexIAMToken,
			YandexOAuthToken: opts.YandexOAuthToken,
		})
		if err != nil {
			return nil, fmt.Errorf("initializing KMS provider for encryption: %w", err)
		}
		defer provider.Close()

		for ref, td := range tokens {
			if td.Plaintext != "" && len(td.EncryptedToken) == 0 {
				encrypted, err := provider.Encrypt(ctx, opts.KMSKeyID, []byte(td.Plaintext))
				if err != nil {
					return nil, fmt.Errorf("encrypting token %q: %w", ref, err)
				}
				td.EncryptedToken = encrypted
				td.KMSKeyID = opts.KMSKeyID
				td.Plaintext = "" // clear plaintext after encryption
				tokens[ref] = td
				result.Encrypted++
			}
		}
		logger.Info("encrypted plaintext tokens", "count", result.Encrypted)
	}

	// Validate that all tokens have encrypted data
	for ref, td := range tokens {
		if len(td.EncryptedToken) == 0 {
			if td.Plaintext != "" {
				return nil, fmt.Errorf("token %q has plaintext but --encrypt was not specified; "+
					"use --encrypt to encrypt before inserting, or provide pre-encrypted tokens", ref)
			}
			return nil, fmt.Errorf("token %q has neither plaintext nor encrypted data", ref)
		}
	}

	if opts.DryRun {
		logger.Info("dry-run mode — no changes will be written")
		for ref, td := range tokens {
			logger.Info("would migrate token",
				"token_ref", ref,
				"kms_key_id", td.KMSKeyID,
				"enc_token_len", len(td.EncryptedToken),
			)
		}
		result.Inserted = len(tokens) // hypothetical
		return result, nil
	}

	// Connect to target database
	dialect, err := DetectDialect(opts.TargetDSN)
	if err != nil {
		return nil, err
	}

	dsn := opts.TargetDSN
	if dialect == DialectMySQL {
		dsn = strings.TrimPrefix(dsn, "mysql://")
	}
	if dialect == DialectSQLite {
		dsn = strings.TrimPrefix(dsn, "sqlite://")
	}

	db, err := sql.Open(driverForDialect(dialect), dsn)
	if err != nil {
		return nil, fmt.Errorf("opening target database: %w", err)
	}
	defer db.Close()

	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("connecting to target database: %w", err)
	}

	// Choose the SQL statement
	var sqlStmt string
	if opts.Upsert {
		sqlStmt = UpsertTokenSQL(dialect, opts.Table)
	} else {
		sqlStmt = InsertTokenSQL(dialect, opts.Table)
	}

	// Execute in a transaction
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	stmt, err := tx.PrepareContext(ctx, sqlStmt)
	if err != nil {
		return nil, fmt.Errorf("preparing statement: %w", err)
	}
	defer stmt.Close()

	for ref, td := range tokens {
		version := "1"
		kmsKeyID := td.KMSKeyID
		if kmsKeyID == "" {
			kmsKeyID = opts.KMSKeyID
		}

		_, err := stmt.ExecContext(ctx, ref, td.EncryptedToken, kmsKeyID, version)
		if err != nil {
			return nil, fmt.Errorf("inserting token %q: %w", ref, err)
		}
		result.Inserted++
		logger.Debug("migrated token", "token_ref", ref, "kms_key_id", kmsKeyID)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("committing transaction: %w", err)
	}

	logger.Info("migration completed",
		"total", result.Total,
		"inserted", result.Inserted,
		"encrypted", result.Encrypted,
	)

	return result, nil
}
