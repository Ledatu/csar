package coordinator

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
)

// PostgresTokenStore implements TokenStore backed by a PostgreSQL table.
//
// It reads pre-encrypted token blobs — tokens are encrypted out-of-band
// (e.g. via `yc kms symmetric-crypto encrypt`). The coordinator never
// sees plaintext.
//
// All queries use parameterized placeholders ($1, $2, …) — never string
// interpolation — so token_ref values cannot cause SQL injection.
//
// Expected table schema:
//
//	CREATE TABLE csar_tokens (
//	    token_ref    TEXT PRIMARY KEY,
//	    enc_token    BYTEA NOT NULL,
//	    kms_key_id   TEXT NOT NULL,
//	    version      TEXT NOT NULL DEFAULT '1',
//	    updated_at   TIMESTAMPTZ DEFAULT NOW()
//	);
type PostgresTokenStore struct {
	db     *sql.DB
	logger *slog.Logger
}

// Compile-time check: PostgresTokenStore implements TokenStore.
var _ TokenStore = (*PostgresTokenStore)(nil)

// NewPostgresTokenStore creates a token store backed by the given database.
// The caller is responsible for importing the appropriate driver
// (e.g. _ "github.com/lib/pq").
func NewPostgresTokenStore(db *sql.DB, logger *slog.Logger) *PostgresTokenStore {
	return &PostgresTokenStore{
		db:     db,
		logger: logger,
	}
}

// LoadAll queries every token from csar_tokens and returns them as a map
// suitable for AuthServiceImpl.LoadTokensFromMap.
func (s *PostgresTokenStore) LoadAll(ctx context.Context) (map[string]TokenEntry, error) {
	const query = `SELECT token_ref, enc_token, kms_key_id, version FROM csar_tokens`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("postgres token store: query all: %w", err)
	}
	defer rows.Close()

	entries := make(map[string]TokenEntry)
	for rows.Next() {
		var ref, kmsKeyID, version string
		var encToken []byte
		if err := rows.Scan(&ref, &encToken, &kmsKeyID, &version); err != nil {
			return nil, fmt.Errorf("postgres token store: scan row: %w", err)
		}
		entries[ref] = TokenEntry{
			EncryptedToken: encToken,
			KMSKeyID:       kmsKeyID,
			Version:        version,
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres token store: rows iteration: %w", err)
	}

	return entries, nil
}

// FetchOne retrieves a single token from csar_tokens by its ref.
// Returns ErrTokenNotFound (wrapped) when the ref doesn't exist.
//
// Uses a parameterized query ($1) — the tokenRef value is never
// interpolated into the SQL string.
func (s *PostgresTokenStore) FetchOne(ctx context.Context, tokenRef string) (TokenEntry, error) {
	const query = `SELECT enc_token, kms_key_id, version FROM csar_tokens WHERE token_ref = $1`

	var entry TokenEntry
	var encToken []byte
	err := s.db.QueryRowContext(ctx, query, tokenRef).Scan(&encToken, &entry.KMSKeyID, &entry.Version)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return TokenEntry{}, fmt.Errorf("token ref %q: %w", tokenRef, ErrTokenNotFound)
		}
		return TokenEntry{}, fmt.Errorf("postgres token store: fetch %q: %w", tokenRef, err)
	}
	entry.EncryptedToken = encToken

	s.logger.Debug("fetched single token from postgres",
		"token_ref", tokenRef,
		"version", entry.Version,
	)
	return entry, nil
}

// Close closes the underlying database connection pool.
func (s *PostgresTokenStore) Close() error {
	return s.db.Close()
}
