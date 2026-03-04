package helper

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// SQLSourceConfig configures the SQL source adapter.
type SQLSourceConfig struct {
	DSN          string
	Query        string // custom query to run
	RefColumn    string // column name for token_ref (default: "token_ref")
	TokenColumn  string // column name for the token value (default: "token")
	KMSKeyColumn string // optional column for kms_key_id (empty = plaintext source)
}

// SQLSource reads tokens from an existing SQL database.
type SQLSource struct {
	cfg SQLSourceConfig
}

// NewSQLSource creates a new SQL source adapter.
func NewSQLSource(cfg SQLSourceConfig) *SQLSource {
	if cfg.RefColumn == "" {
		cfg.RefColumn = "token_ref"
	}
	if cfg.TokenColumn == "" {
		cfg.TokenColumn = "token"
	}
	return &SQLSource{cfg: cfg}
}

// Load queries the source database and returns tokens.
func (s *SQLSource) Load(ctx context.Context) (map[string]TokenData, error) {
	dialect, err := DetectDialect(s.cfg.DSN)
	if err != nil {
		return nil, err
	}

	dsn := s.cfg.DSN
	if dialect == DialectMySQL {
		dsn = strings.TrimPrefix(dsn, "mysql://")
	}
	if dialect == DialectSQLite {
		dsn = strings.TrimPrefix(dsn, "sqlite://")
	}

	db, err := sql.Open(driverForDialect(dialect), dsn)
	if err != nil {
		return nil, fmt.Errorf("sql source: opening database: %w", err)
	}
	defer db.Close()

	query := s.cfg.Query
	if query == "" {
		cols := s.cfg.RefColumn + ", " + s.cfg.TokenColumn
		if s.cfg.KMSKeyColumn != "" {
			cols += ", " + s.cfg.KMSKeyColumn
		}
		query = fmt.Sprintf("SELECT %s FROM csar_tokens", cols)
	}

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("sql source: query: %w", err)
	}
	defer rows.Close()

	result := make(map[string]TokenData)
	hasKMSColumn := s.cfg.KMSKeyColumn != ""

	for rows.Next() {
		var ref string
		var kmsKeyID string

		if hasKMSColumn {
			// Scan token as []byte to preserve binary ciphertext from BYTEA/BLOB/VARBINARY
			// columns without UTF-8 coercion.
			var encToken []byte
			if err := rows.Scan(&ref, &encToken, &kmsKeyID); err != nil {
				return nil, fmt.Errorf("sql source: scan row: %w", err)
			}
			result[ref] = TokenData{
				EncryptedToken: encToken,
				KMSKeyID:       kmsKeyID,
			}
		} else {
			var token string
			if err := rows.Scan(&ref, &token); err != nil {
				return nil, fmt.Errorf("sql source: scan row: %w", err)
			}
			result[ref] = TokenData{
				Plaintext: token,
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sql source: rows iteration: %w", err)
	}

	return result, nil
}
