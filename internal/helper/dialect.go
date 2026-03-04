package helper

import (
	"fmt"
	"strings"
)

// Dialect represents a SQL dialect (PostgreSQL, MySQL, SQLite).
type Dialect string

const (
	DialectPostgres Dialect = "postgres"
	DialectMySQL    Dialect = "mysql"
	DialectSQLite   Dialect = "sqlite"
)

// DetectDialect auto-detects the SQL dialect from a DSN string.
func DetectDialect(dsn string) (Dialect, error) {
	lower := strings.ToLower(dsn)
	switch {
	case strings.HasPrefix(lower, "postgres://"), strings.HasPrefix(lower, "postgresql://"):
		return DialectPostgres, nil
	case strings.HasPrefix(lower, "mysql://"):
		return DialectMySQL, nil
	case strings.HasPrefix(lower, "sqlite://"), strings.HasPrefix(lower, "file:"):
		return DialectSQLite, nil
	default:
		return "", fmt.Errorf("cannot auto-detect dialect from DSN %q; use postgres://, mysql://, sqlite:// or file: prefix", dsn)
	}
}

// TokensTableDDL returns the CREATE TABLE statement for the csar_tokens table.
func TokensTableDDL(dialect Dialect, table string, ifNotExists bool) string {
	ine := ""
	if ifNotExists {
		ine = "IF NOT EXISTS "
	}

	switch dialect {
	case DialectPostgres:
		return fmt.Sprintf(`CREATE TABLE %s%s (
    token_ref    TEXT PRIMARY KEY,
    enc_token    BYTEA NOT NULL,
    kms_key_id   TEXT NOT NULL,
    version      TEXT NOT NULL DEFAULT '1',
    updated_at   TIMESTAMPTZ DEFAULT NOW()
);`, ine, table)

	case DialectMySQL:
		return fmt.Sprintf(`CREATE TABLE %s%s (
    token_ref    VARCHAR(255) PRIMARY KEY,
    enc_token    VARBINARY(4096) NOT NULL,
    kms_key_id   VARCHAR(255) NOT NULL,
    version      VARCHAR(64) NOT NULL DEFAULT '1',
    updated_at   DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)
);`, ine, table)

	case DialectSQLite:
		return fmt.Sprintf(`CREATE TABLE %s%s (
    token_ref    TEXT PRIMARY KEY,
    enc_token    BLOB NOT NULL,
    kms_key_id   TEXT NOT NULL,
    version      TEXT NOT NULL DEFAULT '1',
    updated_at   TEXT DEFAULT (datetime('now'))
);`, ine, table)

	default:
		return ""
	}
}

// StateStoreTablesDDL returns the CREATE TABLE statements for state store tables
// (csar_routers, csar_quotas). Only relevant for coordinator setups.
func StateStoreTablesDDL(dialect Dialect, ifNotExists bool) []string {
	ine := ""
	if ifNotExists {
		ine = "IF NOT EXISTS "
	}

	switch dialect {
	case DialectPostgres:
		return []string{
			fmt.Sprintf(`CREATE TABLE %scsar_routers (
    router_id       TEXT PRIMARY KEY,
    listen_addr     TEXT NOT NULL DEFAULT '',
    last_heartbeat  TIMESTAMPTZ DEFAULT NOW(),
    healthy         BOOLEAN DEFAULT TRUE
);`, ine),
			fmt.Sprintf(`CREATE TABLE %scsar_quotas (
    route_key   TEXT PRIMARY KEY,
    rps         DOUBLE PRECISION NOT NULL DEFAULT 0,
    burst       INTEGER NOT NULL DEFAULT 0,
    updated_at  TIMESTAMPTZ DEFAULT NOW()
);`, ine),
		}

	case DialectMySQL:
		return []string{
			fmt.Sprintf(`CREATE TABLE %scsar_routers (
    router_id       VARCHAR(255) PRIMARY KEY,
    listen_addr     VARCHAR(255) NOT NULL DEFAULT '',
    last_heartbeat  DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    healthy         BOOLEAN DEFAULT TRUE
);`, ine),
			fmt.Sprintf(`CREATE TABLE %scsar_quotas (
    route_key   VARCHAR(255) PRIMARY KEY,
    rps         DOUBLE NOT NULL DEFAULT 0,
    burst       INT NOT NULL DEFAULT 0,
    updated_at  DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6)
);`, ine),
		}

	case DialectSQLite:
		return []string{
			fmt.Sprintf(`CREATE TABLE %scsar_routers (
    router_id       TEXT PRIMARY KEY,
    listen_addr     TEXT NOT NULL DEFAULT '',
    last_heartbeat  TEXT DEFAULT (datetime('now')),
    healthy         INTEGER DEFAULT 1
);`, ine),
			fmt.Sprintf(`CREATE TABLE %scsar_quotas (
    route_key   TEXT PRIMARY KEY,
    rps         REAL NOT NULL DEFAULT 0,
    burst       INTEGER NOT NULL DEFAULT 0,
    updated_at  TEXT DEFAULT (datetime('now'))
);`, ine),
		}

	default:
		return nil
	}
}

// UpsertTokenSQL returns the dialect-specific upsert (INSERT ON CONFLICT) SQL.
// The returned SQL has placeholders appropriate for each dialect.
func UpsertTokenSQL(dialect Dialect, table string) string {
	switch dialect {
	case DialectPostgres:
		return fmt.Sprintf(`INSERT INTO %s (token_ref, enc_token, kms_key_id, version)
VALUES ($1, $2, $3, $4)
ON CONFLICT (token_ref) DO UPDATE SET
    enc_token = EXCLUDED.enc_token,
    kms_key_id = EXCLUDED.kms_key_id,
    version = EXCLUDED.version,
    updated_at = NOW();`, table)

	case DialectMySQL:
		return fmt.Sprintf(`INSERT INTO %s (token_ref, enc_token, kms_key_id, version)
VALUES (?, ?, ?, ?)
ON DUPLICATE KEY UPDATE
    enc_token = VALUES(enc_token),
    kms_key_id = VALUES(kms_key_id),
    version = VALUES(version),
    updated_at = CURRENT_TIMESTAMP(6);`, table)

	case DialectSQLite:
		return fmt.Sprintf(`INSERT INTO %s (token_ref, enc_token, kms_key_id, version)
VALUES (?, ?, ?, ?)
ON CONFLICT(token_ref) DO UPDATE SET
    enc_token = excluded.enc_token,
    kms_key_id = excluded.kms_key_id,
    version = excluded.version,
    updated_at = datetime('now');`, table)

	default:
		return ""
	}
}

// InsertTokenSQL returns the dialect-specific INSERT (no upsert) SQL.
func InsertTokenSQL(dialect Dialect, table string) string {
	switch dialect {
	case DialectPostgres:
		return fmt.Sprintf(`INSERT INTO %s (token_ref, enc_token, kms_key_id, version)
VALUES ($1, $2, $3, $4);`, table)

	case DialectMySQL, DialectSQLite:
		return fmt.Sprintf(`INSERT INTO %s (token_ref, enc_token, kms_key_id, version)
VALUES (?, ?, ?, ?);`, table)

	default:
		return ""
	}
}

// PlaceholderFunc returns a function that generates parameter placeholders
// appropriate for the given dialect. PostgreSQL uses $1, $2, ...; MySQL/SQLite use ?.
func PlaceholderFunc(dialect Dialect) func(n int) string {
	switch dialect {
	case DialectPostgres:
		return func(n int) string { return fmt.Sprintf("$%d", n) }
	default:
		return func(_ int) string { return "?" }
	}
}
