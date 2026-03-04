package helper

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strings"
)

// DBInitOptions configures the db init command.
type DBInitOptions struct {
	DSN          string
	Table        string // default: "csar_tokens"
	IfNotExists  bool   // default: true
	StateStore   bool   // also create state store tables
}

// DBInit creates the csar_tokens table (and optionally state store tables)
// in the target database.
func DBInit(ctx context.Context, opts DBInitOptions, logger *slog.Logger) error {
	dialect, err := DetectDialect(opts.DSN)
	if err != nil {
		return err
	}

	dsn := opts.DSN
	// For MySQL, strip the mysql:// prefix — the Go driver expects user:pass@tcp(host)/db
	if dialect == DialectMySQL {
		dsn = strings.TrimPrefix(dsn, "mysql://")
	}
	// For SQLite, strip the sqlite:// prefix
	if dialect == DialectSQLite {
		dsn = strings.TrimPrefix(dsn, "sqlite://")
	}

	driverName := driverForDialect(dialect)

	db, err := sql.Open(driverName, dsn)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer db.Close()

	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("connecting to database: %w", err)
	}

	logger.Info("connected to database", "dialect", string(dialect))

	// Create tokens table
	ddl := TokensTableDDL(dialect, opts.Table, opts.IfNotExists)
	logger.Info("creating tokens table", "table", opts.Table, "ddl", ddl)
	if _, err := db.ExecContext(ctx, ddl); err != nil {
		return fmt.Errorf("creating table %s: %w", opts.Table, err)
	}
	logger.Info("tokens table created", "table", opts.Table)

	// Optionally create state store tables
	if opts.StateStore {
		stmts := StateStoreTablesDDL(dialect, opts.IfNotExists)
		for _, stmt := range stmts {
			logger.Info("creating state store table", "ddl", stmt)
			if _, err := db.ExecContext(ctx, stmt); err != nil {
				return fmt.Errorf("creating state store table: %w", err)
			}
		}
		logger.Info("state store tables created")
	}

	return nil
}

// driverForDialect returns the database/sql driver name for the given dialect.
func driverForDialect(dialect Dialect) string {
	switch dialect {
	case DialectPostgres:
		return "postgres"
	case DialectMySQL:
		return "mysql"
	case DialectSQLite:
		return "sqlite"
	default:
		return ""
	}
}
