package helper

import (
	"strings"
	"testing"
)

func TestDetectDialect(t *testing.T) {
	tests := []struct {
		dsn     string
		want    Dialect
		wantErr bool
	}{
		{"postgres://user:pass@host/db", DialectPostgres, false},
		{"postgresql://user:pass@host/db", DialectPostgres, false},
		{"POSTGRES://user:pass@host/db", DialectPostgres, false},
		{"mysql://user:pass@host/db", DialectMySQL, false},
		{"sqlite://path/to/db.sqlite", DialectSQLite, false},
		{"file:path/to/db.sqlite", DialectSQLite, false},
		{"unknown://foo", "", true},
		{"just-a-string", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.dsn, func(t *testing.T) {
			got, err := DetectDialect(tt.dsn)
			if (err != nil) != tt.wantErr {
				t.Errorf("DetectDialect(%q) error = %v, wantErr %v", tt.dsn, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("DetectDialect(%q) = %v, want %v", tt.dsn, got, tt.want)
			}
		})
	}
}

func TestTokensTableDDL_Postgres(t *testing.T) {
	ddl := TokensTableDDL(DialectPostgres, "csar_tokens", true)
	if !strings.Contains(ddl, "IF NOT EXISTS") {
		t.Error("expected IF NOT EXISTS clause")
	}
	if !strings.Contains(ddl, "BYTEA") {
		t.Error("expected BYTEA type for PostgreSQL")
	}
	if !strings.Contains(ddl, "token_ref    TEXT PRIMARY KEY") {
		t.Error("expected TEXT PRIMARY KEY for token_ref")
	}
	if !strings.Contains(ddl, "TIMESTAMPTZ") {
		t.Error("expected TIMESTAMPTZ for updated_at")
	}
}

func TestTokensTableDDL_MySQL(t *testing.T) {
	ddl := TokensTableDDL(DialectMySQL, "tokens", false)
	if strings.Contains(ddl, "IF NOT EXISTS") {
		t.Error("did not expect IF NOT EXISTS clause")
	}
	if !strings.Contains(ddl, "VARBINARY(4096)") {
		t.Error("expected VARBINARY type for MySQL")
	}
	if !strings.Contains(ddl, "VARCHAR(255)") {
		t.Error("expected VARCHAR type for MySQL token_ref")
	}
}

func TestTokensTableDDL_SQLite(t *testing.T) {
	ddl := TokensTableDDL(DialectSQLite, "csar_tokens", true)
	if !strings.Contains(ddl, "BLOB") {
		t.Error("expected BLOB type for SQLite")
	}
	if !strings.Contains(ddl, "datetime('now')") {
		t.Error("expected datetime('now') for SQLite")
	}
}

func TestStateStoreTablesDDL(t *testing.T) {
	for _, dialect := range []Dialect{DialectPostgres, DialectMySQL, DialectSQLite} {
		t.Run(string(dialect), func(t *testing.T) {
			stmts := StateStoreTablesDDL(dialect, true)
			if len(stmts) != 2 {
				t.Errorf("expected 2 statements, got %d", len(stmts))
			}
			// Check that both csar_routers and csar_quotas are created
			combined := strings.Join(stmts, "\n")
			if !strings.Contains(combined, "csar_routers") {
				t.Error("expected csar_routers table")
			}
			if !strings.Contains(combined, "csar_quotas") {
				t.Error("expected csar_quotas table")
			}
		})
	}
}

func TestUpsertTokenSQL(t *testing.T) {
	tests := []struct {
		dialect  Dialect
		contains string
	}{
		{DialectPostgres, "ON CONFLICT"},
		{DialectMySQL, "ON DUPLICATE KEY UPDATE"},
		{DialectSQLite, "ON CONFLICT"},
	}

	for _, tt := range tests {
		t.Run(string(tt.dialect), func(t *testing.T) {
			sql := UpsertTokenSQL(tt.dialect, "csar_tokens")
			if !strings.Contains(sql, tt.contains) {
				t.Errorf("expected %q in upsert SQL for %s, got:\n%s", tt.contains, tt.dialect, sql)
			}
		})
	}
}

func TestPlaceholderFunc(t *testing.T) {
	pgPH := PlaceholderFunc(DialectPostgres)
	if pgPH(1) != "$1" || pgPH(3) != "$3" {
		t.Error("PostgreSQL placeholders should be $1, $2, ...")
	}

	myPH := PlaceholderFunc(DialectMySQL)
	if myPH(1) != "?" || myPH(3) != "?" {
		t.Error("MySQL placeholders should be ?")
	}
}

func TestCustomTableName(t *testing.T) {
	ddl := TokensTableDDL(DialectPostgres, "my_custom_tokens", true)
	if !strings.Contains(ddl, "my_custom_tokens") {
		t.Error("expected custom table name in DDL")
	}
	if strings.Contains(ddl, "csar_tokens") {
		t.Error("should not contain default table name when custom is used")
	}
}
