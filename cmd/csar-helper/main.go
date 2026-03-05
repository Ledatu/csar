package main

import (
	"os"

	_ "github.com/go-sql-driver/mysql" // MySQL driver
	_ "github.com/lib/pq"              // PostgreSQL driver
	_ "modernc.org/sqlite"             // SQLite driver (pure Go)
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
