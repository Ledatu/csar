package main

import (
	"log/slog"
	"os"

	"github.com/spf13/cobra"
)

var logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
	Level: slog.LevelInfo,
}))

var rootCmd = &cobra.Command{
	Use:   "csar-helper",
	Short: "CSAR helper — database, key management, and configuration tool",
	Long: `csar-helper is a companion CLI for the CSAR API gateway.

It provides commands for:
  • Database initialization and token migration
  • Cryptographic key generation and JWKS management
  • Configuration scaffolding and validation
  • A development JWKS server for local testing`,
}

func init() {
	rootCmd.CompletionOptions.DisableDefaultCmd = true
}
