package main

import (
	"fmt"

	csarcrypto "github.com/ledatu/csar/internal/crypto"
	"github.com/spf13/cobra"
)

var (
	devJWKSPubKey   string
	devJWKSFile     string
	devJWKSAddr     string
)

var devJWKSCmd = &cobra.Command{
	Use:   "dev-jwks",
	Short: "Start a local JWKS server for development",
	Long: `Starts a lightweight HTTP server that serves a JWKS document at
/.well-known/jwks.json for local JWT validation testing.

You can either provide a public key (which will be converted to JWKS on the fly)
or an existing jwks.json file.`,
	Example: `  # Serve JWKS from a public key
  csar-helper dev-jwks --pub-key csar.pub

  # Serve an existing jwks.json on a custom port
  csar-helper dev-jwks --jwks-file jwks.json --addr :9090

  # Use with csar router (set jwks_url to http://localhost:8080/.well-known/jwks.json)`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if devJWKSPubKey == "" && devJWKSFile == "" {
			return fmt.Errorf("either --pub-key or --jwks-file is required")
		}

		return csarcrypto.RunDevJWKSServer(csarcrypto.DevServerOptions{
			PubKeyPath: devJWKSPubKey,
			JWKSFile:   devJWKSFile,
			Addr:       devJWKSAddr,
			Logger:     logger,
		})
	},
}

func init() {
	devJWKSCmd.Flags().StringVar(&devJWKSPubKey, "pub-key", "", "path to PEM-encoded public key")
	devJWKSCmd.Flags().StringVar(&devJWKSFile, "jwks-file", "", "path to existing jwks.json file")
	devJWKSCmd.Flags().StringVar(&devJWKSAddr, "addr", ":8080", "listen address for the JWKS server")

	rootCmd.AddCommand(devJWKSCmd)
}
