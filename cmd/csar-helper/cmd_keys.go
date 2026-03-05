package main

import (
	"fmt"
	"sort"

	csarcrypto "github.com/ledatu/csar/internal/crypto"
	"github.com/spf13/cobra"
)

// ─── keys ──────────────────────────────────────────────────────────────────────

var keysCmd = &cobra.Command{
	Use:   "keys",
	Short: "Cryptographic key generation and conversion",
	Long: `Commands for generating JWT signing keys and exporting them
to JWKS or environment variable formats.`,
}

// ─── keys generate ─────────────────────────────────────────────────────────────

var (
	keysGenAlgorithm string
	keysGenRSABits   int
	keysGenOutputDir string
	keysGenKeyName   string
)

var keysGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a signing key pair (Ed25519 or RSA)",
	Long: `Generates a cryptographic key pair for JWT signing.

Ed25519 is the default algorithm (fast, compact, modern).
RSA is available as an alternative for compatibility with legacy systems.

The key ID (kid) is automatically derived from the SHA-256 hash of the public key.
Private keys are saved with 0600 permissions.`,
	Example: `  # Generate an Ed25519 key pair (default)
  csar-helper keys generate

  # Generate an RSA-4096 key pair with a custom name
  csar-helper keys generate --algorithm rsa --rsa-bits 4096 --name myservice

  # Generate keys into a specific directory
  csar-helper keys generate --output ./keys`,
	RunE: func(cmd *cobra.Command, args []string) error {
		result, err := csarcrypto.GenerateKeyPair(csarcrypto.GenerateOptions{
			Algorithm: csarcrypto.KeyAlgorithm(keysGenAlgorithm),
			RSABits:   keysGenRSABits,
			OutputDir: keysGenOutputDir,
			KeyName:   keysGenKeyName,
		})
		if err != nil {
			return err
		}

		fmt.Printf("Key pair generated successfully:\n")
		fmt.Printf("  Algorithm:    %s\n", result.Algorithm)
		fmt.Printf("  Key ID (kid): %s\n", result.KID)
		fmt.Printf("  Private key:  %s  (mode 0600)\n", result.PrivateKeyPath)
		fmt.Printf("  Public key:   %s\n", result.PublicKeyPath)
		return nil
	},
}

// ─── keys to-jwks ──────────────────────────────────────────────────────────────

var keysToJWKSPubKey string
var keysToJWKSOutput string

var keysToJWKSCmd = &cobra.Command{
	Use:   "to-jwks",
	Short: "Convert a public key to JWKS format",
	Long: `Reads a PEM-encoded public key and outputs a valid JWKS (JSON Web Key Set)
document that can be served at /.well-known/jwks.json for JWT validation.`,
	Example: `  # Print JWKS to stdout
  csar-helper keys to-jwks --pub-key csar.pub

  # Save JWKS to a file
  csar-helper keys to-jwks --pub-key csar.pub --output jwks.json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if keysToJWKSPubKey == "" {
			return fmt.Errorf("--pub-key is required")
		}

		jwksJSON, err := csarcrypto.PublicKeyToJWKS(keysToJWKSPubKey)
		if err != nil {
			return err
		}

		if keysToJWKSOutput != "" {
			if err := writeFileSafe(keysToJWKSOutput, jwksJSON, 0o644); err != nil {
				return err
			}
			fmt.Printf("JWKS written to %s\n", keysToJWKSOutput)
			return nil
		}

		fmt.Println(string(jwksJSON))
		return nil
	},
}

// ─── keys to-env ───────────────────────────────────────────────────────────────

var (
	keysToEnvPrivKey string
	keysToEnvPubKey  string
)

var keysToEnvCmd = &cobra.Command{
	Use:   "to-env",
	Short: "Export keys as base64 environment variables",
	Long: `Reads private and public key PEM files and outputs base64-encoded values
suitable for environment variables (e.g. for csar-ts client configuration).

Output variables:
  CSAR_JWT_PRIVATE_KEY   Base64-encoded private key PEM
  CSAR_JWT_PUBLIC_KEY    Base64-encoded public key PEM
  CSAR_JWT_KID           Key ID derived from the public key`,
	Example: `  # Print env vars to stdout
  csar-helper keys to-env --priv-key csar.key --pub-key csar.pub

  # Write to .env file
  csar-helper keys to-env --priv-key csar.key --pub-key csar.pub >> .env`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if keysToEnvPrivKey == "" {
			return fmt.Errorf("--priv-key is required")
		}
		if keysToEnvPubKey == "" {
			return fmt.Errorf("--pub-key is required")
		}

		envVars, err := csarcrypto.PublicKeyToEnvVars(keysToEnvPrivKey, keysToEnvPubKey)
		if err != nil {
			return err
		}

		// Sort keys for deterministic output
		keys := make([]string, 0, len(envVars))
		for k := range envVars {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for _, k := range keys {
			fmt.Printf("%s=%s\n", k, envVars[k])
		}
		return nil
	},
}

func init() {
	// keys generate flags
	keysGenerateCmd.Flags().StringVar(&keysGenAlgorithm, "algorithm", "ed25519", "key algorithm: ed25519, rsa")
	keysGenerateCmd.Flags().IntVar(&keysGenRSABits, "rsa-bits", 2048, "RSA key size in bits (only for --algorithm=rsa)")
	keysGenerateCmd.Flags().StringVar(&keysGenOutputDir, "output", ".", "output directory for key files")
	keysGenerateCmd.Flags().StringVar(&keysGenKeyName, "name", "csar", "base name for key files (produces <name>.key and <name>.pub)")

	// keys to-jwks flags
	keysToJWKSCmd.Flags().StringVar(&keysToJWKSPubKey, "pub-key", "", "path to PEM-encoded public key (required)")
	keysToJWKSCmd.Flags().StringVar(&keysToJWKSOutput, "output", "", "output file path (default: stdout)")

	// keys to-env flags
	keysToEnvCmd.Flags().StringVar(&keysToEnvPrivKey, "priv-key", "", "path to PEM-encoded private key (required)")
	keysToEnvCmd.Flags().StringVar(&keysToEnvPubKey, "pub-key", "", "path to PEM-encoded public key (required)")

	keysCmd.AddCommand(keysGenerateCmd, keysToJWKSCmd, keysToEnvCmd)
	rootCmd.AddCommand(keysCmd)
}
