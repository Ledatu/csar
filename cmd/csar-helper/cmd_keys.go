package main

import (
	"fmt"
	"sort"
	"time"

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

// ─── keys issue-token ──────────────────────────────────────────────────────────

var (
	keysIssuePrivKey     string
	keysIssuePubKey      string
	keysIssueKID         string
	keysIssueSub         string
	keysIssueIss         string
	keysIssueAud         []string
	keysIssueTTL         time.Duration
	keysIssueExtraClaims []string
)

var keysIssueTokenCmd = &cobra.Command{
	Use:   "issue-token",
	Short: "Issue a signed JWT using a private key",
	Long: `Generates and signs a JWT using the provided private key (Ed25519 or RSA).

The key ID (kid) is automatically derived from the public key's SHA-256 hash.
You can override it with --kid or by providing --pub-key.

The token is printed to stdout so it can be captured in a shell variable:

  TOKEN=$(csar-helper keys issue-token --priv-key csar.key --sub myservice --ttl 1h)`,
	Example: `  # Minimal: sign with Ed25519 key, 1h TTL
  csar-helper keys issue-token --priv-key csar.key

  # Full example with custom claims
  csar-helper keys issue-token \
    --priv-key csar.key --pub-key csar.pub \
    --sub seller1 --iss csar-dev --aud wb-api \
    --ttl 24h \
    --claim seller_id=4c68d0cf-947a-5740-95e3-dce57b196455 \
    --claim role=admin`,
	RunE: func(cmd *cobra.Command, args []string) error {
		extra, err := csarcrypto.ParseExtraClaims(keysIssueExtraClaims)
		if err != nil {
			return err
		}

		token, err := csarcrypto.IssueToken(csarcrypto.IssueTokenOptions{
			PrivKeyPath: keysIssuePrivKey,
			PubKeyPath:  keysIssuePubKey,
			KID:         keysIssueKID,
			Subject:     keysIssueSub,
			Issuer:      keysIssueIss,
			Audience:    keysIssueAud,
			TTL:         keysIssueTTL,
			ExtraClaims: extra,
		})
		if err != nil {
			return err
		}

		fmt.Println(token)
		return nil
	},
}

func init() {
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

	// keys issue-token flags
	keysIssueTokenCmd.Flags().StringVar(&keysIssuePrivKey, "priv-key", "", "path to PEM-encoded private key (required)")
	keysIssueTokenCmd.Flags().StringVar(&keysIssuePubKey, "pub-key", "", "path to PEM-encoded public key (for kid derivation)")
	keysIssueTokenCmd.Flags().StringVar(&keysIssueKID, "kid", "", "override key ID (kid header)")
	keysIssueTokenCmd.Flags().StringVar(&keysIssueSub, "sub", "", "subject claim (sub)")
	keysIssueTokenCmd.Flags().StringVar(&keysIssueIss, "iss", "", "issuer claim (iss)")
	keysIssueTokenCmd.Flags().StringArrayVar(&keysIssueAud, "aud", nil, "audience claim (aud), repeatable")
	keysIssueTokenCmd.Flags().DurationVar(&keysIssueTTL, "ttl", time.Hour, "token lifetime (e.g. 1h, 30m, 24h)")
	keysIssueTokenCmd.Flags().StringArrayVar(&keysIssueExtraClaims, "claim", nil, "extra claim as key=value, repeatable (e.g. --claim role=admin)")

	keysCmd.AddCommand(keysGenerateCmd, keysToJWKSCmd, keysToEnvCmd, keysIssueTokenCmd)
	rootCmd.AddCommand(keysCmd)
}
