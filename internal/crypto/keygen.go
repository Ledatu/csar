// Package crypto provides key generation, JWKS conversion, and a dev JWKS server
// for the csar-helper CLI.
package crypto

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/ledatu/csar-core/jwtx"
)

// KeyAlgorithm represents the key type to generate.
type KeyAlgorithm string

const (
	AlgEd25519 KeyAlgorithm = "ed25519"
	AlgRSA     KeyAlgorithm = "rsa"
)

// GenerateOptions configures key pair generation.
type GenerateOptions struct {
	Algorithm KeyAlgorithm // default: ed25519
	RSABits   int          // default: 2048 (only used for RSA)
	OutputDir string       // directory for output files
	KeyName   string       // base name for key files (default: "csar")
}

// GeneratedKey contains the result of a key generation operation.
type GeneratedKey struct {
	PrivateKeyPath string
	PublicKeyPath  string
	KID            string       // key ID derived from SHA-256 of public key
	Algorithm      KeyAlgorithm
}

// GenerateKeyPair generates a cryptographic key pair and writes it to disk.
// Private key files are written with 0600 permissions.
func GenerateKeyPair(opts GenerateOptions) (*GeneratedKey, error) {
	if opts.KeyName == "" {
		opts.KeyName = "csar"
	}
	if opts.RSABits == 0 {
		opts.RSABits = 2048
	}
	if opts.Algorithm == "" {
		opts.Algorithm = AlgEd25519
	}

	var jwtxAlg string
	switch opts.Algorithm {
	case AlgEd25519:
		jwtxAlg = "EdDSA"
	case AlgRSA:
		jwtxAlg = "RS256"
	default:
		return nil, fmt.Errorf("unsupported algorithm %q; supported: ed25519, rsa", opts.Algorithm)
	}

	var genOpts []jwtx.GenerateOption
	if opts.Algorithm == AlgRSA {
		genOpts = append(genOpts, jwtx.WithRSABits(opts.RSABits))
	}

	kp, err := jwtx.GenerateKeyPair(jwtxAlg, genOpts...)
	if err != nil {
		return nil, err
	}

	privPEM, pubPEM, err := jwtx.MarshalKeyPairPEM(kp)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(opts.OutputDir, 0o755); err != nil {
		return nil, fmt.Errorf("creating output directory: %w", err)
	}

	privPath := filepath.Join(opts.OutputDir, opts.KeyName+".key")
	pubPath := filepath.Join(opts.OutputDir, opts.KeyName+".pub")

	if err := os.WriteFile(privPath, privPEM, 0o600); err != nil {
		return nil, fmt.Errorf("writing private key: %w", err)
	}
	if err := os.WriteFile(pubPath, pubPEM, 0o644); err != nil {
		return nil, fmt.Errorf("writing public key: %w", err)
	}

	return &GeneratedKey{
		PrivateKeyPath: privPath,
		PublicKeyPath:  pubPath,
		KID:            kp.KID,
		Algorithm:      opts.Algorithm,
	}, nil
}

// ComputeKID derives a key ID from the SHA-256 hash of the DER-encoded public key.
// Returns the first 8 bytes as a 16-character hex string.
func ComputeKID(pubDER []byte) string {
	return jwtx.ComputeKID(pubDER)
}
