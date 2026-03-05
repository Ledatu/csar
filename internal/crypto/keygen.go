// Package crypto provides key generation, JWKS conversion, and a dev JWKS server
// for the csar-helper CLI.
package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
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

	var privPEM, pubPEM []byte
	var kid string
	var err error

	switch opts.Algorithm {
	case AlgEd25519:
		privPEM, pubPEM, kid, err = generateEd25519()
	case AlgRSA:
		privPEM, pubPEM, kid, err = generateRSA(opts.RSABits)
	default:
		return nil, fmt.Errorf("unsupported algorithm %q; supported: ed25519, rsa", opts.Algorithm)
	}
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
		KID:            kid,
		Algorithm:      opts.Algorithm,
	}, nil
}

func generateEd25519() (privPEM, pubPEM []byte, kid string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, "", fmt.Errorf("generating Ed25519 key: %w", err)
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, "", fmt.Errorf("marshaling private key: %w", err)
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, nil, "", fmt.Errorf("marshaling public key: %w", err)
	}

	privPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	pubPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
	kid = ComputeKID(pubBytes)

	return privPEM, pubPEM, kid, nil
}

func generateRSA(bits int) (privPEM, pubPEM []byte, kid string, err error) {
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, "", fmt.Errorf("generating RSA-%d key: %w", bits, err)
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, "", fmt.Errorf("marshaling private key: %w", err)
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, nil, "", fmt.Errorf("marshaling public key: %w", err)
	}

	privPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	pubPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
	kid = ComputeKID(pubBytes)

	return privPEM, pubPEM, kid, nil
}

// ComputeKID derives a key ID from the SHA-256 hash of the DER-encoded public key.
// Returns the first 8 bytes as a 16-character hex string.
func ComputeKID(pubDER []byte) string {
	h := sha256.Sum256(pubDER)
	return hex.EncodeToString(h[:8])
}
