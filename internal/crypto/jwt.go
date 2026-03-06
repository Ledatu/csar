package crypto

import (
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// IssueTokenOptions configures JWT generation.
type IssueTokenOptions struct {
	// PrivKeyPath is the path to the PEM-encoded private key (Ed25519 or RSA PKCS#8).
	PrivKeyPath string

	// PubKeyPath is optional. When provided, the KID is derived from the public key.
	// If omitted, kid is derived from the private key's public component.
	PubKeyPath string

	// KID overrides automatic key-ID derivation.
	KID string

	// Subject (sub claim).
	Subject string

	// Issuer (iss claim).
	Issuer string

	// Audience (aud claim), comma-separated or slice.
	Audience []string

	// TTL for the token (default: 1 hour).
	TTL time.Duration

	// ExtraClaims are additional key=value pairs injected into the token.
	// Values are always strings; use the form "key=value".
	ExtraClaims map[string]string
}

// IssueToken creates and signs a JWT using the private key at opts.PrivKeyPath.
// Supports Ed25519 (EdDSA) and RSA (RS256) keys.
// Returns the compact serialised token string.
func IssueToken(opts IssueTokenOptions) (string, error) {
	if opts.PrivKeyPath == "" {
		return "", fmt.Errorf("--priv-key is required")
	}
	if opts.TTL <= 0 {
		opts.TTL = time.Hour
	}

	privData, err := os.ReadFile(opts.PrivKeyPath)
	if err != nil {
		return "", fmt.Errorf("reading private key: %w", err)
	}

	block, _ := pem.Decode(privData)
	if block == nil {
		return "", fmt.Errorf("no PEM block found in %s", opts.PrivKeyPath)
	}

	rawKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parsing private key: %w", err)
	}

	// Determine signing method and derive kid
	var (
		signingMethod jwt.SigningMethod
		signingKey    any
		kid           string
	)

	switch k := rawKey.(type) {
	case ed25519.PrivateKey:
		signingMethod = jwt.SigningMethodEdDSA
		signingKey = k
		kid = computeKIDFromEd25519Public(k.Public().(ed25519.PublicKey))

	case *rsa.PrivateKey:
		signingMethod = jwt.SigningMethodRS256
		signingKey = k
		kidBytes, err2 := x509.MarshalPKIXPublicKey(&k.PublicKey)
		if err2 != nil {
			return "", fmt.Errorf("marshaling RSA public key for kid: %w", err2)
		}
		kid = ComputeKID(kidBytes)

	default:
		return "", fmt.Errorf("unsupported private key type: %T", rawKey)
	}

	// Override kid from explicit pub-key file or --kid flag
	if opts.PubKeyPath != "" {
		pubData, err2 := os.ReadFile(opts.PubKeyPath)
		if err2 != nil {
			return "", fmt.Errorf("reading public key: %w", err2)
		}
		pubBlock, _ := pem.Decode(pubData)
		if pubBlock == nil {
			return "", fmt.Errorf("no PEM block found in %s", opts.PubKeyPath)
		}
		kid = ComputeKID(pubBlock.Bytes)
	}
	if opts.KID != "" {
		kid = opts.KID
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"iat": jwt.NewNumericDate(now),
		"nbf": jwt.NewNumericDate(now),
		"exp": jwt.NewNumericDate(now.Add(opts.TTL)),
	}
	if opts.Subject != "" {
		claims["sub"] = opts.Subject
	}
	if opts.Issuer != "" {
		claims["iss"] = opts.Issuer
	}
	if len(opts.Audience) > 0 {
		claims["aud"] = opts.Audience
	}
	for k, v := range opts.ExtraClaims {
		// Support numeric values for well-known numeric claims
		claims[k] = v
	}

	token := jwt.NewWithClaims(signingMethod, claims)
	token.Header["kid"] = kid

	signed, err := token.SignedString(signingKey)
	if err != nil {
		return "", fmt.Errorf("signing token: %w", err)
	}
	return signed, nil
}

// computeKIDFromEd25519Public derives a KID from a raw Ed25519 public key.
func computeKIDFromEd25519Public(pub ed25519.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		// fallback: hash raw bytes
		return ComputeKID(pub)
	}
	return ComputeKID(der)
}

// ParseExtraClaims parses a slice of "key=value" strings into a map.
func ParseExtraClaims(pairs []string) (map[string]string, error) {
	out := make(map[string]string, len(pairs))
	for _, p := range pairs {
		k, v, ok := strings.Cut(p, "=")
		if !ok {
			return nil, fmt.Errorf("invalid claim %q: expected key=value format", p)
		}
		out[k] = v
	}
	return out, nil
}
