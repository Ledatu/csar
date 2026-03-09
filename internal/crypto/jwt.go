package crypto

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Ledatu/csar-core/jwtx"
	"github.com/golang-jwt/jwt/v5"
)

// IssueTokenOptions configures JWT generation.
type IssueTokenOptions struct {
	PrivKeyPath string
	PubKeyPath  string
	KID         string
	Subject     string
	Issuer      string
	Audience    []string
	TTL         time.Duration
	ExtraClaims map[string]string
}

// IssueToken creates and signs a JWT using the private key at opts.PrivKeyPath.
// Supports Ed25519 (EdDSA) and RSA (RS256) keys.
func IssueToken(opts IssueTokenOptions) (string, error) {
	if opts.PrivKeyPath == "" {
		return "", fmt.Errorf("--priv-key is required")
	}
	if opts.TTL <= 0 {
		opts.TTL = time.Hour
	}

	var kp *jwtx.KeyPair
	var err error

	if opts.PubKeyPath != "" {
		kp, err = jwtx.LoadKeyPairFromPEM(opts.PrivKeyPath, opts.PubKeyPath)
	} else {
		kp, err = loadKeyPairPrivOnly(opts.PrivKeyPath)
	}
	if err != nil {
		return "", err
	}

	if opts.KID != "" {
		kp.KID = opts.KID
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
		claims[k] = v
	}

	return jwtx.Sign(kp, claims)
}

// loadKeyPairPrivOnly loads a key pair from a private key PEM only,
// deriving the public key and KID from the private key's public component.
func loadKeyPairPrivOnly(privPath string) (*jwtx.KeyPair, error) {
	privData, err := os.ReadFile(privPath)
	if err != nil {
		return nil, fmt.Errorf("reading private key: %w", err)
	}

	block, _ := pem.Decode(privData)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", privPath)
	}

	rawKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}

	signer, ok := rawKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key does not implement crypto.Signer")
	}

	pub := signer.Public()
	alg, err := jwtx.DetectAlgorithm(pub)
	if err != nil {
		return nil, err
	}

	kid, err := jwtx.ComputeKIDFromPublicKey(pub)
	if err != nil {
		return nil, err
	}

	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("marshalling public key: %w", err)
	}

	return &jwtx.KeyPair{
		PrivateKey: signer,
		PublicKey:  pub,
		Algorithm:  alg,
		KID:        kid,
		PublicDER:  pubDER,
	}, nil
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
