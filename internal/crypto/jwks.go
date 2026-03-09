package crypto

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/ledatu/csar-core/jwtx"
)

// JWK represents a single JSON Web Key (RFC 7517 / RFC 8037).
type JWK = jwtx.JWK

// JWKS represents a JSON Web Key Set.
type JWKS = jwtx.JWKS

// PublicKeyToJWKS reads a PEM-encoded public key file and returns a JWKS JSON document.
func PublicKeyToJWKS(pubKeyPath string) ([]byte, error) {
	data, err := os.ReadFile(pubKeyPath)
	if err != nil {
		return nil, fmt.Errorf("reading public key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", pubKeyPath)
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}

	kid := jwtx.ComputeKID(block.Bytes)

	jwk, err := jwtx.NewJWKFromPublicKey(pub, kid)
	if err != nil {
		return nil, err
	}

	jwks := jwtx.JWKS{Keys: []jwtx.JWK{*jwk}}
	return json.MarshalIndent(jwks, "", "  ")
}

// PublicKeyToEnvVars reads private and public key PEM files and returns
// a map of environment variable names to base64-encoded values.
func PublicKeyToEnvVars(privKeyPath, pubKeyPath string) (map[string]string, error) {
	privData, err := os.ReadFile(privKeyPath)
	if err != nil {
		return nil, fmt.Errorf("reading private key: %w", err)
	}

	pubData, err := os.ReadFile(pubKeyPath)
	if err != nil {
		return nil, fmt.Errorf("reading public key: %w", err)
	}

	block, _ := pem.Decode(pubData)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", pubKeyPath)
	}
	kid := jwtx.ComputeKID(block.Bytes)

	return map[string]string{
		"CSAR_JWT_PRIVATE_KEY": base64.StdEncoding.EncodeToString(privData),
		"CSAR_JWT_PUBLIC_KEY":  base64.StdEncoding.EncodeToString(pubData),
		"CSAR_JWT_KID":         kid,
	}, nil
}
