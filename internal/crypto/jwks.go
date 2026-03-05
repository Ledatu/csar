package crypto

import (
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
)

// JWK represents a single JSON Web Key (RFC 7517 / RFC 8037).
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg,omitempty"`

	// RSA fields
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`

	// OKP fields (Ed25519)
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
}

// JWKS represents a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// PublicKeyToJWKS reads a PEM-encoded public key file and returns a JWKS JSON document.
func PublicKeyToJWKS(pubKeyPath string) ([]byte, error) {
	jwk, err := publicKeyFileToJWK(pubKeyPath)
	if err != nil {
		return nil, err
	}

	jwks := JWKS{Keys: []JWK{*jwk}}
	return json.MarshalIndent(jwks, "", "  ")
}

// PublicKeyToEnvVars reads private and public key PEM files and returns
// a map of environment variable names to base64-encoded values,
// suitable for configuring csar-ts or similar clients.
func PublicKeyToEnvVars(privKeyPath, pubKeyPath string) (map[string]string, error) {
	privData, err := os.ReadFile(privKeyPath)
	if err != nil {
		return nil, fmt.Errorf("reading private key: %w", err)
	}

	pubData, err := os.ReadFile(pubKeyPath)
	if err != nil {
		return nil, fmt.Errorf("reading public key: %w", err)
	}

	// Parse public key to compute KID
	block, _ := pem.Decode(pubData)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", pubKeyPath)
	}
	kid := ComputeKID(block.Bytes)

	return map[string]string{
		"CSAR_JWT_PRIVATE_KEY": base64.StdEncoding.EncodeToString(privData),
		"CSAR_JWT_PUBLIC_KEY":  base64.StdEncoding.EncodeToString(pubData),
		"CSAR_JWT_KID":         kid,
	}, nil
}

// publicKeyFileToJWK reads a PEM public key and converts it to a JWK.
func publicKeyFileToJWK(pubKeyPath string) (*JWK, error) {
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

	kid := ComputeKID(block.Bytes)

	switch key := pub.(type) {
	case ed25519.PublicKey:
		return &JWK{
			Kty: "OKP",
			Kid: kid,
			Use: "sig",
			Alg: "EdDSA",
			Crv: "Ed25519",
			X:   base64.RawURLEncoding.EncodeToString(key),
		}, nil

	case *rsa.PublicKey:
		return &JWK{
			Kty: "RSA",
			Kid: kid,
			Use: "sig",
			Alg: "RS256",
			N:   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}, nil

	default:
		return nil, fmt.Errorf("unsupported key type: %T", pub)
	}
}
