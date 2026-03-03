// Package authn provides inbound identity validation middleware.
//
// The primary component is JWTValidator, which validates Bearer tokens
// against a JWKS (JSON Web Key Set) endpoint before allowing the request
// to proceed through the router pipeline.
//
// Recommended by security audit §3.3.1: CSAR injects credentials outbound
// but did not validate inbound credentials.
package authn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Config configures JWT validation for a route.
type Config struct {
	// JWKSURL is the endpoint serving the JSON Web Key Set.
	JWKSURL string

	// Issuer validates the "iss" claim if non-empty.
	Issuer string

	// Audiences validates the "aud" claim contains at least one entry.
	Audiences []string

	// HeaderName is the HTTP header carrying the token. Default: "Authorization".
	HeaderName string

	// TokenPrefix is stripped before parsing. Default: "Bearer ".
	TokenPrefix string

	// CacheTTL controls JWKS cache lifetime. Default: 5m.
	CacheTTL time.Duration

	// RequiredClaims specifies claim key=value pairs that must match.
	RequiredClaims map[string]string

	// ForwardClaims copies JWT claims into request headers.
	// Map key = claim name, value = header name.
	ForwardClaims map[string]string
}

// JWTValidator validates inbound JWT tokens against a JWKS endpoint.
type JWTValidator struct {
	logger *slog.Logger
	client *http.Client

	// JWKS cache per URL
	mu    sync.RWMutex
	cache map[string]*jwksCache
}

type jwksCache struct {
	keys      []JSONWebKey
	fetchedAt time.Time
	ttl       time.Duration
}

// JSONWebKey represents a single key from a JWKS endpoint.
type JSONWebKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`   // RSA modulus
	E   string `json:"e"`   // RSA exponent
	Crv string `json:"crv"` // EC curve
	X   string `json:"x"`   // EC x coordinate
	Y   string `json:"y"`   // EC y coordinate
}

// jwksResponse is the top-level JWKS JSON structure.
type jwksResponse struct {
	Keys []JSONWebKey `json:"keys"`
}

// jwtHeader represents the decoded JWT header.
type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// NewJWTValidator creates a new JWTValidator.
func NewJWTValidator(logger *slog.Logger) *JWTValidator {
	return &JWTValidator{
		logger: logger,
		client: &http.Client{Timeout: 10 * time.Second},
		cache:  make(map[string]*jwksCache),
	}
}

// Wrap returns middleware that validates the JWT before calling next.
func (v *JWTValidator) Wrap(cfg Config, next http.Handler) http.Handler {
	// Apply defaults
	if cfg.HeaderName == "" {
		cfg.HeaderName = "Authorization"
	}
	if cfg.TokenPrefix == "" {
		cfg.TokenPrefix = "Bearer "
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = 5 * time.Minute
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract token from header
		authHeader := r.Header.Get(cfg.HeaderName)
		if authHeader == "" {
			v.reject(w, http.StatusUnauthorized, "missing authorization header")
			return
		}

		if !strings.HasPrefix(authHeader, cfg.TokenPrefix) {
			v.reject(w, http.StatusUnauthorized, "invalid token format")
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, cfg.TokenPrefix)
		if tokenStr == "" {
			v.reject(w, http.StatusUnauthorized, "empty token")
			return
		}

		// Parse JWT (header.payload.signature)
		parts := strings.Split(tokenStr, ".")
		if len(parts) != 3 {
			v.reject(w, http.StatusUnauthorized, "malformed JWT")
			return
		}

		// Decode header
		headerBytes, err := base64URLDecode(parts[0])
		if err != nil {
			v.reject(w, http.StatusUnauthorized, "invalid JWT header encoding")
			return
		}

		var header jwtHeader
		if err := json.Unmarshal(headerBytes, &header); err != nil {
			v.reject(w, http.StatusUnauthorized, "invalid JWT header")
			return
		}

		// Reject "none" algorithm (critical security check)
		if strings.EqualFold(header.Alg, "none") {
			v.reject(w, http.StatusUnauthorized, "unsecured JWT (alg=none) rejected")
			return
		}

		// Fetch JWKS and find matching key
		key, err := v.findKey(cfg.JWKSURL, cfg.CacheTTL, header.Kid, header.Alg)
		if err != nil {
			v.logger.Error("JWKS key lookup failed", "error", err, "kid", header.Kid)
			v.reject(w, http.StatusUnauthorized, "unable to validate token signature")
			return
		}

		// Verify signature
		signingInput := parts[0] + "." + parts[1]
		signature, err := base64URLDecode(parts[2])
		if err != nil {
			v.reject(w, http.StatusUnauthorized, "invalid JWT signature encoding")
			return
		}

		if err := verifySignature(header.Alg, key, []byte(signingInput), signature); err != nil {
			v.reject(w, http.StatusUnauthorized, "invalid JWT signature")
			return
		}

		// Decode and validate claims
		claimBytes, err := base64URLDecode(parts[1])
		if err != nil {
			v.reject(w, http.StatusUnauthorized, "invalid JWT payload encoding")
			return
		}

		var claims map[string]interface{}
		if err := json.Unmarshal(claimBytes, &claims); err != nil {
			v.reject(w, http.StatusUnauthorized, "invalid JWT claims")
			return
		}

		// Validate expiration
		if exp, ok := claims["exp"].(float64); ok {
			if time.Now().Unix() > int64(exp) {
				v.reject(w, http.StatusUnauthorized, "token expired")
				return
			}
		}

		// Validate not-before
		if nbf, ok := claims["nbf"].(float64); ok {
			if time.Now().Unix() < int64(nbf) {
				v.reject(w, http.StatusUnauthorized, "token not yet valid")
				return
			}
		}

		// Validate issuer
		if cfg.Issuer != "" {
			iss, _ := claims["iss"].(string)
			if iss != cfg.Issuer {
				v.reject(w, http.StatusUnauthorized, "invalid issuer")
				return
			}
		}

		// Validate audience
		if len(cfg.Audiences) > 0 {
			if !validateAudience(claims["aud"], cfg.Audiences) {
				v.reject(w, http.StatusUnauthorized, "invalid audience")
				return
			}
		}

		// Validate required claims
		for key, expected := range cfg.RequiredClaims {
			val, ok := claims[key]
			if !ok {
				v.reject(w, http.StatusForbidden, fmt.Sprintf("missing required claim %q", key))
				return
			}
			if fmt.Sprint(val) != expected {
				v.reject(w, http.StatusForbidden, fmt.Sprintf("claim %q value mismatch", key))
				return
			}
		}

		// Forward claims to request headers
		for claimName, headerName := range cfg.ForwardClaims {
			if val, ok := claims[claimName]; ok {
				r.Header.Set(headerName, fmt.Sprint(val))
			}
		}

		v.logger.Debug("JWT validated successfully",
			"kid", header.Kid,
			"alg", header.Alg,
			"sub", claims["sub"],
		)

		next.ServeHTTP(w, r)
	})
}

// findKey fetches (or returns cached) JWKS and finds the key matching kid and alg.
func (v *JWTValidator) findKey(jwksURL string, cacheTTL time.Duration, kid, alg string) (*JSONWebKey, error) {
	keys, err := v.getJWKS(jwksURL, cacheTTL)
	if err != nil {
		return nil, err
	}

	for i := range keys {
		k := &keys[i]
		if kid != "" && k.Kid != kid {
			continue
		}
		// Match by algorithm compatibility
		if k.Alg != "" && k.Alg != alg {
			continue
		}
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		return k, nil
	}

	// If kid was specified but not found, try refreshing the cache
	// (key may have been rotated).
	v.mu.Lock()
	delete(v.cache, jwksURL)
	v.mu.Unlock()

	keys, err = v.getJWKS(jwksURL, cacheTTL)
	if err != nil {
		return nil, err
	}

	for i := range keys {
		k := &keys[i]
		if kid != "" && k.Kid != kid {
			continue
		}
		if k.Alg != "" && k.Alg != alg {
			continue
		}
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		return k, nil
	}

	return nil, fmt.Errorf("no matching key found for kid=%q alg=%q", kid, alg)
}

// getJWKS returns cached JWKS keys or fetches them from the URL.
func (v *JWTValidator) getJWKS(jwksURL string, cacheTTL time.Duration) ([]JSONWebKey, error) {
	v.mu.RLock()
	if c, ok := v.cache[jwksURL]; ok && time.Since(c.fetchedAt) < c.ttl {
		v.mu.RUnlock()
		return c.keys, nil
	}
	v.mu.RUnlock()

	// Fetch JWKS
	resp, err := v.client.Get(jwksURL) //nolint:gosec // URL is from trusted config
	if err != nil {
		return nil, fmt.Errorf("fetching JWKS from %s: %w", jwksURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned %d", resp.StatusCode)
	}

	var jwks jwksResponse
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("decoding JWKS response: %w", err)
	}

	// Cache
	v.mu.Lock()
	v.cache[jwksURL] = &jwksCache{
		keys:      jwks.Keys,
		fetchedAt: time.Now(),
		ttl:       cacheTTL,
	}
	v.mu.Unlock()

	return jwks.Keys, nil
}

// reject sends a JSON error response.
func (v *JWTValidator) reject(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"error":%q}`, message)
}

// validateAudience checks if the token audience matches any of the expected audiences.
func validateAudience(aud interface{}, expected []string) bool {
	expectedSet := make(map[string]struct{}, len(expected))
	for _, a := range expected {
		expectedSet[a] = struct{}{}
	}

	switch v := aud.(type) {
	case string:
		_, ok := expectedSet[v]
		return ok
	case []interface{}:
		for _, a := range v {
			if s, ok := a.(string); ok {
				if _, found := expectedSet[s]; found {
					return true
				}
			}
		}
	}
	return false
}

// verifySignature verifies the JWT signature using the provided key.
func verifySignature(alg string, jwk *JSONWebKey, signingInput, signature []byte) error {
	switch {
	case strings.HasPrefix(alg, "RS"):
		return verifyRSA(alg, jwk, signingInput, signature)
	case strings.HasPrefix(alg, "ES"):
		return verifyECDSA(alg, jwk, signingInput, signature)
	default:
		return fmt.Errorf("unsupported algorithm: %s", alg)
	}
}

// verifyRSA verifies an RSA signature (RS256, RS384, RS512).
func verifyRSA(alg string, jwk *JSONWebKey, signingInput, signature []byte) error {
	if jwk.Kty != "RSA" {
		return errors.New("key type mismatch: expected RSA")
	}

	nBytes, err := base64URLDecode(jwk.N)
	if err != nil {
		return fmt.Errorf("decoding RSA modulus: %w", err)
	}
	eBytes, err := base64URLDecode(jwk.E)
	if err != nil {
		return fmt.Errorf("decoding RSA exponent: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	pubKey := &rsa.PublicKey{N: n, E: e}

	hashFunc := algToHash(alg)
	if hashFunc == 0 {
		return fmt.Errorf("unsupported RSA hash for %s", alg)
	}

	h := hashFunc.New()
	h.Write(signingInput)
	digest := h.Sum(nil)

	return rsa.VerifyPKCS1v15(pubKey, hashFunc, digest, signature)
}

// verifyECDSA verifies an ECDSA signature (ES256, ES384, ES512).
func verifyECDSA(alg string, jwk *JSONWebKey, signingInput, signature []byte) error {
	if jwk.Kty != "EC" {
		return errors.New("key type mismatch: expected EC")
	}

	curve, err := getCurve(jwk.Crv)
	if err != nil {
		return err
	}

	xBytes, err := base64URLDecode(jwk.X)
	if err != nil {
		return fmt.Errorf("decoding EC x: %w", err)
	}
	yBytes, err := base64URLDecode(jwk.Y)
	if err != nil {
		return fmt.Errorf("decoding EC y: %w", err)
	}

	pubKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}

	hashFunc := algToHash(alg)
	if hashFunc == 0 {
		return fmt.Errorf("unsupported ECDSA hash for %s", alg)
	}

	h := hashFunc.New()
	h.Write(signingInput)
	digest := h.Sum(nil)

	// ECDSA signature in JWT is r||s (raw, not ASN.1)
	keySize := (pubKey.Curve.Params().BitSize + 7) / 8
	if len(signature) != 2*keySize {
		return errors.New("invalid ECDSA signature length")
	}

	r := new(big.Int).SetBytes(signature[:keySize])
	s := new(big.Int).SetBytes(signature[keySize:])

	if !ecdsa.Verify(pubKey, digest, r, s) {
		return errors.New("ECDSA signature verification failed")
	}
	return nil
}

// algToHash maps JWT algorithm names to crypto.Hash.
func algToHash(alg string) crypto.Hash {
	switch alg {
	case "RS256", "ES256":
		return crypto.SHA256
	case "RS384", "ES384":
		return crypto.SHA384
	case "RS512", "ES512":
		return crypto.SHA512
	default:
		return 0
	}
}

// getCurve returns the elliptic curve for a JOSE curve name.
func getCurve(crv string) (elliptic.Curve, error) {
	switch crv {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported EC curve: %s", crv)
	}
}

// base64URLDecode decodes a base64url-encoded string (without padding).
func base64URLDecode(s string) ([]byte, error) {
	// Add padding if needed
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}
