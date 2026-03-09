// Package authn provides inbound identity validation middleware.
//
// The primary component is JWTValidator, which validates Bearer tokens
// against a JWKS (JSON Web Key Set) endpoint before allowing the request
// to proceed through the router pipeline.
package authn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Ledatu/csar-core/jwtx"
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

	// CookieName, if set, reads the JWT from the named cookie instead
	// of a request header. HeaderName and TokenPrefix are ignored when set.
	CookieName string
}

// JWTValidator validates inbound JWT tokens against a JWKS endpoint.
type JWTValidator struct {
	logger *slog.Logger
	client *http.Client

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
	X   string `json:"x"`   // EC x coordinate / Ed25519 public key
	Y   string `json:"y"`   // EC y coordinate
}

type jwksResponse struct {
	Keys []JSONWebKey `json:"keys"`
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
		var tokenStr string

		if cfg.CookieName != "" {
			cookie, err := r.Cookie(cfg.CookieName)
			if err != nil {
				v.reject(w, http.StatusUnauthorized, "missing session cookie")
				return
			}
			tokenStr = cookie.Value
		} else {
			authHeader := r.Header.Get(cfg.HeaderName)
			if authHeader == "" {
				v.reject(w, http.StatusUnauthorized, "missing authorization header")
				return
			}
			if !strings.HasPrefix(authHeader, cfg.TokenPrefix) {
				v.reject(w, http.StatusUnauthorized, "invalid token format")
				return
			}
			tokenStr = strings.TrimPrefix(authHeader, cfg.TokenPrefix)
		}

		if tokenStr == "" {
			v.reject(w, http.StatusUnauthorized, "empty token")
			return
		}

		// Build audience config: use first audience as RequiredAudience (backward compat).
		var requiredAud string
		if len(cfg.Audiences) > 0 {
			requiredAud = cfg.Audiences[0]
		}

		verifyCfg := &jwtx.VerifyConfig{
			RequiredIssuer:   cfg.Issuer,
			RequiredAudience: requiredAud,
		}

		// Key resolution via JWKS URL.
		keyFunc := func(kid, alg string) (crypto.PublicKey, error) {
			jwk, err := v.findKey(cfg.JWKSURL, cfg.CacheTTL, kid, alg)
			if err != nil {
				return nil, err
			}
			return jwkToPublicKey(jwk)
		}

		vt, err := jwtx.Verify(tokenStr, keyFunc, verifyCfg)
		if err != nil {
			v.logger.Error("JWT validation failed", "error", err)
			v.reject(w, http.StatusUnauthorized, "invalid token")
			return
		}

		// Validate audience against full list if multiple audiences configured.
		if len(cfg.Audiences) > 1 {
			if !validateAudience(vt.Claims["aud"], cfg.Audiences) {
				v.reject(w, http.StatusUnauthorized, "invalid audience")
				return
			}
		}

		// Validate required claims.
		for key, expected := range cfg.RequiredClaims {
			val, ok := vt.Claims[key]
			if !ok {
				v.reject(w, http.StatusForbidden, fmt.Sprintf("missing required claim %q", key))
				return
			}
			if fmt.Sprint(val) != expected {
				v.reject(w, http.StatusForbidden, fmt.Sprintf("claim %q value mismatch", key))
				return
			}
		}

		// Forward claims to request headers.
		for claimName, headerName := range cfg.ForwardClaims {
			if val, ok := vt.Claims[claimName]; ok {
				r.Header.Set(headerName, fmt.Sprint(val))
			}
		}

		v.logger.Debug("JWT validated successfully",
			"kid", vt.Header["kid"],
			"alg", vt.Header["alg"],
			"sub", vt.Claims["sub"],
		)

		next.ServeHTTP(w, r)
	})
}

// jwkToPublicKey converts a JSONWebKey to a crypto.PublicKey.
func jwkToPublicKey(jwk *JSONWebKey) (crypto.PublicKey, error) {
	switch jwk.Kty {
	case "RSA":
		return jwkToRSAPublicKey(jwk)
	case "EC":
		return jwkToECPublicKey(jwk)
	case "OKP":
		return jwkToEdPublicKey(jwk)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", jwk.Kty)
	}
}

func jwkToRSAPublicKey(jwk *JSONWebKey) (*rsa.PublicKey, error) {
	nBytes, err := base64URLDecode(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("decoding RSA modulus: %w", err)
	}
	eBytes, err := base64URLDecode(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("decoding RSA exponent: %w", err)
	}
	n := new(big.Int).SetBytes(nBytes)
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}
	return &rsa.PublicKey{N: n, E: e}, nil
}

func jwkToECPublicKey(jwk *JSONWebKey) (*ecdsa.PublicKey, error) {
	curve, err := getCurve(jwk.Crv)
	if err != nil {
		return nil, err
	}
	xBytes, err := base64URLDecode(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("decoding EC x: %w", err)
	}
	yBytes, err := base64URLDecode(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("decoding EC y: %w", err)
	}
	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}

func jwkToEdPublicKey(jwk *JSONWebKey) (ed25519.PublicKey, error) {
	if jwk.Crv != "Ed25519" {
		return nil, fmt.Errorf("unsupported OKP curve: %s", jwk.Crv)
	}
	xBytes, err := base64URLDecode(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("decoding Ed25519 public key: %w", err)
	}
	if len(xBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key length: %d", len(xBytes))
	}
	return ed25519.PublicKey(xBytes), nil
}

// findKey fetches (or returns cached) JWKS and finds the key matching kid and alg.
func (v *JWTValidator) findKey(jwksURL string, cacheTTL time.Duration, kid, alg string) (*JSONWebKey, error) {
	keys, err := v.getJWKS(jwksURL, cacheTTL)
	if err != nil {
		return nil, err
	}

	if key := matchKey(keys, kid, alg); key != nil {
		return key, nil
	}

	// If kid was specified but not found, try refreshing the cache (key rotation).
	v.mu.Lock()
	delete(v.cache, jwksURL)
	v.mu.Unlock()

	keys, err = v.getJWKS(jwksURL, cacheTTL)
	if err != nil {
		return nil, err
	}

	if key := matchKey(keys, kid, alg); key != nil {
		return key, nil
	}

	return nil, fmt.Errorf("no matching key found for kid=%q alg=%q", kid, alg)
}

func matchKey(keys []JSONWebKey, kid, alg string) *JSONWebKey {
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
		return k
	}
	return nil
}

// getJWKS returns cached JWKS keys or fetches them from the URL.
func (v *JWTValidator) getJWKS(jwksURL string, cacheTTL time.Duration) ([]JSONWebKey, error) {
	v.mu.RLock()
	if c, ok := v.cache[jwksURL]; ok && time.Since(c.fetchedAt) < c.ttl {
		v.mu.RUnlock()
		return c.keys, nil
	}
	v.mu.RUnlock()

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

	v.mu.Lock()
	v.cache[jwksURL] = &jwksCache{
		keys:      jwks.Keys,
		fetchedAt: time.Now(),
		ttl:       cacheTTL,
	}
	v.mu.Unlock()

	return jwks.Keys, nil
}

func (v *JWTValidator) reject(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"code":"auth_failed","status":%d,"message":%q}`, status, message)
}

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

func base64URLDecode(s string) ([]byte, error) {
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}
