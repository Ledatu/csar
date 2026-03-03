package authn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"
)

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// signJWT signs a JWT with the given RSA private key.
func signJWT(header, payload map[string]interface{}, key *rsa.PrivateKey) string {
	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(payload)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	signingInput := headerB64 + "." + payloadB64
	h := sha256.Sum256([]byte(signingInput))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	return signingInput + "." + sigB64
}

// rsaKeyToJWK converts an RSA public key to a JSONWebKey.
func rsaKeyToJWK(pub *rsa.PublicKey, kid string) JSONWebKey {
	return JSONWebKey{
		Kty: "RSA",
		Kid: kid,
		Alg: "RS256",
		Use: "sig",
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

func TestJWTValidator_ValidToken(t *testing.T) {
	// Generate RSA key pair
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	jwk := rsaKeyToJWK(&key.PublicKey, "test-key-1")

	// Start JWKS server
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jwksResponse{Keys: []JSONWebKey{jwk}})
	}))
	defer jwksServer.Close()

	// Create valid JWT
	token := signJWT(
		map[string]interface{}{"alg": "RS256", "kid": "test-key-1", "typ": "JWT"},
		map[string]interface{}{
			"sub": "user123",
			"iss": "test-issuer",
			"aud": "test-audience",
			"exp": float64(time.Now().Add(time.Hour).Unix()),
		},
		key,
	)

	validator := NewJWTValidator(newTestLogger())

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := validator.Wrap(Config{
		JWKSURL:   jwksServer.URL,
		Issuer:    "test-issuer",
		Audiences: []string{"test-audience"},
	}, next)

	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if !nextCalled {
		t.Error("next handler was not called")
	}
}

func TestJWTValidator_MissingToken(t *testing.T) {
	validator := NewJWTValidator(newTestLogger())
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called")
	})

	handler := validator.Wrap(Config{JWKSURL: "http://unused"}, next)

	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestJWTValidator_ExpiredToken(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwk := rsaKeyToJWK(&key.PublicKey, "test-key-1")

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jwksResponse{Keys: []JSONWebKey{jwk}})
	}))
	defer jwksServer.Close()

	// Create expired JWT
	token := signJWT(
		map[string]interface{}{"alg": "RS256", "kid": "test-key-1", "typ": "JWT"},
		map[string]interface{}{
			"sub": "user123",
			"exp": float64(time.Now().Add(-time.Hour).Unix()),
		},
		key,
	)

	validator := NewJWTValidator(newTestLogger())
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called for expired token")
	})

	handler := validator.Wrap(Config{JWKSURL: jwksServer.URL}, next)

	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestJWTValidator_WrongIssuer(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwk := rsaKeyToJWK(&key.PublicKey, "test-key-1")

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jwksResponse{Keys: []JSONWebKey{jwk}})
	}))
	defer jwksServer.Close()

	token := signJWT(
		map[string]interface{}{"alg": "RS256", "kid": "test-key-1", "typ": "JWT"},
		map[string]interface{}{
			"sub": "user123",
			"iss": "wrong-issuer",
			"exp": float64(time.Now().Add(time.Hour).Unix()),
		},
		key,
	)

	validator := NewJWTValidator(newTestLogger())
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next should not be called")
	})

	handler := validator.Wrap(Config{
		JWKSURL: jwksServer.URL,
		Issuer:  "expected-issuer",
	}, next)

	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestJWTValidator_AlgNone_Rejected(t *testing.T) {
	// Build a token with alg=none (no signature)
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"attacker","exp":99999999999}`))
	token := header + "." + payload + "."

	validator := NewJWTValidator(newTestLogger())
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next should not be called for alg=none")
	})

	handler := validator.Wrap(Config{JWKSURL: "http://unused"}, next)

	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestJWTValidator_ForwardClaims(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwk := rsaKeyToJWK(&key.PublicKey, "test-key-1")

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jwksResponse{Keys: []JSONWebKey{jwk}})
	}))
	defer jwksServer.Close()

	token := signJWT(
		map[string]interface{}{"alg": "RS256", "kid": "test-key-1", "typ": "JWT"},
		map[string]interface{}{
			"sub":   "user456",
			"email": "user@example.com",
			"exp":   float64(time.Now().Add(time.Hour).Unix()),
		},
		key,
	)

	validator := NewJWTValidator(newTestLogger())

	var capturedSub, capturedEmail string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedSub = r.Header.Get("X-User-ID")
		capturedEmail = r.Header.Get("X-User-Email")
		w.WriteHeader(http.StatusOK)
	})

	handler := validator.Wrap(Config{
		JWKSURL: jwksServer.URL,
		ForwardClaims: map[string]string{
			"sub":   "X-User-ID",
			"email": "X-User-Email",
		},
	}, next)

	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if capturedSub != "user456" {
		t.Errorf("X-User-ID = %q, want %q", capturedSub, "user456")
	}
	if capturedEmail != "user@example.com" {
		t.Errorf("X-User-Email = %q, want %q", capturedEmail, "user@example.com")
	}
}

func TestJWTValidator_RequiredClaims(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwk := rsaKeyToJWK(&key.PublicKey, "test-key-1")

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jwksResponse{Keys: []JSONWebKey{jwk}})
	}))
	defer jwksServer.Close()

	// Token with wrong role
	token := signJWT(
		map[string]interface{}{"alg": "RS256", "kid": "test-key-1", "typ": "JWT"},
		map[string]interface{}{
			"sub":  "user123",
			"role": "viewer",
			"exp":  float64(time.Now().Add(time.Hour).Unix()),
		},
		key,
	)

	validator := NewJWTValidator(newTestLogger())
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next should not be called")
	})

	handler := validator.Wrap(Config{
		JWKSURL:        jwksServer.URL,
		RequiredClaims: map[string]string{"role": "admin"},
	}, next)

	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestJWTValidator_ECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	jwk := JSONWebKey{
		Kty: "EC",
		Kid: "ec-key-1",
		Alg: "ES256",
		Use: "sig",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(key.PublicKey.X.Bytes()),
		Y:   base64.RawURLEncoding.EncodeToString(key.PublicKey.Y.Bytes()),
	}

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jwksResponse{Keys: []JSONWebKey{jwk}})
	}))
	defer jwksServer.Close()

	// Sign with ECDSA
	headerJSON, _ := json.Marshal(map[string]interface{}{"alg": "ES256", "kid": "ec-key-1", "typ": "JWT"})
	payloadJSON, _ := json.Marshal(map[string]interface{}{
		"sub": "ec-user",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	})

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := headerB64 + "." + payloadB64

	h := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		t.Fatal(err)
	}

	// Encode as r||s (fixed length per RFC 7518)
	keySize := (key.Curve.Params().BitSize + 7) / 8
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	sigBytes := make([]byte, 2*keySize)
	copy(sigBytes[keySize-len(rBytes):keySize], rBytes)
	copy(sigBytes[2*keySize-len(sBytes):], sBytes)

	token := signingInput + "." + base64.RawURLEncoding.EncodeToString(sigBytes)

	validator := NewJWTValidator(newTestLogger())
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := validator.Wrap(Config{JWKSURL: jwksServer.URL}, next)

	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		body, _ := io.ReadAll(rec.Result().Body)
		t.Errorf("status = %d, want 200; body = %s", rec.Code, body)
	}
	if !nextCalled {
		t.Error("next handler was not called")
	}
}

func TestJWTValidator_JWKSCaching(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwk := rsaKeyToJWK(&key.PublicKey, "test-key-1")

	fetchCount := 0
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount++
		json.NewEncoder(w).Encode(jwksResponse{Keys: []JSONWebKey{jwk}})
	}))
	defer jwksServer.Close()

	validator := NewJWTValidator(newTestLogger())
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := validator.Wrap(Config{
		JWKSURL:  jwksServer.URL,
		CacheTTL: Duration(5 * time.Minute),
	}, next)

	// Send two requests — JWKS should be fetched only once
	for i := 0; i < 2; i++ {
		token := signJWT(
			map[string]interface{}{"alg": "RS256", "kid": "test-key-1", "typ": "JWT"},
			map[string]interface{}{
				"sub": fmt.Sprintf("user%d", i),
				"exp": float64(time.Now().Add(time.Hour).Unix()),
			},
			key,
		)
		req := httptest.NewRequest(http.MethodGet, "/api", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("request %d: status = %d, want 200", i, rec.Code)
		}
	}

	if fetchCount != 1 {
		t.Errorf("JWKS fetched %d times, want 1 (should be cached)", fetchCount)
	}
}

func TestJWTValidator_MalformedToken(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"no dots", "notajwt"},
		{"one part", "header.payload"},
		{"bad base64", "!!!.!!!.!!!"},
	}

	validator := NewJWTValidator(newTestLogger())
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next should not be called")
	})

	handler := validator.Wrap(Config{JWKSURL: "http://unused"}, next)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api", nil)
			authValue := "Bearer " + tt.token
			if tt.token == "" {
				authValue = "Bearer "
			}
			req.Header.Set("Authorization", authValue)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401 for %q", rec.Code, tt.name)
			}
		})
	}
}

// Duration is a helper for test config — maps to time.Duration.
type Duration = time.Duration

func TestBase64URLDecode(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"aGVsbG8", "hello"},
		{"d29ybGQ", "world"},
	}

	for _, tt := range tests {
		got, err := base64URLDecode(tt.input)
		if err != nil {
			t.Errorf("base64URLDecode(%q) error: %v", tt.input, err)
			continue
		}
		if string(got) != tt.expected {
			t.Errorf("base64URLDecode(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestValidateAudience(t *testing.T) {
	tests := []struct {
		name     string
		aud      interface{}
		expected []string
		want     bool
	}{
		{"string match", "api", []string{"api"}, true},
		{"string no match", "other", []string{"api"}, false},
		{"array match", []interface{}{"api", "web"}, []string{"api"}, true},
		{"array no match", []interface{}{"other"}, []string{"api"}, false},
		{"nil", nil, []string{"api"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := validateAudience(tt.aud, tt.expected)
			if got != tt.want {
				t.Errorf("validateAudience = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCompilePathPattern(t *testing.T) {
	tests := []struct {
		path    string
		hasRe   bool
		matches string
		noMatch string
	}{
		{"/api/v1/users/{id:[0-9]+}", true, "/api/v1/users/42", "/api/v1/users/abc"},
		{"/api/{ver:v[0-9]+}/items/{id}", true, "/api/v2/items/foo", "/api/latest/items/foo"},
		{"/plain/path", false, "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			pat, hasRe := compilePathPattern(tt.path)
			if hasRe != tt.hasRe {
				t.Fatalf("hasRegex = %v, want %v", hasRe, tt.hasRe)
			}
			if !hasRe {
				return
			}
			if !pat.MatchString(tt.matches) {
				t.Errorf("pattern %q should match %q", pat, tt.matches)
			}
			if tt.noMatch != "" && pat.MatchString(tt.noMatch) {
				t.Errorf("pattern %q should NOT match %q", pat, tt.noMatch)
			}
		})
	}
}

// compilePathPattern is imported from the router package — duplicate here for testing.
// In production, this lives in internal/router/router.go.
func compilePathPattern(path string) (*regexp.Regexp, bool) {
	if !strings.Contains(path, "{") {
		return nil, false
	}
	var b strings.Builder
	b.WriteString("^")
	i := 0
	for i < len(path) {
		brace := strings.IndexByte(path[i:], '{')
		if brace < 0 {
			b.WriteString(regexp.QuoteMeta(path[i:]))
			break
		}
		b.WriteString(regexp.QuoteMeta(path[i : i+brace]))
		rest := path[i+brace:]
		closeBrace := strings.IndexByte(rest, '}')
		if closeBrace < 0 {
			b.WriteString(regexp.QuoteMeta(rest))
			i = len(path)
			break
		}
		varContent := rest[1:closeBrace]
		if colonIdx := strings.IndexByte(varContent, ':'); colonIdx >= 0 {
			b.WriteString("(")
			b.WriteString(varContent[colonIdx+1:])
			b.WriteString(")")
		} else {
			b.WriteString("([^/]+)")
		}
		i += brace + closeBrace + 1
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return nil, false
	}
	return re, true
}
