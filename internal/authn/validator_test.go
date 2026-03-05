package authn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

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
