package authn

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

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
				"sub": "user",
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
