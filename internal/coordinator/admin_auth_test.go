package coordinator

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ledatu/csar/internal/authn"
)

func TestAdminAuthMiddleware_AllowedKMSKeys_Array(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	jwk := testRSAKeyToJWK(&key.PublicKey, "admin-key-1")

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := struct {
			Keys []map[string]string `json:"keys"`
		}{
			Keys: []map[string]string{{
				"kty": jwk.Kty, "kid": jwk.Kid, "alg": jwk.Alg,
				"use": jwk.Use, "n": jwk.N, "e": jwk.E,
			}},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer jwksServer.Close()

	token := testSignJWT(
		map[string]interface{}{"alg": "RS256", "kid": "admin-key-1", "typ": "JWT"},
		map[string]interface{}{
			"sub":              "admin@example.com",
			"iss":              "test-issuer",
			"aud":              "csar-coordinator-admin",
			"exp":              float64(time.Now().Add(time.Hour).Unix()),
			"scope":            "admin",
			"tenant":           "acme",
			"token_prefix":     "acme/",
			"allowed_kms_keys": []interface{}{"key-alpha", "key-beta", "key-gamma"},
		},
		key,
	)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	validator := authn.NewJWTValidator(logger, nil)

	cfg := AdminAuthConfig{
		JWKSUrl:   jwksServer.URL,
		Issuer:    "test-issuer",
		Audiences: []string{"csar-coordinator-admin"},
	}

	var gotClaims *AdminClaims
	downstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotClaims = AdminClaimsFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	middleware := AdminAuthMiddleware(validator, cfg, logger)
	handler := middleware(downstream)

	req := httptest.NewRequest(http.MethodGet, "/admin/tokens", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		body, _ := io.ReadAll(rec.Body)
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, body)
	}
	if gotClaims == nil {
		t.Fatal("AdminClaims not found in context")
	}

	if gotClaims.Sub != "admin@example.com" {
		t.Errorf("Sub = %q, want %q", gotClaims.Sub, "admin@example.com")
	}
	if gotClaims.Scope != "admin" {
		t.Errorf("Scope = %q, want %q", gotClaims.Scope, "admin")
	}
	if gotClaims.Tenant != "acme" {
		t.Errorf("Tenant = %q, want %q", gotClaims.Tenant, "acme")
	}
	if gotClaims.TokenPrefix != "acme/" {
		t.Errorf("TokenPrefix = %q, want %q", gotClaims.TokenPrefix, "acme/")
	}

	wantKeys := []string{"key-alpha", "key-beta", "key-gamma"}
	if len(gotClaims.AllowedKMSKeys) != len(wantKeys) {
		t.Fatalf("AllowedKMSKeys = %v, want %v", gotClaims.AllowedKMSKeys, wantKeys)
	}
	for i, k := range wantKeys {
		if gotClaims.AllowedKMSKeys[i] != k {
			t.Errorf("AllowedKMSKeys[%d] = %q, want %q", i, gotClaims.AllowedKMSKeys[i], k)
		}
	}

	// Verify that forwarded headers were cleaned up from the request
	// (the downstream handler should not see them).
	if v := req.Header.Get("X-Admin-Allowed-KMS-Keys"); v != "" {
		t.Errorf("X-Admin-Allowed-KMS-Keys header not cleaned up: %q", v)
	}
}

func TestAdminAuthMiddleware_AllowedKMSKeys_CommaSeparated(t *testing.T) {
	keys := parseKMSKeysClaim("key-1, key-2, key-3")
	want := []string{"key-1", "key-2", "key-3"}
	if len(keys) != len(want) {
		t.Fatalf("parseKMSKeysClaim = %v, want %v", keys, want)
	}
	for i, k := range want {
		if keys[i] != k {
			t.Errorf("keys[%d] = %q, want %q", i, keys[i], k)
		}
	}
}

func TestAdminAuthMiddleware_AllowedKMSKeys_JSONArray(t *testing.T) {
	keys := parseKMSKeysClaim(`["key-x","key-y"]`)
	want := []string{"key-x", "key-y"}
	if len(keys) != len(want) {
		t.Fatalf("parseKMSKeysClaim = %v, want %v", keys, want)
	}
	for i, k := range want {
		if keys[i] != k {
			t.Errorf("keys[%d] = %q, want %q", i, keys[i], k)
		}
	}
}

// testSignJWT signs a JWT with the given RSA private key (test helper).
func testSignJWT(header, payload map[string]interface{}, key *rsa.PrivateKey) string {
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

type testJWK struct {
	Kty string
	Kid string
	Alg string
	Use string
	N   string
	E   string
}

// testRSAKeyToJWK converts an RSA public key to JWK fields for testing.
func testRSAKeyToJWK(pub *rsa.PublicKey, kid string) testJWK {
	return testJWK{
		Kty: "RSA",
		Kid: kid,
		Alg: "RS256",
		Use: "sig",
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}
