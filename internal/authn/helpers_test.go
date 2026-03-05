package authn

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
	"regexp"
	"strings"
	"testing"
	"time"
)

// Duration is a helper for test config — maps to time.Duration.
type Duration = time.Duration

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
