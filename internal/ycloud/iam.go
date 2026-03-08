// Package ycloud provides shared Yandex Cloud authentication primitives
// used by multiple providers (KMS, Object Storage, etc.).
package ycloud

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
	"golang.org/x/sync/singleflight"

	"github.com/ledatu/csar/internal/logging"
)

// AuthConfig is the shared authentication configuration for Yandex Cloud services.
type AuthConfig struct {
	// AuthMode selects the credential source:
	// "static", "iam_token", "oauth_token", "metadata", "service_account".
	AuthMode string

	// IAMToken is a static IAM bearer token (dev/testing).
	IAMToken logging.Secret

	// OAuthToken is a Yandex OAuth token exchanged for IAM tokens at runtime.
	OAuthToken logging.Secret

	// SAKeyFile is the path to a service-account key JSON file.
	SAKeyFile string

	// Static credentials (for S3-compatible APIs).
	AccessKeyID     logging.Secret
	SecretAccessKey logging.Secret
}

// IAMTokenResolver resolves Yandex Cloud IAM tokens with caching and
// automatic refresh. It is safe for concurrent use.
//
// Supported auth modes: iam_token, oauth_token, metadata, service_account.
type IAMTokenResolver struct {
	mu        sync.RWMutex
	authToken string
	expiry    time.Time

	authMode    string
	oauthToken  string
	metadataURL string

	// service_account key material (loaded once at construction).
	saID        string
	saAccountID string
	saPrivKey   *rsa.PrivateKey

	client *http.Client

	// sf collapses concurrent refresh requests into a single HTTP call.
	// This prevents the write lock from being held for the entire duration
	// of the network call (50-200ms), which would block all readers.
	sf singleflight.Group
}

// NewIAMTokenResolver creates a resolver for the given auth config.
// For "static" mode, returns nil (no IAM token needed).
func NewIAMTokenResolver(cfg AuthConfig, client *http.Client) (*IAMTokenResolver, error) {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	r := &IAMTokenResolver{
		authMode:    cfg.AuthMode,
		oauthToken:  cfg.OAuthToken.Plaintext(),
		metadataURL: "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token",
		client:      client,
	}

	switch cfg.AuthMode {
	case "iam_token":
		if cfg.IAMToken.IsEmpty() {
			return nil, fmt.Errorf("ycloud: auth_mode=iam_token requires a non-empty iam_token")
		}
		r.authToken = cfg.IAMToken.Plaintext()

	case "oauth_token":
		if cfg.OAuthToken.IsEmpty() {
			return nil, fmt.Errorf("ycloud: auth_mode=oauth_token requires a non-empty oauth_token")
		}

	case "metadata":
		// Token will be fetched on first call.

	case "service_account":
		if cfg.SAKeyFile == "" {
			return nil, fmt.Errorf("ycloud: auth_mode=service_account requires a non-empty sa_key_file")
		}
		saKey, err := LoadSAKey(cfg.SAKeyFile)
		if err != nil {
			return nil, fmt.Errorf("ycloud: load sa_key_file: %w", err)
		}
		r.saID = saKey.ID
		r.saAccountID = saKey.ServiceAccountID
		r.saPrivKey = saKey.PrivateKey

	default:
		return nil, fmt.Errorf("ycloud: unsupported auth_mode %q; supported: iam_token, oauth_token, metadata, service_account", cfg.AuthMode)
	}

	return r, nil
}

// ResolveToken returns a valid IAM token, refreshing it if necessary.
func (r *IAMTokenResolver) ResolveToken(ctx context.Context) (string, error) {
	r.mu.RLock()
	tok := r.authToken
	exp := r.expiry
	r.mu.RUnlock()

	// Static iam_token mode — no expiry.
	if r.authMode == "iam_token" {
		return tok, nil
	}

	// If token is valid and not expiring soon, reuse it.
	if tok != "" && time.Now().Add(30*time.Second).Before(exp) {
		return tok, nil
	}

	return r.refreshToken(ctx)
}

// refreshResult holds the token + expiry returned by a singleflight refresh.
type refreshResult struct {
	token  string
	expiry time.Time
}

// refreshToken obtains a new IAM token based on the configured auth mode.
//
// Uses singleflight to collapse concurrent refresh requests into a single
// HTTP call. The write lock is only held briefly to update the cached token
// after the network call completes, so readers (ResolveToken callers) are
// never blocked for the duration of the HTTP round-trip.
func (r *IAMTokenResolver) refreshToken(ctx context.Context) (string, error) {
	// Quick check: another goroutine may have already refreshed.
	r.mu.RLock()
	if r.authToken != "" && time.Now().Add(30*time.Second).Before(r.expiry) {
		tok := r.authToken
		r.mu.RUnlock()
		return tok, nil
	}
	r.mu.RUnlock()

	// Use singleflight to perform the HTTP call without holding any lock.
	// All concurrent callers will share the result of a single network call.
	res, err, _ := r.sf.Do("refresh", func() (interface{}, error) {
		// Double-check inside singleflight (may have been refreshed by a
		// previous singleflight call that just completed).
		r.mu.RLock()
		if r.authToken != "" && time.Now().Add(30*time.Second).Before(r.expiry) {
			tok := r.authToken
			r.mu.RUnlock()
			return refreshResult{token: tok, expiry: r.expiry}, nil
		}
		r.mu.RUnlock()

		var tok string
		var exp time.Time
		var refreshErr error

		switch r.authMode {
		case "oauth_token":
			tok, exp, refreshErr = r.exchangeOAuthToken(ctx)
		case "metadata":
			tok, exp, refreshErr = r.fetchMetadataToken(ctx)
		case "service_account":
			tok, exp, refreshErr = r.exchangeSAToken(ctx)
		default:
			return nil, fmt.Errorf("ycloud: cannot refresh token for auth_mode=%q", r.authMode)
		}

		if refreshErr != nil {
			return nil, refreshErr
		}

		// Briefly acquire write lock to update the cached token.
		r.mu.Lock()
		r.authToken = tok
		r.expiry = exp
		r.mu.Unlock()

		return refreshResult{token: tok, expiry: exp}, nil
	})

	if err != nil {
		return "", err
	}

	return res.(refreshResult).token, nil
}

// exchangeOAuthToken exchanges a Yandex OAuth token for an IAM token.
//
// POST https://iam.api.cloud.yandex.net/iam/v1/tokens
// Body: { "yandexPassportOauthToken": "<oauth_token>" }
func (r *IAMTokenResolver) exchangeOAuthToken(ctx context.Context) (string, time.Time, error) {
	payload := map[string]string{
		"yandexPassportOauthToken": r.oauthToken,
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://iam.api.cloud.yandex.net/iam/v1/tokens",
		bytes.NewReader(body))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("ycloud: build IAM token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("ycloud: IAM token exchange HTTP: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", time.Time{}, fmt.Errorf("ycloud: IAM token exchange: HTTP %d: %s", resp.StatusCode, string(b))
	}

	var result iamTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", time.Time{}, fmt.Errorf("ycloud: decode IAM token response: %w", err)
	}

	expiry := result.ExpiresAt
	if expiry.IsZero() {
		expiry = time.Now().Add(11 * time.Hour)
	}

	return result.IAMToken, expiry, nil
}

// fetchMetadataToken obtains an IAM token from the instance metadata service.
//
// GET http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
// Header: Metadata-Flavor: Google
func (r *IAMTokenResolver) fetchMetadataToken(ctx context.Context) (string, time.Time, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.metadataURL, nil)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("ycloud: build metadata request: %w", err)
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := r.client.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("ycloud: metadata HTTP: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", time.Time{}, fmt.Errorf("ycloud: metadata token: HTTP %d: %s", resp.StatusCode, string(b))
	}

	var result metadataTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", time.Time{}, fmt.Errorf("ycloud: decode metadata token: %w", err)
	}

	expiry := time.Now().Add(time.Duration(result.ExpiresIn) * time.Second)
	return result.AccessToken, expiry, nil
}

// exchangeSAToken mints a JWT signed with the service-account private key
// and exchanges it for a Yandex IAM token.
func (r *IAMTokenResolver) exchangeSAToken(ctx context.Context) (string, time.Time, error) {
	jwt, err := r.mintSAJWT()
	if err != nil {
		return "", time.Time{}, fmt.Errorf("ycloud: mint SA JWT: %w", err)
	}

	payload := map[string]string{"jwt": jwt}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://iam.api.cloud.yandex.net/iam/v1/tokens",
		bytes.NewReader(body))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("ycloud: build SA token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("ycloud: SA token exchange HTTP: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", time.Time{}, fmt.Errorf("ycloud: SA token exchange: HTTP %d: %s", resp.StatusCode, string(b))
	}

	var result iamTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", time.Time{}, fmt.Errorf("ycloud: decode SA token response: %w", err)
	}

	expiry := result.ExpiresAt
	if expiry.IsZero() {
		expiry = time.Now().Add(11 * time.Hour)
	}

	return result.IAMToken, expiry, nil
}

// mintSAJWT creates and signs a JWT for the Yandex IAM token endpoint.
//
//	Header:  { "typ": "JWT", "alg": "PS256", "kid": "<key_id>" }
//	Payload: { "iss": "<service_account_id>",
//	           "aud": "https://iam.api.cloud.yandex.net/iam/v1/tokens",
//	           "iat": <now>, "exp": <now+60> }
func (r *IAMTokenResolver) mintSAJWT() (string, error) {
	now := time.Now()
	claims := jwtlib.MapClaims{
		"iss": r.saAccountID,
		"aud": jwtlib.ClaimStrings{"https://iam.api.cloud.yandex.net/iam/v1/tokens"},
		"iat": jwtlib.NewNumericDate(now),
		"exp": jwtlib.NewNumericDate(now.Add(60 * time.Second)),
	}
	tok := jwtlib.NewWithClaims(jwtlib.SigningMethodPS256, claims)
	tok.Header["kid"] = r.saID

	signed, err := tok.SignedString(r.saPrivKey)
	if err != nil {
		return "", fmt.Errorf("sign SA JWT: %w", err)
	}
	return signed, nil
}

// ---------------------------------------------------------------------------
// Service-account key file
// ---------------------------------------------------------------------------

// SAKey holds parsed Yandex Cloud service-account key material.
type SAKey struct {
	ID               string
	ServiceAccountID string
	PrivateKey       *rsa.PrivateKey
}

// saKeyJSON mirrors the JSON structure of a Yandex Cloud service-account key file.
type saKeyJSON struct {
	ID               string `json:"id"`
	ServiceAccountID string `json:"service_account_id"`
	PrivateKey       string `json:"private_key"` // PEM-encoded PKCS#8 RSA private key
}

// LoadSAKey reads and parses a Yandex Cloud service-account key JSON file.
func LoadSAKey(path string) (*SAKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	var k saKeyJSON
	if err := json.Unmarshal(data, &k); err != nil {
		return nil, fmt.Errorf("parse JSON: %w", err)
	}

	if k.ID == "" {
		return nil, fmt.Errorf("missing \"id\" field")
	}
	if k.ServiceAccountID == "" {
		return nil, fmt.Errorf("missing \"service_account_id\" field")
	}
	if k.PrivateKey == "" {
		return nil, fmt.Errorf("missing \"private_key\" field")
	}

	block, _ := pem.Decode([]byte(k.PrivateKey))
	if block == nil {
		return nil, fmt.Errorf("private_key: not a valid PEM block")
	}

	var rsaKey *rsa.PrivateKey
	keyIface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Fallback: try PKCS#1 ("BEGIN RSA PRIVATE KEY").
		rsaKey, err2 := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("private_key: parse PKCS#8: %w; parse PKCS#1: %v", err, err2)
		}
		return &SAKey{
			ID:               k.ID,
			ServiceAccountID: k.ServiceAccountID,
			PrivateKey:       rsaKey,
		}, nil
	}

	rsaKey, ok := keyIface.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private_key: expected RSA key, got %T", keyIface)
	}
	_ = rsaKey // used below

	return &SAKey{
		ID:               k.ID,
		ServiceAccountID: k.ServiceAccountID,
		PrivateKey:       rsaKey,
	}, nil
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

// iamTokenResponse is the Yandex IAM token exchange response.
type iamTokenResponse struct {
	IAMToken  string    `json:"iamToken"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// metadataTokenResponse is the instance metadata token response.
type metadataTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
	TokenType   string `json:"token_type"`
}
