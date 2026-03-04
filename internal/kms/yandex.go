package kms

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ledatu/csar/internal/logging"
)

// Default Yandex Cloud KMS endpoint for SymmetricCrypto REST API.
// The SymmetricCrypto service (encrypt/decrypt) uses the same base as SymmetricKey CRUD.
//
// Encrypt:  POST {endpoint}/{keyId}:encrypt
// Decrypt:  POST {endpoint}/{keyId}:decrypt
//
// Reference: https://yandex.cloud/en/docs/kms/api-ref/SymmetricCrypto/
const defaultYandexKMSEndpoint = "https://kms.api.cloud.yandex.net/kms/v1/keys"

// YandexAPIProvider implements Provider by calling the Yandex Cloud KMS
// symmetric crypto REST API directly over HTTPS — no go-sdk dependency.
//
// API reference:
//
//	POST  {endpoint}/{keyId}:encrypt   →  { "plaintext": "<base64>" }
//	POST  {endpoint}/{keyId}:decrypt   →  { "ciphertext": "<base64>" }
type YandexAPIProvider struct {
	endpoint string // e.g. "https://kms.api.cloud.yandex.net/kms/v1/keys"
	client   *http.Client

	// Token management — supports multiple auth modes.
	mu        sync.RWMutex
	authToken string // current IAM token

	// For token refresh (metadata / oauth flows).
	authMode      string // "iam_token" | "oauth_token" | "metadata"
	oauthToken    string // cached OAuth token for exchange
	tokenExpiry   time.Time
	metadataURL   string // instance metadata endpoint
	saKeyFile     string // service-account key file path (not used yet, reserved)
}

// YandexAPIConfig holds constructor parameters for YandexAPIProvider.
type YandexAPIConfig struct {
	// Endpoint is the KMS API base URL (default: https://kms.api.cloud.yandex.net/kms/v1/keys).
	Endpoint string

	// AuthMode selects the credential source: "iam_token", "oauth_token", "metadata".
	AuthMode string

	// IAMToken is a static IAM bearer token (for dev/testing).
	// Uses logging.Secret to prevent accidental logging of the plaintext value.
	IAMToken logging.Secret

	// OAuthToken is a Yandex OAuth token exchanged for IAM tokens at runtime.
	// Uses logging.Secret to prevent accidental logging of the plaintext value.
	OAuthToken logging.Secret

	// SAKeyFile is the path to a service-account key JSON file (reserved).
	SAKeyFile string

	// Timeout caps each HTTP request to the KMS API.
	Timeout time.Duration
}

// NewYandexAPIProvider creates a working Yandex Cloud KMS provider.
// It calls the REST API directly and does NOT require go-sdk.
func NewYandexAPIProvider(cfg YandexAPIConfig) (*YandexAPIProvider, error) {
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = defaultYandexKMSEndpoint
	}
	endpoint = strings.TrimRight(endpoint, "/")

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	p := &YandexAPIProvider{
		endpoint: endpoint,
		client: &http.Client{
			Timeout: timeout,
		},
		authMode:    cfg.AuthMode,
		oauthToken:  cfg.OAuthToken.Plaintext(),
		saKeyFile:   cfg.SAKeyFile,
		metadataURL: "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token",
	}

	switch cfg.AuthMode {
	case "iam_token":
		if cfg.IAMToken.IsEmpty() {
			return nil, fmt.Errorf("yandexapi: auth_mode=iam_token requires a non-empty iam_token")
		}
		p.authToken = cfg.IAMToken.Plaintext()

	case "oauth_token":
		if cfg.OAuthToken.IsEmpty() {
			return nil, fmt.Errorf("yandexapi: auth_mode=oauth_token requires a non-empty oauth_token")
		}
		// IAM token will be obtained on first API call.

	case "metadata":
		// IAM token will be obtained from the instance metadata service.

	default:
		return nil, fmt.Errorf("yandexapi: unsupported auth_mode %q; supported: iam_token, oauth_token, metadata", cfg.AuthMode)
	}

	return p, nil
}

// Name returns the provider identifier.
func (p *YandexAPIProvider) Name() string { return "yandexapi" }

// Health checks connectivity by resolving an IAM token.
// This validates that authentication is working without performing
// an actual encrypt/decrypt operation.
func (p *YandexAPIProvider) Health(ctx context.Context) error {
	_, err := p.resolveToken(ctx)
	if err != nil {
		return fmt.Errorf("yandexapi health: %w", err)
	}
	return nil
}

// Encrypt encrypts plaintext using Yandex Cloud KMS symmetric encryption.
//
// REST API:  POST {endpoint}/{keyId}:encrypt
// Body:     { "plaintext": "<base64>" }
// Response: { "keyId": "...", "ciphertext": "<base64>", "versionId": "..." }
func (p *YandexAPIProvider) Encrypt(ctx context.Context, keyID string, plaintext []byte) ([]byte, error) {
	token, err := p.resolveToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("yandexapi encrypt: auth: %w", err)
	}

	reqBody := yandexEncryptRequest{
		Plaintext: base64.StdEncoding.EncodeToString(plaintext),
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("yandexapi encrypt: marshal: %w", err)
	}

	url := fmt.Sprintf("%s/%s:encrypt", p.endpoint, keyID)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("yandexapi encrypt: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+token)

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("yandexapi encrypt: HTTP call: %w", err)
	}
	defer resp.Body.Close()

	if err := checkYandexResponse(resp, "encrypt"); err != nil {
		return nil, err
	}

	var result yandexEncryptResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("yandexapi encrypt: decode response: %w", err)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(result.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("yandexapi encrypt: decode ciphertext base64: %w", err)
	}

	return ciphertext, nil
}

// Decrypt decrypts ciphertext using Yandex Cloud KMS symmetric decryption.
//
// REST API:  POST {endpoint}/{keyId}:decrypt
// Body:     { "ciphertext": "<base64>" }
// Response: { "keyId": "...", "plaintext": "<base64>", "versionId": "..." }
func (p *YandexAPIProvider) Decrypt(ctx context.Context, keyID string, ciphertext []byte) ([]byte, error) {
	token, err := p.resolveToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("yandexapi decrypt: auth: %w", err)
	}

	reqBody := yandexDecryptRequest{
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("yandexapi decrypt: marshal: %w", err)
	}

	url := fmt.Sprintf("%s/%s:decrypt", p.endpoint, keyID)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("yandexapi decrypt: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+token)

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("yandexapi decrypt: HTTP call: %w", err)
	}
	defer resp.Body.Close()

	if err := checkYandexResponse(resp, "decrypt"); err != nil {
		return nil, err
	}

	var result yandexDecryptResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("yandexapi decrypt: decode response: %w", err)
	}

	plaintext, err := base64.StdEncoding.DecodeString(result.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("yandexapi decrypt: decode plaintext base64: %w", err)
	}

	return plaintext, nil
}

// Close releases HTTP transport resources.
func (p *YandexAPIProvider) Close() error {
	p.client.CloseIdleConnections()
	return nil
}

// ---------------------------------------------------------------------------
// Auth token resolution
// ---------------------------------------------------------------------------

// resolveToken returns a valid IAM token, refreshing it if necessary.
func (p *YandexAPIProvider) resolveToken(ctx context.Context) (string, error) {
	p.mu.RLock()
	tok := p.authToken
	exp := p.tokenExpiry
	p.mu.RUnlock()

	// Static iam_token mode — no expiry.
	if p.authMode == "iam_token" {
		return tok, nil
	}

	// If token is valid and not expiring soon, reuse it.
	if tok != "" && time.Now().Add(30*time.Second).Before(exp) {
		return tok, nil
	}

	// Need refresh.
	return p.refreshToken(ctx)
}

// refreshToken obtains a new IAM token based on the configured auth mode.
func (p *YandexAPIProvider) refreshToken(ctx context.Context) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Double-check after acquiring write lock.
	if p.authToken != "" && time.Now().Add(30*time.Second).Before(p.tokenExpiry) {
		return p.authToken, nil
	}

	var tok string
	var exp time.Time
	var err error

	switch p.authMode {
	case "oauth_token":
		tok, exp, err = p.exchangeOAuthToken(ctx)
	case "metadata":
		tok, exp, err = p.fetchMetadataToken(ctx)
	default:
		return "", fmt.Errorf("yandexapi: cannot refresh token for auth_mode=%q", p.authMode)
	}

	if err != nil {
		return "", err
	}

	p.authToken = tok
	p.tokenExpiry = exp
	return tok, nil
}

// exchangeOAuthToken exchanges a Yandex OAuth token for an IAM token
// via the Yandex IAM API.
//
// POST https://iam.api.cloud.yandex.net/iam/v1/tokens
// Body: { "yandexPassportOauthToken": "<oauth_token>" }
func (p *YandexAPIProvider) exchangeOAuthToken(ctx context.Context) (string, time.Time, error) {
	payload := map[string]string{
		"yandexPassportOauthToken": p.oauthToken,
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://iam.api.cloud.yandex.net/iam/v1/tokens",
		bytes.NewReader(body))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("yandexapi: build IAM token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("yandexapi: IAM token exchange HTTP: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", time.Time{}, fmt.Errorf("yandexapi: IAM token exchange: HTTP %d: %s", resp.StatusCode, string(b))
	}

	var result iamTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", time.Time{}, fmt.Errorf("yandexapi: decode IAM token response: %w", err)
	}

	expiry := result.ExpiresAt
	if expiry.IsZero() {
		// Default: IAM tokens are valid for ~12 hours; use a conservative 11h.
		expiry = time.Now().Add(11 * time.Hour)
	}

	return result.IAMToken, expiry, nil
}

// fetchMetadataToken obtains an IAM token from the instance metadata service.
//
// GET http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
// Header: Metadata-Flavor: Google
func (p *YandexAPIProvider) fetchMetadataToken(ctx context.Context) (string, time.Time, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.metadataURL, nil)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("yandexapi: build metadata request: %w", err)
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := p.client.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("yandexapi: metadata HTTP: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", time.Time{}, fmt.Errorf("yandexapi: metadata token: HTTP %d: %s", resp.StatusCode, string(b))
	}

	var result metadataTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", time.Time{}, fmt.Errorf("yandexapi: decode metadata token: %w", err)
	}

	expiry := time.Now().Add(time.Duration(result.ExpiresIn) * time.Second)
	return result.AccessToken, expiry, nil
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

// Yandex KMS encrypt request.
type yandexEncryptRequest struct {
	Plaintext string `json:"plaintext"` // base64-encoded
}

// Yandex KMS encrypt response.
type yandexEncryptResponse struct {
	KeyID      string `json:"keyId"`
	VersionID  string `json:"versionId"`
	Ciphertext string `json:"ciphertext"` // base64-encoded
}

// Yandex KMS decrypt request.
type yandexDecryptRequest struct {
	Ciphertext string `json:"ciphertext"` // base64-encoded
}

// Yandex KMS decrypt response.
type yandexDecryptResponse struct {
	KeyID     string `json:"keyId"`
	VersionID string `json:"versionId"`
	Plaintext string `json:"plaintext"` // base64-encoded
}

// IAM token exchange response.
type iamTokenResponse struct {
	IAMToken  string    `json:"iamToken"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// Instance metadata token response.
type metadataTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"` // seconds
	TokenType   string `json:"token_type"`
}

// Yandex API error response body.
type yandexErrorResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// checkYandexResponse inspects the HTTP response and returns a typed error
// suitable for retry/circuit-breaker classification.
func checkYandexResponse(resp *http.Response, op string) error {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))

	// Try to parse Yandex error JSON for a better message.
	var ye yandexErrorResponse
	if json.Unmarshal(b, &ye) == nil && ye.Message != "" {
		return fmt.Errorf("yandexapi %s: HTTP %d: %s (code %d)", op, resp.StatusCode, ye.Message, ye.Code)
	}

	return fmt.Errorf("yandexapi %s: HTTP %d: %s", op, resp.StatusCode, string(b))
}
