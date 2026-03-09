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
	"time"

	"github.com/ledatu/csar-core/secret"
	"github.com/ledatu/csar-core/ycloud"
)

// Default Yandex Cloud KMS base endpoint for the SymmetricCrypto REST API.
// Encrypt and Decrypt append "/{keyId}:encrypt" / "/{keyId}:decrypt" at call time.
//
// Reference: https://yandex.cloud/en/docs/kms/api-ref/SymmetricCrypto/
const defaultYandexKMSEndpoint = "https://kms.yandex/kms/v1/keys"

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
	resolver *ycloud.IAMTokenResolver
}

// YandexAPIConfig holds constructor parameters for YandexAPIProvider.
type YandexAPIConfig struct {
	// Endpoint is the KMS API base URL (default: https://kms.api.cloud.yandex.net/kms/v1/keys).
	Endpoint string

	// AuthMode selects the credential source:
	// "iam_token", "oauth_token", "metadata", "service_account".
	AuthMode string

	// IAMToken is a static IAM bearer token (for dev/testing).
	// Uses logging.Secret to prevent accidental logging of the plaintext value.
	IAMToken secret.Secret

	// OAuthToken is a Yandex OAuth token exchanged for IAM tokens at runtime.
	// Uses logging.Secret to prevent accidental logging of the plaintext value.
	OAuthToken secret.Secret

	// SAKeyFile is the path to a service-account key JSON file.
	// Required when AuthMode == "service_account".
	// Download from Yandex Cloud Console → Service Accounts → Keys → Create API key.
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

	httpClient := &http.Client{Timeout: timeout}

	resolver, err := ycloud.NewIAMTokenResolver(&ycloud.AuthConfig{
		AuthMode:   cfg.AuthMode,
		IAMToken:   cfg.IAMToken,
		OAuthToken: cfg.OAuthToken,
		SAKeyFile:  cfg.SAKeyFile,
	}, httpClient)
	if err != nil {
		return nil, fmt.Errorf("yandexapi: %w", err)
	}

	return &YandexAPIProvider{
		endpoint: endpoint,
		client:   httpClient,
		resolver: resolver,
	}, nil
}

// Name returns the provider identifier.
func (p *YandexAPIProvider) Name() string { return "yandexapi" }

// Health checks connectivity by resolving an IAM token.
// This validates that authentication is working without performing
// an actual encrypt/decrypt operation.
func (p *YandexAPIProvider) Health(ctx context.Context) error {
	_, err := p.resolver.ResolveToken(ctx)
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
	token, err := p.resolver.ResolveToken(ctx)
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
	token, err := p.resolver.ResolveToken(ctx)
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
