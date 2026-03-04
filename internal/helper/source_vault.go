package helper

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// VaultSourceConfig configures the Vault / HTTP API source adapter.
type VaultSourceConfig struct {
	// Vault-specific
	VaultAddr  string // e.g. "http://127.0.0.1:8200"
	VaultToken string // Vault token for authentication
	VaultPath  string // path within the mount, e.g. "csar/tokens"
	VaultMount string // KV mount, default "secret"

	// Generic HTTP source
	HTTPURL     string   // direct HTTP URL (alternative to Vault)
	HTTPHeaders []string // repeatable headers in "Key: Value" format
	JQPath      string   // dot-separated path to extract tokens map from JSON response
}

// VaultSource reads tokens from HashiCorp Vault or a generic HTTP API.
type VaultSource struct {
	cfg VaultSourceConfig
}

// NewVaultSource creates a new Vault/HTTP source adapter.
func NewVaultSource(cfg VaultSourceConfig) *VaultSource {
	if cfg.VaultMount == "" {
		cfg.VaultMount = "secret"
	}
	return &VaultSource{cfg: cfg}
}

// Load fetches tokens from Vault or HTTP API.
func (s *VaultSource) Load(ctx context.Context) (map[string]TokenData, error) {
	if s.cfg.HTTPURL != "" {
		return s.loadHTTP(ctx)
	}
	if s.cfg.VaultAddr != "" {
		return s.loadVault(ctx)
	}
	return nil, fmt.Errorf("vault source: either --vault-addr or --http-url is required")
}

// loadVault fetches tokens from Vault KV v2.
func (s *VaultSource) loadVault(ctx context.Context) (map[string]TokenData, error) {
	// Build the Vault KV v2 data URL
	url := fmt.Sprintf("%s/v1/%s/data/%s",
		strings.TrimRight(s.cfg.VaultAddr, "/"),
		s.cfg.VaultMount,
		strings.TrimLeft(s.cfg.VaultPath, "/"),
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("vault source: creating request: %w", err)
	}
	req.Header.Set("X-Vault-Token", s.cfg.VaultToken)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vault source: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("vault source: unexpected status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("vault source: reading response: %w", err)
	}

	// Vault KV v2 response: { "data": { "data": { "key": "value" } } }
	var vaultResp struct {
		Data struct {
			Data map[string]interface{} `json:"data"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &vaultResp); err != nil {
		return nil, fmt.Errorf("vault source: parsing response: %w", err)
	}

	result := make(map[string]TokenData, len(vaultResp.Data.Data))
	for ref, val := range vaultResp.Data.Data {
		tokenStr, ok := val.(string)
		if !ok {
			return nil, fmt.Errorf("vault source: token %q is not a string", ref)
		}
		result[ref] = TokenData{Plaintext: tokenStr}
	}

	return result, nil
}

// loadHTTP fetches tokens from a generic HTTP API.
func (s *VaultSource) loadHTTP(ctx context.Context) (map[string]TokenData, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.HTTPURL, nil)
	if err != nil {
		return nil, fmt.Errorf("http source: creating request: %w", err)
	}

	for _, h := range s.cfg.HTTPHeaders {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http source: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("http source: unexpected status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("http source: reading response: %w", err)
	}

	// Parse JSON response
	var raw interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("http source: parsing response: %w", err)
	}

	// Navigate JQ-style path if specified
	if s.cfg.JQPath != "" {
		raw, err = navigateJQPath(raw, s.cfg.JQPath)
		if err != nil {
			return nil, fmt.Errorf("http source: navigating path %q: %w", s.cfg.JQPath, err)
		}
	}

	// Extract tokens from the result
	tokenMap, ok := raw.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("http source: expected JSON object with token_ref keys, got %T", raw)
	}

	result := make(map[string]TokenData, len(tokenMap))
	for ref, val := range tokenMap {
		tokenStr, ok := val.(string)
		if !ok {
			return nil, fmt.Errorf("http source: token %q is not a string", ref)
		}
		result[ref] = TokenData{Plaintext: tokenStr}
	}

	return result, nil
}

// navigateJQPath navigates a dot-separated path through a JSON structure.
// e.g. "data.tokens" navigates {"data": {"tokens": {...}}} to the inner map.
func navigateJQPath(data interface{}, path string) (interface{}, error) {
	parts := strings.Split(path, ".")
	current := data
	for _, part := range parts {
		if part == "" {
			continue
		}
		m, ok := current.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("expected object at %q, got %T", part, current)
		}
		next, exists := m[part]
		if !exists {
			return nil, fmt.Errorf("key %q not found", part)
		}
		current = next
	}
	return current, nil
}
