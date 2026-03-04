package helper

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// EnvSourceConfig configures the environment variable source adapter.
type EnvSourceConfig struct {
	Prefix string // e.g. "TOKEN_" — matches TOKEN_my_api=secret123
}

// EnvSource reads tokens from environment variables matching a prefix.
// The token_ref is derived from the env var name by stripping the prefix
// and lowercasing.
//
// Example: Prefix = "TOKEN_"
//
//	TOKEN_my_api=secret123  →  token_ref="my_api", plaintext="secret123"
//	TOKEN_OTHER=foo         →  token_ref="other",  plaintext="foo"
type EnvSource struct {
	cfg EnvSourceConfig
}

// NewEnvSource creates a new environment variable source adapter.
func NewEnvSource(cfg EnvSourceConfig) *EnvSource {
	return &EnvSource{cfg: cfg}
}

// Load reads environment variables matching the prefix and returns tokens.
func (s *EnvSource) Load(_ context.Context) (map[string]TokenData, error) {
	if s.cfg.Prefix == "" {
		return nil, fmt.Errorf("env source: --env-prefix is required")
	}

	result := make(map[string]TokenData)
	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key, value := parts[0], parts[1]
		if !strings.HasPrefix(key, s.cfg.Prefix) {
			continue
		}
		ref := strings.ToLower(strings.TrimPrefix(key, s.cfg.Prefix))
		if ref == "" {
			continue
		}
		result[ref] = TokenData{Plaintext: value}
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("env source: no environment variables found with prefix %q", s.cfg.Prefix)
	}

	return result, nil
}
