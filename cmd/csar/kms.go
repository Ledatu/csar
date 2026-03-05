package main

import (
	"fmt"
	"strings"

	"github.com/ledatu/csar/internal/config"
	"github.com/ledatu/csar/internal/kms"
	"github.com/ledatu/csar/internal/logging"
)

// initKMSProvider creates a KMS provider based on the resolved provider name.
func initKMSProvider(provider, localKeys string, cfg *config.Config,
	yandexEndpoint, yandexAuthMode, yandexIAMToken, yandexOAuthToken string,
) (kms.Provider, error) {
	switch provider {
	case "local":
		keys := localKeys
		if keys == "" && cfg.KMS != nil && len(cfg.KMS.LocalKeys) > 0 {
			return kms.NewLocalProvider(cfg.KMS.LocalKeys)
		}
		if keys == "" {
			return nil, fmt.Errorf("--kms-local-keys is required when --kms-provider=local " +
				"(format: \"keyID1=passphrase1,keyID2=passphrase2\")")
		}
		passphrases, err := parseLocalKeys(keys)
		if err != nil {
			return nil, err
		}
		return kms.NewLocalProvider(passphrases)

	case "yandexapi":
		yCfg := kms.YandexAPIConfig{
			Endpoint:   yandexEndpoint,
			AuthMode:   yandexAuthMode,
			IAMToken:   logging.NewSecret(yandexIAMToken),
			OAuthToken: logging.NewSecret(yandexOAuthToken),
		}
		// Merge with YAML config if present.
		if cfg.KMS != nil && cfg.KMS.Yandex != nil {
			y := cfg.KMS.Yandex
			if yCfg.Endpoint == "" {
				yCfg.Endpoint = y.Endpoint
			}
			if yCfg.AuthMode == "metadata" && y.AuthMode != "" {
				yCfg.AuthMode = y.AuthMode
			}
			if yCfg.IAMToken.IsEmpty() {
				yCfg.IAMToken = y.IAMToken
			}
			if yCfg.OAuthToken.IsEmpty() {
				yCfg.OAuthToken = y.OAuthToken
			}
		}
		if cfg.KMS != nil && cfg.KMS.OperationTimeout.Duration > 0 {
			yCfg.Timeout = cfg.KMS.OperationTimeout.Duration
		}
		return kms.NewYandexAPIProvider(yCfg)

	case "yandex":
		return nil, fmt.Errorf("--kms-provider=yandex is deprecated; use --kms-provider=yandexapi instead")

	default:
		return nil, fmt.Errorf("unknown KMS provider %q; supported: \"local\", \"yandexapi\"", provider)
	}
}

// parseLocalKeys parses "key1=pass1,key2=pass2" into a map.
func parseLocalKeys(raw string) (map[string]string, error) {
	result := make(map[string]string)
	for _, pair := range strings.Split(raw, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return nil, fmt.Errorf("invalid key=passphrase pair: %q (expected format: keyID=passphrase)", pair)
		}
		result[parts[0]] = parts[1]
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("no valid key=passphrase pairs found in %q", raw)
	}
	return result, nil
}
