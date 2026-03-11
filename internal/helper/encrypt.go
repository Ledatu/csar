package helper

import (
	"context"
	"fmt"

	"github.com/ledatu/csar/internal/kms"
	"github.com/ledatu/csar/internal/logging"
)

// EncryptOptions configures the token encrypt command.
type EncryptOptions struct {
	Plaintext   string
	KMSProvider string            // "local" or "yandexapi"
	KMSKeyID    string            // key ID to use for encryption
	LocalKeys   map[string]string // for local provider: keyID -> passphrase

	// Yandex KMS options (used when KMSProvider == "yandexapi")
	YandexEndpoint   string
	YandexAuthMode   string
	YandexIAMToken   string
	YandexOAuthToken string
}

// EncryptToken encrypts a single plaintext token using the specified KMS provider.
// Returns the encrypted bytes.
func EncryptToken(ctx context.Context, opts EncryptOptions) ([]byte, error) {
	provider, err := initProvider(opts.KMSProvider, opts.LocalKeys, &opts)
	if err != nil {
		return nil, err
	}
	defer provider.Close()

	encrypted, err := provider.Encrypt(ctx, opts.KMSKeyID, []byte(opts.Plaintext))
	if err != nil {
		return nil, fmt.Errorf("encrypting token: %w", err)
	}

	return encrypted, nil
}

// initProvider creates a KMS provider from the given name and config.
// The encryptOpts parameter is optional and provides Yandex KMS configuration
// when called from EncryptToken. For Migrate flows, pass nil and set yandex
// fields separately.
func initProvider(providerName string, localKeys map[string]string, encryptOpts *EncryptOptions) (kms.Provider, error) {
	switch providerName {
	case "local":
		if len(localKeys) == 0 {
			return nil, fmt.Errorf("local KMS provider requires at least one key passphrase")
		}
		return kms.NewLocalProvider(localKeys)

	case "yandexapi":
		if encryptOpts == nil {
			return nil, fmt.Errorf("yandexapi KMS provider requires Yandex configuration options")
		}
		authMode := encryptOpts.YandexAuthMode
		if authMode == "" {
			authMode = "metadata"
		}
		yCfg := kms.YandexAPIConfig{
			Endpoint:   encryptOpts.YandexEndpoint,
			AuthMode:   authMode,
			IAMToken:   logging.NewSecret(encryptOpts.YandexIAMToken),
			OAuthToken: logging.NewSecret(encryptOpts.YandexOAuthToken),
		}
		return kms.NewYandexAPIProvider(yCfg)

	default:
		return nil, fmt.Errorf("unsupported KMS provider %q; supported: \"local\", \"yandexapi\"", providerName)
	}
}
