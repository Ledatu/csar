package middleware

import (
	"context"
	"fmt"
	"os"

	"github.com/ledatu/csar/internal/kms"
	"gopkg.in/yaml.v3"
)

// TokenFileEntry represents a single token in the token file.
type TokenFileEntry struct {
	// Plaintext is the raw secret token value (will be encrypted at load time).
	Plaintext string `yaml:"plaintext"`

	// KMSKeyID is the KMS key used to encrypt/decrypt this token.
	KMSKeyID string `yaml:"kms_key_id"`
}

// TokenFile is the format of the --token-file YAML file.
// Keys are token_ref names (e.g. "my_api_token").
type TokenFile map[string]TokenFileEntry

// LoadTokenFile reads a YAML token file, encrypts each token using the KMS provider,
// and returns a populated StaticTokenFetcher ready for use.
//
// Token file format:
//
//	my_api_token:
//	  plaintext: "my-api-key-here"
//	  kms_key_id: "key-1"
//	orders_token:
//	  plaintext: "another-key"
//	  kms_key_id: "key-2"
func LoadTokenFile(path string, provider kms.Provider) (*StaticTokenFetcher, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading token file %s: %w", path, err)
	}

	var entries TokenFile
	if err := yaml.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("parsing token file %s: %w", path, err)
	}

	if len(entries) == 0 {
		return nil, fmt.Errorf("token file %s contains no token entries", path)
	}

	fetcher := NewStaticTokenFetcher()
	ctx := context.Background()

	for ref, entry := range entries {
		if entry.Plaintext == "" {
			return nil, fmt.Errorf("token file: token_ref %q has empty plaintext", ref)
		}
		if entry.KMSKeyID == "" {
			return nil, fmt.Errorf("token file: token_ref %q has empty kms_key_id", ref)
		}

		// Encrypt the plaintext at startup so the runtime pipeline
		// (fetch encrypted → decrypt → inject) works identically to production.
		encrypted, err := provider.Encrypt(ctx, entry.KMSKeyID, []byte(entry.Plaintext))
		if err != nil {
			return nil, fmt.Errorf("token file: encrypting token_ref %q with kms_key_id %q: %w",
				ref, entry.KMSKeyID, err)
		}

		fetcher.Add(ref, encrypted, entry.KMSKeyID)
	}

	return fetcher, nil
}
