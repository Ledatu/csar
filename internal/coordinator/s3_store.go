package coordinator

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"strings"

	"github.com/ledatu/csar/internal/s3store"
)

// S3TokenStore implements TokenStore backed by S3-compatible object storage
// (e.g. Yandex Cloud Object Storage).
//
// Each token is stored as a JSON object under a configurable prefix:
//
//	s3://<bucket>/<prefix><token_ref>
//
// Two KMS modes are supported:
//   - "passthrough": Objects contain plaintext tokens (SSE handles encryption
//     at rest). TokenEntry.KMSKeyID is empty, routers skip KMS decryption.
//   - "kms": Objects contain pre-encrypted ciphertext + kms_key_id. Routers
//     decrypt via KMS as usual.
//
// S3 ETags are used as the Version field for change detection by TokenRefresher.
type S3TokenStore struct {
	client  *s3store.Client
	kmsMode string // "passthrough" or "kms"
	logger  *slog.Logger
}

// Compile-time check: S3TokenStore implements TokenStore.
var _ TokenStore = (*S3TokenStore)(nil)

// NewS3TokenStore creates a token store backed by S3.
// kmsMode must be "passthrough" or "kms".
func NewS3TokenStore(client *s3store.Client, kmsMode string, logger *slog.Logger) *S3TokenStore {
	return &S3TokenStore{
		client:  client,
		kmsMode: kmsMode,
		logger:  logger,
	}
}

// LoadAll lists all token objects under the configured prefix, parses their
// JSON bodies, and returns a map suitable for AuthServiceImpl.LoadTokensFromMap.
func (s *S3TokenStore) LoadAll(ctx context.Context) (map[string]TokenEntry, error) {
	objects, err := s.client.ListObjects(ctx)
	if err != nil {
		return nil, fmt.Errorf("s3 token store: list: %w", err)
	}

	entries := make(map[string]TokenEntry, len(objects))
	for _, obj := range objects {
		entry, err := s.parseObject(obj)
		if err != nil {
			s.logger.Warn("s3 token store: skipping malformed object",
				"token_ref", obj.TokenRef,
				"error", err,
			)
			continue
		}
		entries[obj.TokenRef] = entry
	}

	return entries, nil
}

// FetchOne retrieves a single token from S3 by its ref.
// Returns ErrTokenNotFound (wrapped) when the object doesn't exist.
func (s *S3TokenStore) FetchOne(ctx context.Context, tokenRef string) (TokenEntry, error) {
	obj, err := s.client.GetObject(ctx, tokenRef)
	if err != nil {
		// Check for "not found" in the error message from s3store.
		if strings.Contains(err.Error(), "not found") {
			return TokenEntry{}, fmt.Errorf("token ref %q: %w", tokenRef, ErrTokenNotFound)
		}
		return TokenEntry{}, fmt.Errorf("s3 token store: fetch %q: %w", tokenRef, err)
	}

	entry, err := s.parseObject(obj)
	if err != nil {
		return TokenEntry{}, fmt.Errorf("s3 token store: parse %q: %w", tokenRef, err)
	}

	s.logger.Debug("fetched single token from s3",
		"token_ref", tokenRef,
		"version", entry.Version,
	)
	return entry, nil
}

// Close releases S3 client resources.
func (s *S3TokenStore) Close() error {
	return s.client.Close()
}

// parseObject converts an S3 ObjectEntry into a TokenEntry based on kmsMode.
func (s *S3TokenStore) parseObject(obj s3store.ObjectEntry) (TokenEntry, error) {
	tokenObj, err := s3store.ParseTokenObject(obj.Body)
	if err != nil {
		return TokenEntry{}, err
	}

	switch s.kmsMode {
	case "passthrough":
		if tokenObj.Plaintext == "" {
			return TokenEntry{}, fmt.Errorf("passthrough mode requires \"plaintext\" field")
		}
		return TokenEntry{
			EncryptedToken: []byte(tokenObj.Plaintext),
			KMSKeyID:       "", // empty = router skips KMS decrypt
			Version:        obj.ETag,
		}, nil

	case "kms":
		if tokenObj.EncryptedToken == "" {
			return TokenEntry{}, fmt.Errorf("kms mode requires \"enc_token\" field")
		}
		decoded, err := base64.StdEncoding.DecodeString(tokenObj.EncryptedToken)
		if err != nil {
			return TokenEntry{}, fmt.Errorf("invalid base64 in enc_token: %w", err)
		}
		return TokenEntry{
			EncryptedToken: decoded,
			KMSKeyID:       tokenObj.KMSKeyID,
			Version:        obj.ETag,
		}, nil

	default:
		return TokenEntry{}, fmt.Errorf("unknown kms_mode %q", s.kmsMode)
	}
}
