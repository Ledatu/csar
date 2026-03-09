package coordinator

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/Ledatu/csar-core/s3store"
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

// Compile-time check: S3TokenStore implements MutableTokenStore.
var _ MutableTokenStore = (*S3TokenStore)(nil)

// NewS3TokenStore creates a token store backed by S3.
// kmsMode must be "passthrough" or "kms".
func NewS3TokenStore(client *s3store.Client, kmsMode string, logger *slog.Logger) *S3TokenStore {
	return &S3TokenStore{
		client:  client,
		kmsMode: kmsMode,
		logger:  logger,
	}
}

// LoadAll is intentionally a no-op for the S3 token store. The S3 backend
// uses on-demand fetching exclusively: tokens are fetched individually via
// FetchOne (read-through in AuthServiceImpl) when first requested, rather
// than listing and bulk-fetching all objects from the bucket.
//
// This eliminates the risk of silent data truncation on transient S3 errors
// during listing, avoids unnecessary S3 API calls for tokens that may never
// be needed, and ensures instant coordinator startup.
func (s *S3TokenStore) LoadAll(_ context.Context) (map[string]TokenEntry, error) {
	s.logger.Info("s3 token store: LoadAll is a no-op — tokens are fetched on demand via FetchOne")
	return make(map[string]TokenEntry), nil
}

// FetchOne retrieves a single token from S3 by its ref.
// Returns ErrTokenNotFound (wrapped) when the object doesn't exist.
func (s *S3TokenStore) FetchOne(ctx context.Context, tokenRef string) (TokenEntry, error) {
	obj, err := s.client.GetObject(ctx, tokenRef)
	if err != nil {
		// Detect "not found" from both auth modes:
		// - IAM raw HTTP: error message contains "not found"
		// - AWS SDK (static auth): returns *types.NoSuchKey
		var nsk *types.NoSuchKey
		if strings.Contains(err.Error(), "not found") || errors.As(err, &nsk) {
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

// UpsertToken writes a token entry to S3. The entry is serialized into the
// appropriate JSON format based on kmsMode and written via PutObject.
// Returns the S3 ETag as the version string.
func (s *S3TokenStore) UpsertToken(ctx context.Context, ref string, entry TokenEntry, meta TokenMetadata) (string, error) {
	obj := s3store.TokenObject{
		SchemaVersion: 1,
		UpdatedBy:     meta.UpdatedBy,
		Tenant:        meta.Tenant,
	}

	switch s.kmsMode {
	case "passthrough":
		obj.Plaintext = string(entry.EncryptedToken)
	case "kms":
		obj.EncryptedToken = base64.StdEncoding.EncodeToString(entry.EncryptedToken)
		obj.KMSKeyID = entry.KMSKeyID
	default:
		return "", fmt.Errorf("s3 token store: unknown kms_mode %q", s.kmsMode)
	}

	body, err := s3store.MarshalTokenObject(obj)
	if err != nil {
		return "", fmt.Errorf("s3 token store: marshal %q: %w", ref, err)
	}

	etag, err := s.client.PutObject(ctx, ref, body)
	if err != nil {
		return "", fmt.Errorf("s3 token store: upsert %q: %w", ref, err)
	}

	s.logger.Info("token upserted to s3",
		"token_ref", ref,
		"version", etag,
	)
	return etag, nil
}

// DeleteToken removes a token object from S3.
func (s *S3TokenStore) DeleteToken(ctx context.Context, ref string) error {
	if err := s.client.DeleteObject(ctx, ref); err != nil {
		return fmt.Errorf("s3 token store: delete %q: %w", ref, err)
	}

	s.logger.Info("token deleted from s3", "token_ref", ref)
	return nil
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
			KMSKeyID:       "",
			Passthrough:    true,
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
