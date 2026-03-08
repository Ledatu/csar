package helper

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/ledatu/csar/internal/s3store"
)

// S3SourceConfig configures the S3 source adapter.
type S3SourceConfig struct {
	// Client is the pre-configured S3 client.
	Client *s3store.Client

	// KMSMode controls how token objects are interpreted:
	// "passthrough" — objects contain plaintext tokens.
	// "kms" — objects contain pre-encrypted ciphertext + kms_key_id.
	KMSMode string
}

// S3Source reads tokens from S3-compatible object storage.
type S3Source struct {
	client  *s3store.Client
	kmsMode string
}

// NewS3Source creates a new S3 source adapter.
func NewS3Source(cfg S3SourceConfig) *S3Source {
	if cfg.KMSMode == "" {
		cfg.KMSMode = "kms"
	}
	return &S3Source{
		client:  cfg.Client,
		kmsMode: cfg.KMSMode,
	}
}

// Load fetches all token objects from S3 and returns them as TokenData.
func (s *S3Source) Load(ctx context.Context) (map[string]TokenData, error) {
	objects, err := s.client.ListObjects(ctx)
	if err != nil {
		return nil, fmt.Errorf("s3 source: %w", err)
	}

	result := make(map[string]TokenData, len(objects))
	for _, obj := range objects {
		tokenObj, err := s3store.ParseTokenObject(obj.Body)
		if err != nil {
			return nil, fmt.Errorf("s3 source: token %q: %w", obj.TokenRef, err)
		}

		switch s.kmsMode {
		case "passthrough":
			if tokenObj.Plaintext == "" {
				return nil, fmt.Errorf("s3 source: token %q: passthrough mode requires \"plaintext\" field", obj.TokenRef)
			}
			result[obj.TokenRef] = TokenData{
				Plaintext: tokenObj.Plaintext,
			}

		case "kms":
			if tokenObj.EncryptedToken == "" {
				return nil, fmt.Errorf("s3 source: token %q: kms mode requires \"enc_token\" field", obj.TokenRef)
			}
			decoded, err := base64.StdEncoding.DecodeString(tokenObj.EncryptedToken)
			if err != nil {
				return nil, fmt.Errorf("s3 source: token %q: invalid base64 in enc_token: %w", obj.TokenRef, err)
			}
			result[obj.TokenRef] = TokenData{
				EncryptedToken: decoded,
				KMSKeyID:       tokenObj.KMSKeyID,
			}

		default:
			return nil, fmt.Errorf("s3 source: unknown kms_mode %q", s.kmsMode)
		}
	}

	return result, nil
}
