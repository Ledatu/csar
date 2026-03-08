package configsource

import (
	"context"
	"fmt"

	"github.com/ledatu/csar/internal/s3store"
)

// S3Source loads configuration from an S3-compatible object storage.
// It reuses the existing s3store.Client which supports both static
// (AWS Signature V4) and IAM-based authentication.
type S3Source struct {
	client *s3store.Client
	key    string // full object key (e.g., "configs/routes.yaml")
}

// NewS3Source creates an S3Source that reads a single config object.
//
// The client should be created with an empty Prefix in its Config so that
// the key parameter is used as the full S3 object key. Example:
//
//	client, _ := s3store.NewClient(s3store.Config{Bucket: "my-bucket", Prefix: ""}, logger)
//	src := NewS3Source(client, "configs/routes.yaml")
func NewS3Source(client *s3store.Client, key string) *S3Source {
	return &S3Source{
		client: client,
		key:    key,
	}
}

// Fetch retrieves the config object from S3.
// ETag is the S3 object ETag for change detection.
func (s *S3Source) Fetch(ctx context.Context) (FetchedConfig, error) {
	obj, err := s.client.GetObject(ctx, s.key)
	if err != nil {
		return FetchedConfig{}, fmt.Errorf("fetching config from s3://%s: %w", s.key, err)
	}

	return FetchedConfig{
		Data: obj.Body,
		ETag: obj.ETag,
	}, nil
}
