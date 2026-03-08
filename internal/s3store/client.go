// Package s3store provides a client for reading token objects from
// S3-compatible object storage (e.g. Yandex Cloud Object Storage).
//
// Two authentication modes are supported:
//   - "static": AWS Signature V4 via access_key_id + secret_access_key.
//   - IAM-based ("iam_token", "oauth_token", "metadata", "service_account"):
//     Uses Yandex Cloud IAM tokens with the X-YaCloud-SubjectToken header.
package s3store

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/ledatu/csar/internal/ycloud"
)

// Config holds all S3 client configuration.
type Config struct {
	// Bucket name.
	Bucket string

	// Endpoint is the S3-compatible API endpoint
	// (e.g. "https://storage.yandexcloud.net").
	Endpoint string

	// Region for AWS Signature V4 signing (e.g. "ru-central1").
	Region string

	// Prefix is the key prefix for token objects.
	// Object key = Prefix + token_ref (e.g. "tokens/" + "my_api_token").
	Prefix string

	// Auth configures authentication.
	Auth ycloud.AuthConfig
}

// ObjectEntry represents a single S3 object with its token data.
type ObjectEntry struct {
	TokenRef string // derived from key (prefix stripped)
	Body     []byte // raw object contents (JSON)
	ETag     string // S3 ETag (used as Version for change detection)
}

// Client provides access to token objects in S3-compatible storage.
type Client struct {
	// For static auth: aws-sdk-go-v2 S3 client.
	s3Client *s3.Client

	// For IAM-based auth: raw HTTP with X-YaCloud-SubjectToken.
	iamAuth    bool
	resolver   *ycloud.IAMTokenResolver
	httpClient *http.Client

	cfg    Config
	logger *slog.Logger
}

// NewClient creates an S3 client configured for the given storage backend.
func NewClient(cfg Config, logger *slog.Logger) (*Client, error) {
	if cfg.Bucket == "" {
		return nil, fmt.Errorf("s3store: bucket is required")
	}
	if cfg.Endpoint == "" {
		cfg.Endpoint = "https://storage.yandexcloud.net"
	}
	if cfg.Region == "" {
		cfg.Region = "ru-central1"
	}

	c := &Client{
		cfg:    cfg,
		logger: logger,
	}

	switch cfg.Auth.AuthMode {
	case "static", "":
		if cfg.Auth.AccessKeyID.IsEmpty() || cfg.Auth.SecretAccessKey.IsEmpty() {
			return nil, fmt.Errorf("s3store: static auth requires access_key_id and secret_access_key")
		}

		s3Client := s3.New(s3.Options{
			BaseEndpoint: aws.String(cfg.Endpoint),
			Region:       cfg.Region,
			Credentials: credentials.NewStaticCredentialsProvider(
				cfg.Auth.AccessKeyID.Plaintext(),
				cfg.Auth.SecretAccessKey.Plaintext(),
				"",
			),
			UsePathStyle: true,
		})
		c.s3Client = s3Client

	case "iam_token", "oauth_token", "metadata", "service_account":
		resolver, err := ycloud.NewIAMTokenResolver(cfg.Auth, nil)
		if err != nil {
			return nil, fmt.Errorf("s3store: %w", err)
		}
		c.iamAuth = true
		c.resolver = resolver
		c.httpClient = &http.Client{Timeout: 30 * time.Second}

	default:
		return nil, fmt.Errorf("s3store: unsupported auth_mode %q", cfg.Auth.AuthMode)
	}

	return c, nil
}

// ListObjects lists all token objects under the configured prefix and
// fetches their contents. Handles S3 pagination (1000 objects per page).
func (c *Client) ListObjects(ctx context.Context) ([]ObjectEntry, error) {
	if c.iamAuth {
		return c.listObjectsIAM(ctx)
	}
	return c.listObjectsSDK(ctx)
}

// GetObject fetches a single token object by token_ref.
// Returns the object body, ETag, and any error.
func (c *Client) GetObject(ctx context.Context, tokenRef string) (ObjectEntry, error) {
	key := c.cfg.Prefix + tokenRef
	if c.iamAuth {
		return c.getObjectIAM(ctx, key, tokenRef)
	}
	return c.getObjectSDK(ctx, key, tokenRef)
}

// Close releases resources.
func (c *Client) Close() error {
	if c.httpClient != nil {
		c.httpClient.CloseIdleConnections()
	}
	return nil
}

// ---------------------------------------------------------------------------
// aws-sdk-go-v2 (static auth) implementation
// ---------------------------------------------------------------------------

func (c *Client) listObjectsSDK(ctx context.Context) ([]ObjectEntry, error) {
	var entries []ObjectEntry
	var continuationToken *string

	for {
		input := &s3.ListObjectsV2Input{
			Bucket:            aws.String(c.cfg.Bucket),
			Prefix:            aws.String(c.cfg.Prefix),
			ContinuationToken: continuationToken,
		}

		resp, err := c.s3Client.ListObjectsV2(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("s3store: list objects: %w", err)
		}

		for _, obj := range resp.Contents {
			if obj.Key == nil {
				continue
			}
			tokenRef := strings.TrimPrefix(*obj.Key, c.cfg.Prefix)
			if tokenRef == "" {
				continue // skip the prefix key itself
			}

			entry, err := c.getObjectSDK(ctx, *obj.Key, tokenRef)
			if err != nil {
				c.logger.Warn("s3store: skipping object due to fetch error",
					"key", *obj.Key, "error", err)
				continue
			}
			entries = append(entries, entry)
		}

		if resp.IsTruncated == nil || !*resp.IsTruncated {
			break
		}
		continuationToken = resp.NextContinuationToken
	}

	return entries, nil
}

func (c *Client) getObjectSDK(ctx context.Context, key, tokenRef string) (ObjectEntry, error) {
	resp, err := c.s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(c.cfg.Bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return ObjectEntry{}, fmt.Errorf("s3store: get object %q: %w", key, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ObjectEntry{}, fmt.Errorf("s3store: read object %q: %w", key, err)
	}

	etag := ""
	if resp.ETag != nil {
		etag = *resp.ETag
	}

	return ObjectEntry{
		TokenRef: tokenRef,
		Body:     body,
		ETag:     etag,
	}, nil
}

// ---------------------------------------------------------------------------
// Raw HTTP (IAM auth) implementation
// ---------------------------------------------------------------------------

// listObjectsIAM lists objects using the S3 REST API with IAM token auth.
func (c *Client) listObjectsIAM(ctx context.Context) ([]ObjectEntry, error) {
	var entries []ObjectEntry
	continuationToken := ""

	for {
		objects, nextToken, err := c.listPageIAM(ctx, continuationToken)
		if err != nil {
			return nil, err
		}

		for _, obj := range objects {
			tokenRef := strings.TrimPrefix(obj.Key, c.cfg.Prefix)
			if tokenRef == "" {
				continue
			}

			entry, err := c.getObjectIAM(ctx, obj.Key, tokenRef)
			if err != nil {
				c.logger.Warn("s3store: skipping object due to fetch error",
					"key", obj.Key, "error", err)
				continue
			}
			entries = append(entries, entry)
		}

		if nextToken == "" {
			break
		}
		continuationToken = nextToken
	}

	return entries, nil
}

// listPageIAM fetches one page of ListObjectsV2 via raw HTTP.
func (c *Client) listPageIAM(ctx context.Context, continuationToken string) ([]s3ListObject, string, error) {
	token, err := c.resolver.ResolveToken(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("s3store: auth: %w", err)
	}

	params := url.Values{
		"list-type": {"2"},
		"prefix":    {c.cfg.Prefix},
	}
	if continuationToken != "" {
		params.Set("continuation-token", continuationToken)
	}

	reqURL := fmt.Sprintf("%s/%s?%s", c.cfg.Endpoint, c.cfg.Bucket, params.Encode())

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("s3store: build list request: %w", err)
	}
	req.Header.Set("X-YaCloud-SubjectToken", token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("s3store: list HTTP: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, "", fmt.Errorf("s3store: list: HTTP %d: %s", resp.StatusCode, string(b))
	}

	var result s3ListBucketResult
	if err := xml.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, "", fmt.Errorf("s3store: decode list response: %w", err)
	}

	nextToken := ""
	if result.IsTruncated {
		nextToken = result.NextContinuationToken
	}

	return result.Contents, nextToken, nil
}

// getObjectIAM fetches a single object via raw HTTP with IAM auth.
func (c *Client) getObjectIAM(ctx context.Context, key, tokenRef string) (ObjectEntry, error) {
	token, err := c.resolver.ResolveToken(ctx)
	if err != nil {
		return ObjectEntry{}, fmt.Errorf("s3store: auth: %w", err)
	}

	reqURL := fmt.Sprintf("%s/%s/%s", c.cfg.Endpoint, c.cfg.Bucket, key)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return ObjectEntry{}, fmt.Errorf("s3store: build get request: %w", err)
	}
	req.Header.Set("X-YaCloud-SubjectToken", token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return ObjectEntry{}, fmt.Errorf("s3store: get %q HTTP: %w", key, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return ObjectEntry{}, fmt.Errorf("s3store: object %q not found", key)
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return ObjectEntry{}, fmt.Errorf("s3store: get %q: HTTP %d: %s", key, resp.StatusCode, string(b))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ObjectEntry{}, fmt.Errorf("s3store: read %q: %w", key, err)
	}

	etag := resp.Header.Get("ETag")

	return ObjectEntry{
		TokenRef: tokenRef,
		Body:     body,
		ETag:     etag,
	}, nil
}

// ---------------------------------------------------------------------------
// S3 XML response types (for IAM-based raw HTTP)
// ---------------------------------------------------------------------------

type s3ListBucketResult struct {
	XMLName               xml.Name       `xml:"ListBucketResult"`
	IsTruncated           bool           `xml:"IsTruncated"`
	NextContinuationToken string         `xml:"NextContinuationToken"`
	Contents              []s3ListObject `xml:"Contents"`
}

type s3ListObject struct {
	Key  string `xml:"Key"`
	ETag string `xml:"ETag"`
}
