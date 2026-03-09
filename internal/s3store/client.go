// Package s3store provides a client for reading and writing token objects
// in S3-compatible object storage (e.g. Yandex Cloud Object Storage).
//
// Two authentication modes are supported:
//   - "static": AWS Signature V4 via access_key_id + secret_access_key.
//   - IAM-based ("iam_token", "oauth_token", "metadata", "service_account"):
//     Uses Yandex Cloud IAM tokens with the X-YaCloud-SubjectToken header.
package s3store

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path"
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

// PutObject writes an object to S3 under the configured prefix.
// Returns the ETag of the written object.
func (c *Client) PutObject(ctx context.Context, tokenRef string, body []byte) (string, error) {
	key := c.cfg.Prefix + tokenRef
	if c.iamAuth {
		return c.putObjectIAM(ctx, key, body)
	}
	return c.putObjectSDK(ctx, key, body)
}

// DeleteObject removes an object from S3 by token_ref.
func (c *Client) DeleteObject(ctx context.Context, tokenRef string) error {
	key := c.cfg.Prefix + tokenRef
	if c.iamAuth {
		return c.deleteObjectIAM(ctx, key)
	}
	return c.deleteObjectSDK(ctx, key)
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
				return nil, fmt.Errorf("s3store: fetch object %q: %w", *obj.Key, err)
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

func (c *Client) putObjectSDK(ctx context.Context, key string, body []byte) (string, error) {
	resp, err := c.s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(c.cfg.Bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(body),
		ContentType: aws.String("application/json"),
	})
	if err != nil {
		return "", fmt.Errorf("s3store: put object %q: %w", key, err)
	}

	etag := ""
	if resp.ETag != nil {
		etag = *resp.ETag
	}
	return etag, nil
}

func (c *Client) deleteObjectSDK(ctx context.Context, key string) error {
	_, err := c.s3Client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(c.cfg.Bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return fmt.Errorf("s3store: delete object %q: %w", key, err)
	}
	return nil
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
				return nil, fmt.Errorf("s3store: fetch object %q: %w", obj.Key, err)
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

	bucketBase, err := c.bucketURL()
	if err != nil {
		return nil, "", err
	}

	params := url.Values{
		"list-type": {"2"},
		"prefix":    {c.cfg.Prefix},
	}
	if continuationToken != "" {
		params.Set("continuation-token", continuationToken)
	}

	reqURL := bucketBase + "?" + params.Encode()

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

// objectURL builds a well-formed S3 request URL for the given object key.
//
// Using url.URL avoids the manual escaping pitfalls of fmt.Sprintf string
// concatenation: path.Join normalises slashes, and url.URL.String() re-encodes
// the path components correctly regardless of what the Endpoint string looks like
// (trailing slash, embedded path prefix, etc.).
func (c *Client) objectURL(key string) (string, error) {
	base, err := url.Parse(c.cfg.Endpoint)
	if err != nil {
		return "", fmt.Errorf("s3store: parse endpoint %q: %w", c.cfg.Endpoint, err)
	}
	base.Path = path.Join(base.Path, c.cfg.Bucket, key)
	return base.String(), nil
}

// bucketURL builds the S3 bucket URL used for ListObjectsV2 requests.
func (c *Client) bucketURL() (string, error) {
	base, err := url.Parse(c.cfg.Endpoint)
	if err != nil {
		return "", fmt.Errorf("s3store: parse endpoint %q: %w", c.cfg.Endpoint, err)
	}
	base.Path = path.Join(base.Path, c.cfg.Bucket)
	return base.String(), nil
}

// getObjectIAM fetches a single object via raw HTTP with IAM auth.
func (c *Client) getObjectIAM(ctx context.Context, key, tokenRef string) (ObjectEntry, error) {
	token, err := c.resolver.ResolveToken(ctx)
	if err != nil {
		return ObjectEntry{}, fmt.Errorf("s3store: auth: %w", err)
	}

	reqURL, err := c.objectURL(key)
	if err != nil {
		return ObjectEntry{}, err
	}

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

// putObjectIAM uploads an object via raw HTTP with IAM auth.
func (c *Client) putObjectIAM(ctx context.Context, key string, body []byte) (string, error) {
	token, err := c.resolver.ResolveToken(ctx)
	if err != nil {
		return "", fmt.Errorf("s3store: auth: %w", err)
	}

	reqURL, err := c.objectURL(key)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, reqURL, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("s3store: build put request: %w", err)
	}
	req.Header.Set("X-YaCloud-SubjectToken", token)
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(body))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("s3store: put %q HTTP: %w", key, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return "", fmt.Errorf("s3store: put %q: HTTP %d: %s", key, resp.StatusCode, string(b))
	}

	return resp.Header.Get("ETag"), nil
}

// deleteObjectIAM deletes an object via raw HTTP with IAM auth.
func (c *Client) deleteObjectIAM(ctx context.Context, key string) error {
	token, err := c.resolver.ResolveToken(ctx)
	if err != nil {
		return fmt.Errorf("s3store: auth: %w", err)
	}

	reqURL, err := c.objectURL(key)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, reqURL, nil)
	if err != nil {
		return fmt.Errorf("s3store: build delete request: %w", err)
	}
	req.Header.Set("X-YaCloud-SubjectToken", token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("s3store: delete %q HTTP: %w", key, err)
	}
	defer resp.Body.Close()

	// S3 returns 204 No Content on successful delete.
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("s3store: delete %q: HTTP %d: %s", key, resp.StatusCode, string(b))
	}

	return nil
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
