package configsource

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// maxConfigSize is the maximum response body size (10 MB).
const maxConfigSize = 10 << 20

// HTTPSource loads configuration from an HTTP(S) endpoint.
// It supports ETag-based conditional fetches to avoid unnecessary transfers.
type HTTPSource struct {
	url        string
	headers    map[string]string // extra headers (e.g., Authorization)
	httpClient *http.Client

	mu       sync.Mutex
	lastETag string
}

// defaultHTTPClient is used when the caller does not supply a client.
// A 30-second total timeout prevents Slowloris-style stalls from permanently
// blocking the config watcher loop.
var defaultHTTPClient = &http.Client{Timeout: 30 * time.Second}

// NewHTTPSource creates an HTTPSource for the given URL.
// Extra headers are sent with every request (e.g., {"Authorization": "Bearer xxx"}).
// If httpClient is nil, a default client with a 30-second timeout is used.
func NewHTTPSource(url string, headers map[string]string, httpClient *http.Client) *HTTPSource {
	if httpClient == nil {
		httpClient = defaultHTTPClient
	}
	return &HTTPSource{
		url:        url,
		headers:    headers,
		httpClient: httpClient,
	}
}

// Fetch performs a GET request with If-None-Match conditional header.
//
// On 200 OK: returns the response body and ETag.
// On 304 Not Modified: returns nil Data with the previous ETag,
// signaling to ConfigWatcher that no update is needed.
func (s *HTTPSource) Fetch(ctx context.Context) (FetchedConfig, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return FetchedConfig{}, fmt.Errorf("creating request for %s: %w", s.url, err)
	}

	// Set extra headers.
	for k, v := range s.headers {
		req.Header.Set(k, v)
	}

	// Conditional fetch: skip download if server returns 304.
	s.mu.Lock()
	if s.lastETag != "" {
		req.Header.Set("If-None-Match", s.lastETag)
	}
	s.mu.Unlock()

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return FetchedConfig{}, fmt.Errorf("fetching config from %s: %w", s.url, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotModified:
		s.mu.Lock()
		etag := s.lastETag
		s.mu.Unlock()
		return FetchedConfig{Data: nil, ETag: etag}, nil

	case http.StatusOK:
		// Read body with size limit.
		limited := io.LimitReader(resp.Body, maxConfigSize+1)
		data, err := io.ReadAll(limited)
		if err != nil {
			return FetchedConfig{}, fmt.Errorf("reading response body from %s: %w", s.url, err)
		}
		if len(data) > maxConfigSize {
			return FetchedConfig{}, fmt.Errorf("config from %s exceeds maximum size (%d bytes)", s.url, maxConfigSize)
		}

		// Determine ETag: prefer ETag header, fall back to Last-Modified.
		etag := resp.Header.Get("ETag")
		if etag == "" {
			etag = resp.Header.Get("Last-Modified")
		}

		s.mu.Lock()
		s.lastETag = etag
		s.mu.Unlock()

		return FetchedConfig{
			Data: data,
			ETag: etag,
		}, nil

	default:
		return FetchedConfig{}, fmt.Errorf("unexpected status %d from %s", resp.StatusCode, s.url)
	}
}
