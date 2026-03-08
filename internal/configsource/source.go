// Package configsource provides pluggable configuration sources for the
// CSAR coordinator. It loads route configuration from external backends
// (file, S3, HTTP), validates it, checks integrity via SHA-256 hashes,
// and applies changes to the coordinator's StateStore.
package configsource

import "context"

// FetchedConfig is the result of loading configuration from a source.
type FetchedConfig struct {
	// Data is the raw YAML configuration bytes.
	// May be nil for HTTP 304 Not Modified responses.
	Data []byte

	// ETag is an opaque version identifier used for change detection.
	// Semantics depend on the source:
	//   - File: "mtime:<unix_nano>:size:<bytes>"
	//   - S3: S3 object ETag
	//   - HTTP: ETag or Last-Modified header value
	ETag string
}

// ConfigSource loads configuration from an external source.
// Implementations must be safe for concurrent use.
type ConfigSource interface {
	// Fetch retrieves the current configuration from the source.
	// Returns the raw YAML bytes and an opaque version identifier (ETag).
	//
	// If the source supports conditional fetches (e.g., HTTP If-None-Match)
	// and the content has not changed, Data may be nil with a non-empty ETag.
	Fetch(ctx context.Context) (FetchedConfig, error)
}
