package main

import (
	"log/slog"
	"net/http"

	responsecompress "github.com/ledatu/csar-core/httpx/compress"
)

// Wrap the reloadable router, not individual attempts or cache fills. The cache
// retains upstream bytes; redaction finishes before fallback content encoding.
func withResponseGzip(next http.Handler, enabled bool, logger *slog.Logger) http.Handler {
	if !enabled {
		return next
	}
	logger.Info("negotiated JSON response gzip enabled", "min_bytes", 1024)
	return responsecompress.Gzip(next, responsecompress.Options{OnError: func(err error) { logger.Warn("finalizing gzip response", "error", err) }})
}
