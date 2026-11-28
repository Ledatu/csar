package main

import (
	"log/slog"
	"net/http"

	responsecompress "github.com/ledatu/csar-core/httpx/compress"
)

// Exercise explicit middleware negotiation independently of router selection.
// Route policy/default/reload behavior is covered by internal/router tests.
func withResponseGzip(next http.Handler, enabled bool, logger *slog.Logger) http.Handler {
	if !enabled {
		return next
	}
	return responsecompress.Gzip(next, responsecompress.Options{OnError: func(err error) { logger.Warn("finalizing gzip response", "error", err) }})
}
