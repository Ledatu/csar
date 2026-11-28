package main

import (
	"log/slog"
	"net/http"
	"strings"

	responsecompress "github.com/ledatu/csar-core/httpx/compress"
)

// Wrap the reloadable router, not individual attempts or cache fills. The cache
// retains upstream bytes; redaction finishes before fallback content encoding.
func withResponseGzip(next http.Handler, enabled bool, logger *slog.Logger) http.Handler {
	if !enabled {
		return next
	}
	logger.Info("negotiated JSON response gzip enabled", "min_bytes", 1024)
	compressed := responsecompress.Gzip(next, responsecompress.Options{OnError: func(err error) { logger.Warn("finalizing gzip response", "error", err) }})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Internal service hops should not pay to encode plain upstream
		// JSON only for a nearby service to decode it. Preserve upstream gzip
		// negotiation and pass-through, including cached encoded responses.
		if r.URL.Path == "/svc" || strings.HasPrefix(r.URL.Path, "/svc/") {
			next.ServeHTTP(w, r)
			return
		}
		compressed.ServeHTTP(w, r)
	})
}
