package router

import (
	"net/http"

	responsecompress "github.com/ledatu/csar-core/httpx/compress"
	"github.com/ledatu/csar/internal/config"
)

func (r *Router) responseCompression(policy *config.ResponseCompressionConfig) func(http.Handler) http.Handler {
	enabled, minBytes := r.defaultResponseGzip, 1024
	if policy != nil {
		enabled = policy.Mode == "gzip"
		if policy.MinBytes != 0 {
			minBytes = int(policy.MinBytes)
		}
	}
	if !enabled {
		return nil
	}
	if r.compressionWrappers == nil {
		r.compressionWrappers = make(map[int]func(http.Handler) http.Handler)
	}
	if wrapper := r.compressionWrappers[minBytes]; wrapper != nil {
		return wrapper
	}
	// Pool by encoder configuration, not route or request, including when the
	// legacy global opt-in enables many routes. No live policy state is mutated.
	wrapper := responsecompress.GzipMiddleware(responsecompress.Options{MinBytes: minBytes, OnError: func(err error) { r.logger.Warn("finalizing gzip response", "error", err) }})
	r.compressionWrappers[minBytes] = wrapper
	return wrapper
}
