// Package cors provides Cross-Origin Resource Sharing middleware for CSAR.
//
// When configured on a route, the middleware automatically:
//   - Handles preflight OPTIONS requests with appropriate CORS headers.
//   - Injects CORS response headers into normal requests.
//   - Validates the Origin header against the configured allowlist.
//
// Recommended by feature audit §3.2 (Criticism 5).
package cors

import (
	"net/http"
	"strconv"
	"strings"
)

// Config configures CORS behavior for a route.
type Config struct {
	// AllowedOrigins is the list of allowed origins. "*" allows all.
	AllowedOrigins []string

	// AllowedMethods is the list of allowed HTTP methods.
	AllowedMethods []string

	// AllowedHeaders is the list of allowed request headers.
	AllowedHeaders []string

	// ExposedHeaders is the list of headers exposed to the browser.
	ExposedHeaders []string

	// AllowCredentials indicates whether cookies/auth are allowed.
	AllowCredentials bool

	// MaxAge is the time (in seconds) a preflight response can be cached.
	MaxAge int

	// RequestIDHeader is the header name used for request ID tracing.
	// Defaults to "X-Request-ID" when empty.
	RequestIDHeader string
}

// Middleware handles CORS headers and preflight requests.
type Middleware struct{}

// New creates a new CORS Middleware.
func New() *Middleware {
	return &Middleware{}
}

// Wrap returns an http.Handler that applies CORS headers and handles preflight.
func (m *Middleware) Wrap(cfg Config, next http.Handler) http.Handler {
	// Apply defaults.
	if len(cfg.AllowedMethods) == 0 {
		cfg.AllowedMethods = []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"}
	}
	if len(cfg.AllowedHeaders) == 0 {
		cfg.AllowedHeaders = []string{"Content-Type", "Authorization"}
	}
	if cfg.MaxAge <= 0 {
		cfg.MaxAge = 86400 // 24 hours
	}

	// Always expose CSAR backpressure headers so browser-based clients
	// (csar-ts SDK) can read them from cross-origin responses.
	reqIDHeader := cfg.RequestIDHeader
	if reqIDHeader == "" {
		reqIDHeader = "X-Request-ID"
	}
	csarHeaders := []string{"X-CSAR-Wait-MS", "X-CSAR-Status", "Retry-After", "X-CSAR-Protocol-Version", reqIDHeader, "X-CSAR-Route-ID"}
	exposed := dedupHeaders(append(cfg.ExposedHeaders, csarHeaders...))

	// Pre-compute header values.
	allowMethodsStr := strings.Join(cfg.AllowedMethods, ", ")
	allowHeadersStr := strings.Join(cfg.AllowedHeaders, ", ")
	exposeHeadersStr := strings.Join(exposed, ", ")
	maxAgeStr := strconv.Itoa(cfg.MaxAge)

	// Build origin lookup set for fast matching.
	allowAll := false
	originSet := make(map[string]bool, len(cfg.AllowedOrigins))
	for _, o := range cfg.AllowedOrigins {
		if o == "*" {
			allowAll = true
		}
		originSet[o] = true
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		// If no Origin header, this is not a CORS request — pass through.
		if origin == "" {
			next.ServeHTTP(w, r)
			return
		}

		// Check if origin is allowed.
		allowed := allowAll || originSet[origin]
		if !allowed {
			// Origin not allowed — still process the request but don't add CORS headers.
			next.ServeHTTP(w, r)
			return
		}

		// Set the appropriate Origin header.
		if allowAll && !cfg.AllowCredentials {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		} else {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
		}

		if cfg.AllowCredentials {
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}

		if exposeHeadersStr != "" {
			w.Header().Set("Access-Control-Expose-Headers", exposeHeadersStr)
		}

		// Handle preflight OPTIONS request.
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Methods", allowMethodsStr)
			w.Header().Set("Access-Control-Allow-Headers", allowHeadersStr)
			w.Header().Set("Access-Control-Max-Age", maxAgeStr)
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// Normal request — proxy to the next handler.
		next.ServeHTTP(w, r)
	})
}

// dedupHeaders returns the input slice with duplicate header names removed
// (case-insensitive). The first occurrence wins.
func dedupHeaders(headers []string) []string {
	seen := make(map[string]bool, len(headers))
	out := make([]string, 0, len(headers))
	for _, h := range headers {
		key := strings.ToLower(h)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, h)
	}
	return out
}
