// Package dlp provides response payload redaction (Data Loss Prevention).
//
// The Redactor middleware intercepts JSON responses from upstream APIs
// and masks specified fields before returning them to the client.
// This prevents PII (Personally Identifiable Information) from leaking
// through the API gateway.
//
// Security audit §2.2 fix: responses are size-limited to prevent memory
// exhaustion (DoS) from unbounded JSON payloads. The middleware uses
// a capped buffer and rejects responses exceeding max_response_size.
//
// Recommended by security audit §3.3.2.
package dlp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
)

// DefaultMaxResponseSize is the default maximum response size for DLP processing (10MB).
const DefaultMaxResponseSize int64 = 10 * 1024 * 1024

// Config configures the DLP redaction middleware.
type Config struct {
	// Fields is a list of JSON field paths to redact.
	// Supports dot notation: "user.email", "data.ssn".
	// Supports wildcards: "users.*.email" redacts email in every array element.
	Fields []string

	// Mask is the replacement string. Default: "***REDACTED***".
	Mask string

	// MaxResponseSize is the maximum response body size (in bytes) that will be
	// buffered for redaction. Responses exceeding this limit are passed through
	// un-redacted with a warning header. Default: 10MB.
	// Set to 0 to use the default. Set to -1 to disable the limit (not recommended).
	MaxResponseSize int64
}

// effectiveMaxSize returns the max response size, applying defaults.
func (c *Config) effectiveMaxSize() int64 {
	if c.MaxResponseSize > 0 {
		return c.MaxResponseSize
	}
	if c.MaxResponseSize == -1 {
		return 0 // unlimited
	}
	return DefaultMaxResponseSize
}

// Redactor is response middleware that masks specified JSON fields.
type Redactor struct {
	logger *slog.Logger
}

// NewRedactor creates a new Redactor.
func NewRedactor(logger *slog.Logger) *Redactor {
	return &Redactor{logger: logger}
}

// Wrap returns middleware that redacts specified fields from JSON responses.
func (rd *Redactor) Wrap(cfg Config, next http.Handler) http.Handler {
	if cfg.Mask == "" {
		cfg.Mask = "***REDACTED***"
	}

	maxSize := cfg.effectiveMaxSize()

	// Pre-parse field paths for efficiency.
	paths := make([][]string, len(cfg.Fields))
	for i, f := range cfg.Fields {
		paths[i] = strings.Split(f, ".")
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Preserve X-CSAR-* and Retry-After headers that were set by earlier
		// pipeline stages (e.g. throttle). Inner handlers (like ReverseProxy)
		// may overwrite the ResponseWriter's header map, so we snapshot these
		// before handing off and restore them before flushing.
		savedCSARHeaders := snapshotCSARHeaders(w.Header())

		// Use a capturing response writer to intercept the response body.
		capture := &captureWriter{
			ResponseWriter: w,
			buf:            &bytes.Buffer{},
			maxSize:        maxSize,
		}

		next.ServeHTTP(capture, r)

		// Restore any X-CSAR-* / Retry-After headers that may have been
		// cleared by the inner handler chain (e.g. httputil.ReverseProxy).
		restoreCSARHeaders(w.Header(), savedCSARHeaders)

		// Check if the response was too large to buffer.
		if capture.overflowed {
			rd.logger.Warn("DLP: response exceeded max_response_size, passed through un-redacted",
				"max_response_size", maxSize,
			)
			// The data has already been discarded by captureWriter.
			// Write original headers and a warning.
			w.Header().Set("X-CSAR-DLP-Warning", "response too large for redaction")
			w.WriteHeader(capture.statusCode)
			// Body was already partially written if overflow happened mid-stream,
			// but since we buffer before writing headers, we return an error instead.
			fmt.Fprintf(w, `{"error":"response too large for DLP processing","max_bytes":%d}`, maxSize)
			return
		}

		body := capture.buf.Bytes()

		// Only redact JSON responses.
		ct := capture.Header().Get("Content-Type")
		if !isJSON(ct) || len(body) == 0 {
			// Write the response as-is.
			w.WriteHeader(capture.statusCode)
			w.Write(body) //nolint:errcheck
			return
		}

		// Parse JSON.
		var data interface{}
		if err := json.Unmarshal(body, &data); err != nil {
			// Not valid JSON — pass through.
			rd.logger.Debug("DLP: response is not valid JSON, skipping redaction",
				"content_type", ct,
			)
			w.WriteHeader(capture.statusCode)
			w.Write(body) //nolint:errcheck
			return
		}

		// Apply redaction.
		redacted := false
		for _, path := range paths {
			if redactPath(data, path, cfg.Mask) {
				redacted = true
			}
		}

		if !redacted {
			// No fields matched — write original body to avoid re-serialization overhead.
			w.WriteHeader(capture.statusCode)
			w.Write(body) //nolint:errcheck
			return
		}

		// Re-serialize.
		redactedBody, err := json.Marshal(data)
		if err != nil {
			rd.logger.Error("DLP: failed to re-serialize redacted response", "error", err)
			w.WriteHeader(capture.statusCode)
			w.Write(body) //nolint:errcheck
			return
		}

		// Update Content-Length and write.
		w.Header().Del("Content-Length")
		w.WriteHeader(capture.statusCode)
		w.Write(redactedBody) //nolint:errcheck

		rd.logger.Debug("DLP: redacted response fields",
			"fields", cfg.Fields,
		)
	})
}

// redactPath walks the data structure along the path and replaces
// the target field with the mask. Returns true if anything was redacted.
func redactPath(data interface{}, path []string, mask string) bool {
	if len(path) == 0 {
		return false
	}

	switch v := data.(type) {
	case map[string]interface{}:
		if len(path) == 1 {
			// Terminal: replace the field value.
			if _, ok := v[path[0]]; ok {
				v[path[0]] = mask
				return true
			}
			// Wildcard at terminal doesn't make sense for objects — skip.
			return false
		}

		key := path[0]
		if key == "*" {
			// Wildcard: apply to all values in the object.
			any := false
			for k := range v {
				if redactPath(v[k], path[1:], mask) {
					any = true
				}
			}
			return any
		}

		child, ok := v[key]
		if !ok {
			return false
		}
		return redactPath(child, path[1:], mask)

	case []interface{}:
		// For arrays, apply the current path segment to each element.
		// If the path segment is "*", consume it and descend.
		// If it's not "*", also descend into each element (implicit array iteration).
		any := false
		nextPath := path
		if path[0] == "*" {
			nextPath = path[1:]
		}
		for i := range v {
			if redactPath(v[i], nextPath, mask) {
				any = true
			}
		}
		return any

	default:
		return false
	}
}

// captureWriter captures the response body and status code with size limiting.
type captureWriter struct {
	http.ResponseWriter
	buf        *bytes.Buffer
	maxSize    int64 // 0 = unlimited
	statusCode int
	written    bool
	overflowed bool
}

func (cw *captureWriter) WriteHeader(code int) {
	cw.statusCode = code
	cw.written = true
	// Don't call the underlying WriteHeader yet — we need to process the body first.
}

func (cw *captureWriter) Write(b []byte) (int, error) {
	if !cw.written {
		cw.statusCode = http.StatusOK
		cw.written = true
	}

	if cw.overflowed {
		return len(b), nil // discard silently after overflow
	}

	// Check size limit before writing.
	if cw.maxSize > 0 {
		if int64(cw.buf.Len())+int64(len(b)) > cw.maxSize {
			cw.overflowed = true
			cw.buf.Reset() // free memory
			return len(b), nil
		}
	}

	return cw.buf.Write(b)
}

// snapshotCSARHeaders returns a copy of all X-CSAR-* and Retry-After headers
// from the given header map. Used to preserve backpressure metadata across
// middleware layers that may clear the header map.
func snapshotCSARHeaders(h http.Header) http.Header {
	snap := make(http.Header)
	for k, vv := range h {
		if strings.HasPrefix(strings.ToUpper(k), "X-CSAR-") || strings.EqualFold(k, "Retry-After") {
			snap[k] = append([]string(nil), vv...)
		}
	}
	return snap
}

// restoreCSARHeaders merges the previously-saved CSAR headers back into the
// header map, but only if they are not already present (inner handlers may
// have set fresh values via ModifyResponse).
func restoreCSARHeaders(dst, saved http.Header) {
	for k, vv := range saved {
		if dst.Get(k) == "" {
			dst[k] = vv
		}
	}
}

// isJSON checks if the content type indicates JSON.
func isJSON(ct string) bool {
	return strings.Contains(ct, "application/json") ||
		strings.Contains(ct, "+json")
}
