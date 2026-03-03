// Package cache provides HTTP response caching middleware for CSAR.
//
// The ResponseCache middleware caches responses from idempotent methods
// (GET, HEAD by default), respecting standard HTTP caching headers
// (Cache-Control, ETag, Last-Modified).
//
// Features:
//   - In-memory LRU cache with configurable max entries and TTL.
//   - Respects Cache-Control: no-cache, no-store, max-age, private.
//   - ETag-based conditional requests (If-None-Match → 304 Not Modified).
//   - Size-limited: responses larger than max_body_size are not cached.
//
// Recommended by feature audit §3.2 (Criticism 4).
package cache

import (
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultTTL is the default cache TTL when no Cache-Control header is present.
const DefaultTTL = 5 * time.Minute

// DefaultMaxEntries is the default maximum number of cached responses.
const DefaultMaxEntries = 1000

// DefaultMaxBodySize is the default maximum body size to cache (1MB).
const DefaultMaxBodySize int64 = 1 * 1024 * 1024

// Config configures the response cache for a single route.
type Config struct {
	// TTL is the default cache TTL if no Cache-Control header is present.
	TTL time.Duration

	// MaxEntries is the maximum number of cached responses (LRU eviction).
	MaxEntries int

	// MaxBodySize is the maximum response body size to cache.
	MaxBodySize int64

	// Methods is the set of HTTP methods eligible for caching.
	Methods map[string]struct{}
}

// entry is a cached response.
type entry struct {
	statusCode int
	headers    http.Header
	body       []byte
	etag       string
	expiresAt  time.Time

	// LRU linked list pointers.
	prev, next *entry
	key        string
}

// ResponseCache is an in-memory LRU response cache.
type ResponseCache struct {
	logger *slog.Logger

	mu      sync.RWMutex
	entries map[string]*entry
	head    *entry // most recently used
	tail    *entry // least recently used
	size    int
}

// NewResponseCache creates a new in-memory response cache.
func NewResponseCache(logger *slog.Logger) *ResponseCache {
	return &ResponseCache{
		logger:  logger,
		entries: make(map[string]*entry),
	}
}

// Wrap returns middleware that caches responses from the upstream handler.
func (rc *ResponseCache) Wrap(cfg Config, next http.Handler) http.Handler {
	// Apply defaults.
	if cfg.TTL <= 0 {
		cfg.TTL = DefaultTTL
	}
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = DefaultMaxEntries
	}
	if cfg.MaxBodySize <= 0 {
		cfg.MaxBodySize = DefaultMaxBodySize
	}
	if len(cfg.Methods) == 0 {
		cfg.Methods = map[string]struct{}{
			http.MethodGet:  {},
			http.MethodHead: {},
		}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only cache eligible methods.
		if _, ok := cfg.Methods[r.Method]; !ok {
			next.ServeHTTP(w, r)
			return
		}

		// Check request Cache-Control directives.
		reqCC := r.Header.Get("Cache-Control")
		if strings.Contains(reqCC, "no-cache") || strings.Contains(reqCC, "no-store") {
			next.ServeHTTP(w, r)
			return
		}

		// Generate cache key from method + URL + relevant headers.
		cacheKey := rc.cacheKey(r)

		// Check for cached entry.
		rc.mu.RLock()
		cached, found := rc.entries[cacheKey]
		rc.mu.RUnlock()

		if found && time.Now().Before(cached.expiresAt) {
			// ETag conditional request: If-None-Match.
			if cached.etag != "" && r.Header.Get("If-None-Match") == cached.etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}

			// Serve from cache.
			rc.promote(cacheKey)
			for k, vv := range cached.headers {
				for _, v := range vv {
					w.Header().Add(k, v)
				}
			}
			w.Header().Set("X-CSAR-Cache", "HIT")
			w.WriteHeader(cached.statusCode)
			if len(cached.body) > 0 {
				w.Write(cached.body) //nolint:errcheck
			}
			return
		}

		// Cache MISS — proxy to upstream and capture response.
		rec := httptest.NewRecorder()
		next.ServeHTTP(rec, r)

		result := rec.Result()
		defer result.Body.Close()

		// Check response Cache-Control directives.
		respCC := result.Header.Get("Cache-Control")
		if strings.Contains(respCC, "no-store") || strings.Contains(respCC, "private") {
			// Don't cache — write through.
			rc.writeRecorder(w, rec)
			return
		}

		// Only cache successful responses.
		if result.StatusCode < 200 || result.StatusCode >= 400 {
			rc.writeRecorder(w, rec)
			return
		}

		body := rec.Body.Bytes()

		// Don't cache responses that are too large.
		if int64(len(body)) > cfg.MaxBodySize {
			rc.writeRecorder(w, rec)
			return
		}

		// Determine TTL from Cache-Control: max-age or use default.
		ttl := cfg.TTL
		if maxAge := parseMaxAge(respCC); maxAge > 0 {
			ttl = maxAge
		}

		// Store in cache.
		etag := result.Header.Get("ETag")
		headersCopy := make(http.Header)
		for k, vv := range rec.Header() {
			headersCopy[k] = append([]string(nil), vv...)
		}

		bodyCopy := make([]byte, len(body))
		copy(bodyCopy, body)

		rc.store(cacheKey, &entry{
			statusCode: rec.Code,
			headers:    headersCopy,
			body:       bodyCopy,
			etag:       etag,
			expiresAt:  time.Now().Add(ttl),
			key:        cacheKey,
		}, cfg.MaxEntries)

		// Write through to client.
		for k, vv := range rec.Header() {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.Header().Set("X-CSAR-Cache", "MISS")
		w.WriteHeader(rec.Code)
		if len(body) > 0 {
			w.Write(body) //nolint:errcheck
		}
	})
}

// cacheKey generates a unique key for the request.
func (rc *ResponseCache) cacheKey(r *http.Request) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s %s", r.Method, r.URL.String())

	// Include Accept header to vary by content type.
	if accept := r.Header.Get("Accept"); accept != "" {
		fmt.Fprintf(h, " accept=%s", accept)
	}

	return fmt.Sprintf("%x", h.Sum(nil))
}

// store adds or updates a cache entry, evicting LRU entries if over capacity.
func (rc *ResponseCache) store(key string, e *entry, maxEntries int) {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	// If entry exists, update and promote.
	if existing, ok := rc.entries[key]; ok {
		rc.removeFromList(existing)
		rc.entries[key] = e
		rc.addToFront(e)
		return
	}

	// Add new entry.
	rc.entries[key] = e
	rc.addToFront(e)
	rc.size++

	// Evict if over capacity.
	for rc.size > maxEntries && rc.tail != nil {
		rc.evict()
	}
}

// promote moves an entry to the front (most recently used).
func (rc *ResponseCache) promote(key string) {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	e, ok := rc.entries[key]
	if !ok {
		return
	}
	rc.removeFromList(e)
	rc.addToFront(e)
}

// addToFront adds an entry to the front of the LRU list.
func (rc *ResponseCache) addToFront(e *entry) {
	e.prev = nil
	e.next = rc.head
	if rc.head != nil {
		rc.head.prev = e
	}
	rc.head = e
	if rc.tail == nil {
		rc.tail = e
	}
}

// removeFromList removes an entry from the LRU list.
func (rc *ResponseCache) removeFromList(e *entry) {
	if e.prev != nil {
		e.prev.next = e.next
	} else {
		rc.head = e.next
	}
	if e.next != nil {
		e.next.prev = e.prev
	} else {
		rc.tail = e.prev
	}
	e.prev = nil
	e.next = nil
}

// evict removes the least recently used entry.
func (rc *ResponseCache) evict() {
	if rc.tail == nil {
		return
	}
	e := rc.tail
	rc.removeFromList(e)
	delete(rc.entries, e.key)
	rc.size--
}

// writeRecorder writes a captured response to the real ResponseWriter.
func (rc *ResponseCache) writeRecorder(w http.ResponseWriter, rec *httptest.ResponseRecorder) {
	for k, vv := range rec.Header() {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.Header().Set("X-CSAR-Cache", "BYPASS")
	w.WriteHeader(rec.Code)
	if rec.Body != nil {
		io.Copy(w, rec.Body) //nolint:errcheck
	}
}

// parseMaxAge extracts max-age from a Cache-Control header value.
// Returns 0 if not found or invalid.
func parseMaxAge(cc string) time.Duration {
	for _, directive := range strings.Split(cc, ",") {
		directive = strings.TrimSpace(directive)
		if strings.HasPrefix(directive, "max-age=") {
			val := strings.TrimPrefix(directive, "max-age=")
			seconds, err := strconv.Atoi(val)
			if err == nil && seconds > 0 {
				return time.Duration(seconds) * time.Second
			}
		}
	}
	return 0
}
