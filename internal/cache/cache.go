// Package cache provides HTTP response caching middleware for CSAR.
//
// The response cache is fail-open: cache store failures never make an upstream
// route fail. When a configured store is unavailable, requests bypass caching
// and continue through the normal proxy path.
package cache

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"time"

	"github.com/ledatu/csar-core/gatewayctx"
)

// DefaultTTL is the default cache TTL when no Cache-Control header is present.
const DefaultTTL = 5 * time.Minute

// DefaultMaxEntries is the default maximum number of cached responses.
const DefaultMaxEntries = 1000

// DefaultMaxBodySize is the default maximum body size to cache (1MB).
const DefaultMaxBodySize int64 = 1 * 1024 * 1024

// DefaultOperationTimeout bounds external cache operations.
const DefaultOperationTimeout = 75 * time.Millisecond

// StatsRecorder records cache events without coupling this package to Prometheus.
type StatsRecorder interface {
	RecordResponseCache(route, event string)
}

// Config configures response caching for a single route.
type Config struct {
	RouteKey             string
	Store                string
	KeyTemplate          string
	FailMode             string
	OperationTimeout     time.Duration
	TTL                  time.Duration
	TTLJitter            string
	TTLRules             []TTLRule
	KeyQuery             *KeyQueryConfig
	StaleIfError         time.Duration
	StaleWhileRevalidate time.Duration
	ContentTypes         []string
	ResponseTTLRules     []ResponseTTLRule
	ResponseTags         []ResponseTag
	Namespaces           []string
	Bypass               *BypassConfig
	Coalesce             *CoalesceConfig
	Tags                 []string
	VaryHeaders          []string
	MaxEntries           int
	MaxBodySize          int64
	Methods              map[string]struct{}
	CacheStatuses        []string
}

// TTLRule conditionally overrides the default cache TTL.
type TTLRule struct {
	When string
	From string
	To   string
	TTL  time.Duration
}

// ResponseTTLRule conditionally overrides TTL from upstream response headers.
type ResponseTTLRule struct {
	When   string
	Header string
	Value  string
	TTL    time.Duration
}

// ResponseTag derives cache tags from upstream response headers.
type ResponseTag struct {
	Header string
	Prefix string
}

// BypassConfig configures authorized cache bypass headers.
type BypassConfig struct {
	Headers []BypassHeader
}

// BypassHeader configures one bypass request header.
type BypassHeader struct {
	Name                string
	Value               string
	RequireGatewayScope string
}

// CoalesceConfig configures request coalescing on cache misses.
type CoalesceConfig struct {
	Enabled           bool
	Wait              time.Duration
	WaitTimeoutStatus int
}

// InvalidationConfig configures cache invalidation for a mutating route.
type InvalidationConfig struct {
	RouteKey         string
	Store            string
	OperationTimeout time.Duration
	Tags             []string
	BumpNamespaces   []string
	Debounce         time.Duration
	OnStatus         []string
}

// ResponseCache coordinates configured response cache stores.
type ResponseCache struct {
	logger *slog.Logger
	stats  StatsRecorder

	memory *MemoryStore
	redis  *RedisStore

	coalescer *coalescer
	debouncer *invalidationDebouncer
}

// Option configures ResponseCache.
type Option func(*ResponseCache)

// WithStatsRecorder records cache events.
func WithStatsRecorder(stats StatsRecorder) Option {
	return func(rc *ResponseCache) { rc.stats = stats }
}

// WithRedisStore configures the distributed Redis response cache store.
func WithRedisStore(store *RedisStore) Option {
	return func(rc *ResponseCache) { rc.redis = store }
}

// NewResponseCache creates a response cache coordinator.
func NewResponseCache(logger *slog.Logger, opts ...Option) *ResponseCache {
	rc := &ResponseCache{
		logger:    logger,
		memory:    NewMemoryStore(),
		coalescer: newCoalescer(),
	}
	rc.debouncer = newInvalidationDebouncer(rc)
	for _, opt := range opts {
		opt(rc)
	}
	return rc
}

// Wrap returns middleware that caches responses from the upstream handler.
func (rc *ResponseCache) Wrap(cfg Config, next http.Handler) http.Handler {
	cfg = cfg.withDefaults()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := cfg.Methods[r.Method]; !ok {
			rc.serveBypass(w, r, cfg, next)
			return
		}
		if bypass, event := rc.requestBypassesCache(r, cfg); bypass {
			rc.record(cfg.RouteKey, event)
			rc.serveBypass(w, r, cfg, next)
			return
		}

		store, ok := rc.store(cfg.Store)
		if !ok {
			rc.record(cfg.RouteKey, "bypass")
			rc.serveBypass(w, r, cfg, next)
			return
		}

		namespaces, namespaceVersions, err := rc.namespaceVersions(r, cfg, store)
		if err != nil {
			rc.logger.Warn("response cache namespace versions could not be resolved, bypassing cache",
				"route", cfg.RouteKey,
				"store", store.Name(),
				"error", err,
			)
			rc.record(cfg.RouteKey, "store_error")
			rc.record(cfg.RouteKey, "bypass")
			rc.serveBypass(w, r, cfg, next)
			return
		}

		cacheKey, err := BuildCacheKey(cfg.RouteKey, cfg.KeyTemplate, cfg.VaryHeaders, cfg.KeyQuery, namespaceVersions, r)
		if err != nil {
			rc.logger.Warn("response cache key could not be rendered",
				"route", cfg.RouteKey,
				"error", err,
			)
			rc.record(cfg.RouteKey, "bypass")
			rc.serveBypass(w, r, cfg, next)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), cfg.OperationTimeout)
		entry, err := store.GetFresh(ctx, cacheKey, namespaceVersions)
		cancel()
		switch {
		case err == nil && entry != nil:
			rc.record(cfg.RouteKey, "hit")
			rc.writeEntry(w, entry)
			return
		case err != nil && !errors.Is(err, ErrCacheMiss):
			rc.logger.Warn("response cache read failed, bypassing cache",
				"route", cfg.RouteKey,
				"store", cfg.Store,
				"error", err,
			)
			rc.record(cfg.RouteKey, "store_error")
			rc.record(cfg.RouteKey, "bypass")
			rc.serveBypass(w, r, cfg, next)
			return
		default:
			rc.record(cfg.RouteKey, "miss")
		}

		if cfg.StaleWhileRevalidate > 0 {
			stale, ok := rc.getStale(r, cfg, cacheKey, namespaceVersions, store)
			if ok {
				rc.record(cfg.RouteKey, "stale")
				rc.writeEntryWithStatus(w, stale, "STALE")
				rc.refreshAsync(r, cfg, cacheKey, namespaces, namespaceVersions, store, next)
				return
			}
		}

		if cfg.Coalesce != nil && cfg.Coalesce.Enabled {
			rc.serveCoalesced(w, r, cfg, cacheKey, namespaces, namespaceVersions, store, next)
			return
		}

		result := rc.fetchAndMaybeCache(r, cfg, cacheKey, namespaces, namespaceVersions, store, next)
		if result.cacheStatus == "BYPASS" && result.statusCode >= 500 && cfg.StaleIfError > 0 {
			if stale, ok := rc.getStale(r, cfg, cacheKey, namespaceVersions, store); ok {
				rc.record(cfg.RouteKey, "refresh_error")
				rc.record(cfg.RouteKey, "stale")
				rc.writeEntryWithStatus(w, stale, "STALE")
				return
			}
		}
		rc.writeCaptured(w, result)
	})
}

// WrapInvalidation wraps a mutating route and purges matching cache tags after
// successful upstream responses. Invalidation is fail-open.
func (rc *ResponseCache) WrapInvalidation(cfg InvalidationConfig, next http.Handler) http.Handler {
	cfg = cfg.withDefaults()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusCaptureResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(rec, r)

		if !statusMatches(rec.statusCode, cfg.OnStatus, true) {
			return
		}

		tags, err := RenderTags(cfg.Tags, r)
		if err != nil {
			rc.logger.Warn("cache invalidation tag could not be rendered",
				"route", cfg.RouteKey,
				"error", err,
			)
			rc.record(cfg.RouteKey, "invalidation_error")
			return
		}
		namespaces, err := RenderTags(cfg.BumpNamespaces, r)
		if err != nil {
			rc.logger.Warn("cache invalidation namespace could not be rendered",
				"route", cfg.RouteKey,
				"error", err,
			)
			rc.record(cfg.RouteKey, "invalidation_error")
			return
		}
		if len(tags) == 0 && len(namespaces) == 0 {
			return
		}

		for _, store := range rc.invalidationStores(cfg.Store) {
			if cfg.Debounce > 0 {
				for _, tag := range tags {
					rc.debouncer.invalidateTag(store, cfg, tag)
				}
				for _, namespace := range namespaces {
					rc.debouncer.bumpNamespace(store, cfg, namespace)
				}
				continue
			}
			for _, tag := range tags {
				rc.invalidateTag(store, cfg, tag)
			}
			for _, namespace := range namespaces {
				rc.bumpNamespace(store, cfg, namespace)
			}
		}
	})
}

func (rc *ResponseCache) fetchAndMaybeCache(r *http.Request, cfg Config, cacheKey string, namespaces []string, namespaceVersions map[string]int64, store Store, next http.Handler) capturedResponse {
	rec := httptest.NewRecorder()
	next.ServeHTTP(rec, r)

	result := rec.Result()
	defer result.Body.Close()

	if !shouldCacheResponse(result, rec, cfg) {
		rc.record(cfg.RouteKey, "bypass")
		return captureRecorder(rec, "BYPASS")
	}

	body := rec.Body.Bytes()
	ttl := selectTTL(cfg, r, result)
	ttl = applyTTLJitter(ttl, cfg.TTLJitter, cacheKey)
	tags, err := RenderTags(cfg.Tags, r)
	if err != nil {
		rc.logger.Warn("response cache tags could not be rendered, bypassing cache write",
			"route", cfg.RouteKey,
			"error", err,
		)
		rc.record(cfg.RouteKey, "bypass")
		return captureRecorder(rec, "BYPASS")
	}
	responseTags, err := RenderResponseTags(cfg.ResponseTags, r, result.Header)
	if err != nil {
		rc.logger.Warn("response cache response tags could not be rendered, bypassing cache write",
			"route", cfg.RouteKey,
			"error", err,
		)
		rc.record(cfg.RouteKey, "bypass")
		return captureRecorder(rec, "BYPASS")
	}
	tags = append(tags, responseTags...)

	entry := &Entry{
		StatusCode:  rec.Code,
		Headers:     cloneHeader(rec.Header()),
		Body:        append([]byte(nil), body...),
		ETag:        result.Header.Get("ETag"),
		ContentType: result.Header.Get("Content-Type"),
	}

	ctx, cancel := context.WithTimeout(r.Context(), cfg.OperationTimeout)
	err = store.Set(ctx, cacheKey, entry, SetOptions{
		TTL:               ttl,
		StaleTTL:          maxDuration(cfg.StaleIfError, cfg.StaleWhileRevalidate),
		Tags:              tags,
		NamespaceVersions: namespaceVersions,
		MaxEntries:        cfg.MaxEntries,
	})
	cancel()
	if err != nil {
		rc.logger.Warn("response cache write failed, returning upstream response",
			"route", cfg.RouteKey,
			"store", store.Name(),
			"error", err,
		)
		rc.record(cfg.RouteKey, "store_error")
		return captureRecorder(rec, "BYPASS")
	}

	_ = namespaces
	return captureRecorder(rec, "MISS")
}

func (rc *ResponseCache) serveBypass(w http.ResponseWriter, r *http.Request, cfg Config, next http.Handler) {
	w.Header().Set("X-CSAR-Cache", "BYPASS")
	next.ServeHTTP(w, r)
}

func (rc *ResponseCache) writeEntry(w http.ResponseWriter, e *Entry) {
	rc.writeEntryWithStatus(w, e, "HIT")
}

func (rc *ResponseCache) writeEntryWithStatus(w http.ResponseWriter, e *Entry, cacheStatus string) {
	for k, vv := range e.Headers {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.Header().Set("X-CSAR-Cache", cacheStatus)
	w.WriteHeader(e.StatusCode)
	if len(e.Body) > 0 {
		_, _ = io.Copy(w, bytes.NewReader(e.Body))
	}
}

func (rc *ResponseCache) writeCaptured(w http.ResponseWriter, resp capturedResponse) {
	for k, vv := range resp.headers {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.Header().Set("X-CSAR-Cache", resp.cacheStatus)
	w.WriteHeader(resp.statusCode)
	if len(resp.body) > 0 {
		_, _ = io.Copy(w, bytes.NewReader(resp.body))
	}
}

func capturedFromEntry(e *Entry, cacheStatus string) capturedResponse {
	if e == nil {
		return capturedResponse{statusCode: http.StatusServiceUnavailable, cacheStatus: "BYPASS"}
	}
	return capturedResponse{
		statusCode:  e.StatusCode,
		headers:     cloneHeader(e.Headers),
		body:        append([]byte(nil), e.Body...),
		cacheStatus: cacheStatus,
	}
}

func (rc *ResponseCache) store(name string) (Store, bool) {
	switch strings.ToLower(name) {
	case "redis":
		if rc.redis == nil {
			return nil, false
		}
		return rc.redis, true
	default:
		return rc.memory, true
	}
}

func (rc *ResponseCache) invalidationStores(name string) []Store {
	switch strings.ToLower(name) {
	case "memory":
		return []Store{rc.memory}
	case "redis":
		if rc.redis == nil {
			return nil
		}
		return []Store{rc.redis}
	default:
		stores := []Store{rc.memory}
		if rc.redis != nil {
			stores = append(stores, rc.redis)
		}
		return stores
	}
}

func (rc *ResponseCache) record(route, event string) {
	if rc.stats != nil {
		rc.stats.RecordResponseCache(route, event)
	}
}

func (rc *ResponseCache) namespaceVersions(r *http.Request, cfg Config, store Store) ([]string, map[string]int64, error) {
	namespaces, err := RenderTags(cfg.Namespaces, r)
	if err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithTimeout(r.Context(), cfg.OperationTimeout)
	versions, err := store.GetNamespaceVersions(ctx, namespaces)
	cancel()
	return namespaces, versions, err
}

func (rc *ResponseCache) getStale(r *http.Request, cfg Config, cacheKey string, namespaceVersions map[string]int64, store Store) (*Entry, bool) {
	ctx, cancel := context.WithTimeout(r.Context(), cfg.OperationTimeout)
	entry, err := store.GetStale(ctx, cacheKey, namespaceVersions)
	cancel()
	if err != nil || entry == nil {
		return nil, false
	}
	return entry, true
}

func (rc *ResponseCache) refreshAsync(r *http.Request, cfg Config, cacheKey string, namespaces []string, namespaceVersions map[string]int64, store Store, next http.Handler) {
	req := r.Clone(context.Background())
	go func() {
		leader, call := rc.coalescer.begin(cacheKey)
		if !leader {
			<-call.done
			return
		}
		rc.record(cfg.RouteKey, "coalesced_leader")
		result := rc.fetchAndMaybeCache(req, cfg, cacheKey, namespaces, namespaceVersions, store, next)
		rc.coalescer.finish(cacheKey, call, result)
	}()
}

func (rc *ResponseCache) serveCoalesced(w http.ResponseWriter, r *http.Request, cfg Config, cacheKey string, namespaces []string, namespaceVersions map[string]int64, store Store, next http.Handler) {
	leader, call := rc.coalescer.begin(cacheKey)
	if leader {
		rc.record(cfg.RouteKey, "coalesced_leader")
		result := rc.fetchAndMaybeCache(r, cfg, cacheKey, namespaces, namespaceVersions, store, next)
		if result.cacheStatus == "BYPASS" && result.statusCode >= 500 && cfg.StaleIfError > 0 {
			if stale, ok := rc.getStale(r, cfg, cacheKey, namespaceVersions, store); ok {
				result = capturedFromEntry(stale, "STALE")
				rc.coalescer.finish(cacheKey, call, result)
				rc.record(cfg.RouteKey, "refresh_error")
				rc.record(cfg.RouteKey, "stale")
				rc.writeCaptured(w, result)
				return
			}
		}
		rc.coalescer.finish(cacheKey, call, result)
		rc.writeCaptured(w, result)
		return
	}

	rc.record(cfg.RouteKey, "coalesced_follower")
	timer := time.NewTimer(cfg.Coalesce.Wait)
	defer timer.Stop()
	select {
	case <-call.done:
		rc.writeCaptured(w, call.result)
	case <-timer.C:
		rc.record(cfg.RouteKey, "coalesce_timeout")
		if cfg.StaleWhileRevalidate > 0 {
			if stale, ok := rc.getStale(r, cfg, cacheKey, namespaceVersions, store); ok {
				rc.record(cfg.RouteKey, "stale")
				rc.writeEntryWithStatus(w, stale, "STALE")
				return
			}
		}
		status := cfg.Coalesce.WaitTimeoutStatus
		if status == 0 {
			status = http.StatusServiceUnavailable
		}
		w.Header().Set("X-CSAR-Cache", "BYPASS")
		w.Header().Set("X-CSAR-Status", "cache_coalesce_wait_timeout")
		w.Header().Set("Retry-After", "1")
		http.Error(w, "cache coalesce wait timeout", status)
	case <-r.Context().Done():
		rc.record(cfg.RouteKey, "coalesce_timeout")
		w.Header().Set("X-CSAR-Cache", "BYPASS")
		http.Error(w, "client cancelled while waiting for cache fill", http.StatusServiceUnavailable)
	}
}

func (rc *ResponseCache) invalidateTag(store Store, cfg InvalidationConfig, tag string) {
	ctx, cancel := context.WithTimeout(context.Background(), cfg.OperationTimeout)
	err := store.DeleteByTag(ctx, tag)
	cancel()
	if err != nil && !errors.Is(err, ErrCacheMiss) {
		rc.logger.Warn("cache invalidation failed",
			"route", cfg.RouteKey,
			"store", store.Name(),
			"tag", tag,
			"error", err,
		)
		rc.record(cfg.RouteKey, "invalidation_error")
		if errors.Is(err, ErrStoreUnhealthy) {
			rc.record(cfg.RouteKey, "store_unhealthy")
		}
	}
}

func (rc *ResponseCache) bumpNamespace(store Store, cfg InvalidationConfig, namespace string) {
	ctx, cancel := context.WithTimeout(context.Background(), cfg.OperationTimeout)
	err := store.BumpNamespace(ctx, namespace)
	cancel()
	if err != nil {
		rc.logger.Warn("cache namespace bump failed",
			"route", cfg.RouteKey,
			"store", store.Name(),
			"namespace", namespace,
			"error", err,
		)
		rc.record(cfg.RouteKey, "invalidation_error")
		if errors.Is(err, ErrStoreUnhealthy) {
			rc.record(cfg.RouteKey, "store_unhealthy")
		}
		return
	}
	rc.record(cfg.RouteKey, "namespace_bump")
}

func (cfg Config) withDefaults() Config {
	if cfg.RouteKey == "" {
		cfg.RouteKey = "unknown"
	}
	if cfg.Store == "" {
		cfg.Store = "memory"
	}
	if cfg.FailMode == "" {
		cfg.FailMode = "bypass"
	}
	if cfg.OperationTimeout <= 0 {
		cfg.OperationTimeout = DefaultOperationTimeout
	}
	if cfg.TTL <= 0 {
		cfg.TTL = DefaultTTL
	}
	if cfg.Coalesce != nil && cfg.Coalesce.Wait <= 0 {
		cfg.Coalesce.Wait = 30 * time.Second
	}
	if cfg.Coalesce != nil && cfg.Coalesce.WaitTimeoutStatus == 0 {
		cfg.Coalesce.WaitTimeoutStatus = http.StatusServiceUnavailable
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
	if len(cfg.CacheStatuses) == 0 {
		cfg.CacheStatuses = []string{strconv.Itoa(http.StatusOK)}
	}
	return cfg
}

func (cfg InvalidationConfig) withDefaults() InvalidationConfig {
	if cfg.RouteKey == "" {
		cfg.RouteKey = "unknown"
	}
	if cfg.OperationTimeout <= 0 {
		cfg.OperationTimeout = DefaultOperationTimeout
	}
	if len(cfg.OnStatus) == 0 {
		cfg.OnStatus = []string{"2xx"}
	}
	return cfg
}

func (rc *ResponseCache) requestBypassesCache(r *http.Request, cfg Config) (bool, string) {
	reqCC := r.Header.Get("Cache-Control")
	if hasCacheDirective(reqCC, "no-cache") || hasCacheDirective(reqCC, "no-store") {
		return true, "bypass"
	}
	if cfg.Bypass == nil {
		return false, ""
	}
	for _, h := range cfg.Bypass.Headers {
		if h.Name == "" {
			continue
		}
		value := r.Header.Get(h.Name)
		if value == "" || (h.Value != "" && value != h.Value) {
			continue
		}
		if h.RequireGatewayScope == "" || !hasGatewayScope(r, h.RequireGatewayScope) {
			rc.record(cfg.RouteKey, "bypass_denied")
			return false, ""
		}
		return true, "bypass_authorized"
	}
	return false, ""
}

func shouldCacheResponse(result *http.Response, rec *httptest.ResponseRecorder, cfg Config) bool {
	if !statusMatches(result.StatusCode, cfg.CacheStatuses, false) {
		return false
	}
	if int64(rec.Body.Len()) > cfg.MaxBodySize {
		return false
	}
	if result.Header.Get("Set-Cookie") != "" {
		return false
	}
	if len(cfg.ContentTypes) > 0 && !contentTypeAllowed(result.Header.Get("Content-Type"), cfg.ContentTypes) {
		return false
	}
	respCC := result.Header.Get("Cache-Control")
	return !hasCacheDirective(respCC, "no-store") &&
		!hasCacheDirective(respCC, "private") &&
		!hasCacheDirective(respCC, "no-cache")
}

func selectTTL(cfg Config, r *http.Request, resp *http.Response) time.Duration {
	for _, rule := range cfg.ResponseTTLRules {
		if responseTTLRuleMatches(rule, resp) {
			return rule.TTL
		}
	}
	for _, rule := range cfg.TTLRules {
		if ttlRuleMatches(rule, r, time.Now()) {
			return rule.TTL
		}
	}
	if maxAge := parseMaxAge(resp.Header.Get("Cache-Control")); maxAge > 0 {
		return maxAge
	}
	return cfg.TTL
}

func hasGatewayScope(r *http.Request, scope string) bool {
	for _, s := range strings.Split(r.Header.Get(gatewayctx.HeaderScopes), ",") {
		if strings.TrimSpace(s) == scope {
			return true
		}
	}
	return false
}

func contentTypeAllowed(contentType string, allowed []string) bool {
	contentType = strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	for _, v := range allowed {
		if contentType == strings.ToLower(strings.TrimSpace(v)) {
			return true
		}
	}
	return false
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

func statusMatches(code int, patterns []string, default2xx bool) bool {
	if len(patterns) == 0 {
		return default2xx && code >= 200 && code < 300
	}
	for _, p := range patterns {
		p = strings.TrimSpace(strings.ToLower(p))
		switch {
		case p == "2xx" && code >= 200 && code < 300:
			return true
		case p == "3xx" && code >= 300 && code < 400:
			return true
		default:
			n, err := strconv.Atoi(p)
			if err == nil && n == code {
				return true
			}
		}
	}
	return false
}

func hasCacheDirective(cc, directive string) bool {
	for _, part := range strings.Split(cc, ",") {
		if strings.EqualFold(strings.TrimSpace(strings.SplitN(part, "=", 2)[0]), directive) {
			return true
		}
	}
	return false
}

// parseMaxAge extracts max-age from a Cache-Control header value.
func parseMaxAge(cc string) time.Duration {
	for _, directive := range strings.Split(cc, ",") {
		directive = strings.TrimSpace(directive)
		if strings.HasPrefix(strings.ToLower(directive), "max-age=") {
			val := strings.TrimPrefix(directive, "max-age=")
			seconds, err := strconv.Atoi(val)
			if err == nil && seconds > 0 {
				return time.Duration(seconds) * time.Second
			}
		}
	}
	return 0
}

func cloneHeader(h http.Header) http.Header {
	cp := make(http.Header, len(h))
	for k, vv := range h {
		cp[k] = append([]string(nil), vv...)
	}
	return cp
}

type statusCaptureResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (w *statusCaptureResponseWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusCaptureResponseWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
