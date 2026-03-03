// Package tenant provides multi-tenant routing for the CSAR API gateway.
//
// The Router selects a backend target URL based on a tenant identifier
// extracted from an HTTP header (e.g. "Host", "X-Tenant-ID").
// This allows a single CSAR route to serve multiple tenants, each
// with their own upstream backend.
//
// Recommended by security audit §3.3.3.
package tenant

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
)

// Config configures multi-tenant routing for a single route.
type Config struct {
	// Header is the HTTP header used to identify the tenant.
	// Common choices: "Host", "X-Tenant-ID".
	Header string

	// Backends maps tenant identifiers to target URLs.
	Backends map[string]string

	// Default is the fallback target URL when no tenant header matches.
	// If empty, unmatched tenants receive 404.
	Default string
}

// Router selects upstream backends based on tenant identity.
type Router struct {
	logger *slog.Logger

	// Cached reverse proxies per target URL (thread-safe).
	mu      sync.RWMutex
	proxies map[string]*httputil.ReverseProxy
}

// NewRouter creates a new tenant-aware Router.
func NewRouter(logger *slog.Logger) *Router {
	return &Router{
		logger:  logger,
		proxies: make(map[string]*httputil.ReverseProxy),
	}
}

// Resolve returns the target URL for the given request based on the tenant config.
// Returns the target URL and the tenant identifier, or an error if no match.
func (tr *Router) Resolve(cfg Config, r *http.Request) (targetURL string, tenantID string, err error) {
	// Extract tenant identifier from the specified header.
	tenantID = r.Header.Get(cfg.Header)

	// For Host header, also check r.Host (which Go populates automatically).
	if strings.EqualFold(cfg.Header, "Host") && tenantID == "" {
		tenantID = r.Host
	}

	// Strip port from host if present (e.g. "acme.example.com:8080" → "acme.example.com").
	if idx := strings.LastIndex(tenantID, ":"); idx > 0 {
		tenantID = tenantID[:idx]
	}

	tenantID = strings.TrimSpace(tenantID)

	// Look up backend for this tenant.
	if target, ok := cfg.Backends[tenantID]; ok {
		return target, tenantID, nil
	}

	// Try lowercase match (common for Host header).
	lower := strings.ToLower(tenantID)
	for k, v := range cfg.Backends {
		if strings.ToLower(k) == lower {
			return v, tenantID, nil
		}
	}

	// Fallback to default.
	if cfg.Default != "" {
		return cfg.Default, tenantID, nil
	}

	return "", tenantID, fmt.Errorf("no backend for tenant %q", tenantID)
}

// Proxy returns an http.Handler that routes to the resolved tenant backend.
// The proxyFactory creates a reverse proxy for the given target URL.
func (tr *Router) Proxy(cfg Config, fallbackHandler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetURL, tenantID, err := tr.Resolve(cfg, r)
		if err != nil {
			tr.logger.Warn("tenant routing: no match",
				"header", cfg.Header,
				"tenant_id", tenantID,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, `{"error":"no backend for tenant","tenant":%q}`, tenantID)
			return
		}

		proxy, err := tr.getOrCreateProxy(targetURL)
		if err != nil {
			tr.logger.Error("tenant routing: failed to create proxy",
				"tenant_id", tenantID,
				"target_url", targetURL,
				"error", err,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			fmt.Fprint(w, `{"error":"tenant backend unavailable"}`)
			return
		}

		tr.logger.Debug("tenant routed",
			"tenant_id", tenantID,
			"target_url", targetURL,
		)

		proxy.ServeHTTP(w, r)
	})
}

// getOrCreateProxy returns a cached reverse proxy for the target URL,
// creating one if it doesn't exist yet.
func (tr *Router) getOrCreateProxy(targetURL string) (*httputil.ReverseProxy, error) {
	tr.mu.RLock()
	if p, ok := tr.proxies[targetURL]; ok {
		tr.mu.RUnlock()
		return p, nil
	}
	tr.mu.RUnlock()

	target, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL %q: %w", targetURL, err)
	}

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.URL.Path = target.Path
			req.Host = target.Host
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			fmt.Fprintf(w, `{"error":"tenant upstream error","detail":%q}`, err.Error())
		},
	}

	tr.mu.Lock()
	tr.proxies[targetURL] = proxy
	tr.mu.Unlock()

	return proxy, nil
}
