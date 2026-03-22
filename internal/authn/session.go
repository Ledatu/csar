package authn

import (
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/ledatu/csar-core/apierror"
)

const defaultSessionCacheTTL = 30 * time.Second

// SessionConfig holds the configuration for session-based auth validation.
type SessionConfig struct {
	Endpoint       string
	CookieName     string
	ForwardHeaders []string
	CacheTTL       time.Duration
}

// SessionValidator validates inbound requests by making a subrequest to an
// auth-validate endpoint (e.g. csar-authn /auth/validate). Results are cached
// briefly to avoid per-request overhead.
type SessionValidator struct {
	logger *slog.Logger
	client *http.Client

	mu    sync.RWMutex
	cache map[string]*sessionCacheEntry
}

type sessionCacheEntry struct {
	headers   http.Header
	status    int
	fetchedAt time.Time
}

// NewSessionValidator creates a new SessionValidator.
func NewSessionValidator(logger *slog.Logger, client *http.Client) *SessionValidator {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &SessionValidator{
		logger: logger,
		client: client,
		cache:  make(map[string]*sessionCacheEntry),
	}
}

// Wrap returns middleware that validates the session before calling next.
func (v *SessionValidator) Wrap(cfg SessionConfig, next http.Handler) http.Handler {
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = defaultSessionCacheTTL
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(cfg.CookieName)
		if err != nil {
			v.reject(w, http.StatusUnauthorized, "missing session cookie")
			return
		}

		entry, err := v.validate(cfg, cookie)
		if err != nil {
			v.logger.Error("session validation subrequest failed", "error", err)
			v.reject(w, http.StatusBadGateway, "auth service unavailable")
			return
		}
		if entry.status >= 500 {
			v.logger.Error("session validation backend error", "status", entry.status, "endpoint", cfg.Endpoint)
			v.reject(w, http.StatusBadGateway, "auth service error")
			return
		}
		if entry.status != http.StatusOK {
			v.reject(w, http.StatusUnauthorized, "session invalid")
			return
		}

		// Clear potentially spoofed headers, then copy validated headers.
		for _, h := range cfg.ForwardHeaders {
			r.Header.Del(h)
		}
		for _, h := range cfg.ForwardHeaders {
			if val := entry.headers.Get(h); val != "" {
				r.Header.Set(h, val)
			}
		}

		next.ServeHTTP(w, r)
	})
}

func (v *SessionValidator) validate(cfg SessionConfig, cookie *http.Cookie) (*sessionCacheEntry, error) {
	cacheKey := cfg.Endpoint + "\x00" + cookie.Value

	v.mu.RLock()
	if e, ok := v.cache[cacheKey]; ok && time.Since(e.fetchedAt) < cfg.CacheTTL {
		v.mu.RUnlock()
		return e, nil
	}
	v.mu.RUnlock()

	req, err := http.NewRequest("GET", cfg.Endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("building validate request: %w", err)
	}
	req.AddCookie(cookie)

	resp, err := v.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("validate subrequest to %s: %w", cfg.Endpoint, err)
	}
	defer resp.Body.Close()

	entry := &sessionCacheEntry{
		headers:   resp.Header.Clone(),
		status:    resp.StatusCode,
		fetchedAt: time.Now(),
	}

	// Only cache definitive auth outcomes (2xx, 401, 403). Transient backend
	// errors (5xx) must not be cached — the next request should retry.
	if resp.StatusCode < 500 {
		v.mu.Lock()
		v.cache[cacheKey] = entry
		v.mu.Unlock()
	}

	return entry, nil
}

func (v *SessionValidator) reject(w http.ResponseWriter, status int, message string) {
	apierror.New(apierror.CodeAuthFailed, status, message).Write(w)
}
