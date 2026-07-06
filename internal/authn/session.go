package authn

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ledatu/csar-core/apierror"
	"github.com/ledatu/csar-core/authntokens"
	"github.com/ledatu/csar/pkg/middleware"
)

const defaultSessionCacheTTL = 30 * time.Second
const tokenCacheSafetyMargin = 5 * time.Second

// SessionConfig holds the configuration for session-based auth validation.
type SessionConfig struct {
	Endpoint       string
	CookieName     string
	ForwardHeaders []string
	CacheTTL       time.Duration
	IssueTokens    []IssueTokenConfig
}

// IssueTokenConfig configures one authn-managed route token injection.
type IssueTokenConfig struct {
	Profile        string
	InjectHeader   string
	InjectFormat   string
	OnMissingClaim string
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
	tokens    []authntokens.IssuedToken
	errors    []authntokens.IssueTokenError
	status    int
	fetchedAt time.Time
	expiresAt time.Time
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
		for _, tokenCfg := range cfg.IssueTokens {
			r.Header.Del(tokenCfg.InjectHeader)
		}
		for _, h := range cfg.ForwardHeaders {
			if val := entry.headers.Get(h); val != "" {
				r.Header.Set(h, val)
			}
		}
		if !v.injectIssuedTokens(w, r, cfg, entry) {
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (v *SessionValidator) validate(cfg SessionConfig, cookie *http.Cookie) (*sessionCacheEntry, error) {
	cacheKey := sessionCacheKey(cfg, cookie.Value)
	now := time.Now()

	v.mu.RLock()
	if e, ok := v.cache[cacheKey]; ok && now.Before(e.expiresAt) {
		v.mu.RUnlock()
		return e, nil
	}
	v.mu.RUnlock()

	req, err := buildValidateRequest(cfg)
	if err != nil {
		return nil, fmt.Errorf("building validate request: %w", err)
	}
	req.AddCookie(cookie)

	resp, err := v.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("validate subrequest to %s: %w", cfg.Endpoint, err)
	}
	defer resp.Body.Close()

	entry, err := buildSessionCacheEntry(cfg, resp)
	if err != nil {
		return nil, err
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

func (v *SessionValidator) injectIssuedTokens(w http.ResponseWriter, r *http.Request, cfg SessionConfig, entry *sessionCacheEntry) bool {
	if len(cfg.IssueTokens) == 0 {
		return true
	}
	tokensByProfile := make(map[string]string, len(entry.tokens))
	for _, token := range entry.tokens {
		tokensByProfile[token.Profile] = token.Token
	}
	errorByProfile := make(map[string]string, len(entry.errors))
	for _, tokenErr := range entry.errors {
		errorByProfile[tokenErr.Profile] = tokenErr.Reason
	}
	for _, tokenCfg := range cfg.IssueTokens {
		token := tokensByProfile[tokenCfg.Profile]
		if token == "" {
			if tokenCfg.OnMissingClaim == "omit" {
				continue
			}
			reason := errorByProfile[tokenCfg.Profile]
			if reason == "" {
				reason = "missing_token"
			}
			v.logger.Warn("authn route token missing", "profile", tokenCfg.Profile, "reason", reason)
			v.reject(w, http.StatusForbidden, "required route token unavailable")
			return false
		}
		r.Header.Set(tokenCfg.InjectHeader, middleware.FormatToken(tokenCfg.InjectFormat, token))
	}
	return true
}

func buildValidateRequest(cfg SessionConfig) (*http.Request, error) {
	if len(cfg.IssueTokens) == 0 {
		return http.NewRequest("GET", cfg.Endpoint, nil)
	}
	profiles := uniqueIssueProfiles(cfg.IssueTokens)
	body := authntokens.ValidateRequest{
		IssueTokens: make([]authntokens.IssueTokenRequest, 0, len(profiles)),
	}
	for _, profile := range profiles {
		body.IssueTokens = append(body.IssueTokens, authntokens.IssueTokenRequest{Profile: profile})
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("encoding validate request: %w", err)
	}
	req, err := http.NewRequest("POST", cfg.Endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

func buildSessionCacheEntry(cfg SessionConfig, resp *http.Response) (*sessionCacheEntry, error) {
	now := time.Now()
	entry := &sessionCacheEntry{
		headers:   resp.Header.Clone(),
		status:    resp.StatusCode,
		fetchedAt: now,
		expiresAt: now.Add(cfg.CacheTTL),
	}
	if len(cfg.IssueTokens) == 0 || resp.StatusCode != http.StatusOK {
		return entry, nil
	}

	var body authntokens.ValidateResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("decoding validate response: %w", err)
	}
	for k, v := range body.Headers {
		if v != "" {
			entry.headers.Set(k, v)
		}
	}
	entry.tokens = body.Tokens
	entry.errors = body.Errors
	if tokenExpiry, ok := earliestTokenExpiry(body.Tokens); ok {
		capped := tokenExpiry.Add(-tokenCacheSafetyMargin)
		if capped.Before(now) {
			entry.expiresAt = now
		} else if capped.Before(entry.expiresAt) {
			entry.expiresAt = capped
		}
	}
	return entry, nil
}

func sessionCacheKey(cfg SessionConfig, cookieValue string) string {
	if len(cfg.IssueTokens) == 0 {
		return cfg.Endpoint + "\x00" + cookieValue
	}
	profiles := strings.Join(uniqueIssueProfiles(cfg.IssueTokens), "\x00")
	sum := sha256.Sum256([]byte(profiles))
	return cfg.Endpoint + "\x00" + cookieValue + "\x00" + hex.EncodeToString(sum[:])
}

func uniqueIssueProfiles(tokens []IssueTokenConfig) []string {
	seen := make(map[string]struct{}, len(tokens))
	for _, token := range tokens {
		if token.Profile == "" {
			continue
		}
		seen[token.Profile] = struct{}{}
	}
	profiles := make([]string, 0, len(seen))
	for profile := range seen {
		profiles = append(profiles, profile)
	}
	sort.Strings(profiles)
	return profiles
}

func earliestTokenExpiry(tokens []authntokens.IssuedToken) (time.Time, bool) {
	var earliest time.Time
	for _, token := range tokens {
		if token.ExpiresAt.IsZero() {
			continue
		}
		if earliest.IsZero() || token.ExpiresAt.Before(earliest) {
			earliest = token.ExpiresAt
		}
	}
	return earliest, !earliest.IsZero()
}
