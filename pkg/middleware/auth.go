package middleware

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/ledatu/csar/internal/kms"
)

// placeholderRe matches dynamic interpolation patterns in token_ref.
// Supported sources: {query.param_name} and {header.Header-Name}.
var placeholderRe = regexp.MustCompile(`\{(query|header)\.([^}]+)\}`)

// TokenFetcher fetches encrypted tokens by reference.
// This matches the AuthService proto contract but can be implemented
// without gRPC for local development.
type TokenFetcher interface {
	// GetEncryptedToken returns the encrypted blob, associated KMS key ID, and version.
	GetEncryptedToken(ctx context.Context, tokenRef string) (encryptedToken []byte, kmsKeyID string, version string, err error)
}

// AuthInjectorConfig configures how a decrypted token is injected into the request.
type AuthInjectorConfig struct {
	// TokenRef is the reference name to look up in the AuthService.
	TokenRef string

	// KMSKeyID is the KMS key used to decrypt the token.
	KMSKeyID string

	// InjectHeader is the HTTP header to inject (e.g. "Authorization", "Api-Key").
	InjectHeader string

	// InjectFormat is the format template (e.g. "Bearer {token}").
	// The placeholder {token} is replaced with the decrypted token string.
	InjectFormat string

	// OnKMSError controls behavior when the KMS provider is unavailable.
	// "fail_closed" (default) — reject the request with 502.
	// "serve_stale" — use the last successfully decrypted value from cache.
	OnKMSError string

	// TokenVersion is an opaque version string used for cache invalidation.
	// When the coordinator rotates a token, bumping the version causes
	// routers to re-fetch instead of serving a stale cached value.
	TokenVersion string
}

// AuthInjector is middleware that fetches, decrypts, and injects tokens
// into upstream request headers.
type AuthInjector struct {
	fetcher  TokenFetcher
	provider kms.Provider
	logger   *slog.Logger

	// staleCache holds the last successfully decrypted header value per token_ref.
	// Used when on_kms_error = "serve_stale".
	staleMu    sync.RWMutex
	staleCache map[string]string // tokenRef -> last good header value
}

// NewAuthInjector creates an AuthInjector middleware.
func NewAuthInjector(fetcher TokenFetcher, provider kms.Provider, logger *slog.Logger) *AuthInjector {
	return &AuthInjector{
		fetcher:    fetcher,
		provider:   provider,
		logger:     logger,
		staleCache: make(map[string]string),
	}
}

// Wrap returns an http.Handler that injects the decrypted token into
// the request before forwarding to the next handler.
//
// Dynamic token_ref: If TokenRef contains placeholders like {query.seller_id}
// or {header.X-Seller-ID}, they are resolved from the incoming request at
// runtime. This enables a single route to serve hundreds of per-seller tokens
// without duplicating config entries.
func (a *AuthInjector) Wrap(cfg AuthInjectorConfig, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cfg.TokenRef == "" {
			// No token injection needed, pass through
			next.ServeHTTP(w, r)
			return
		}

		onError := cfg.OnKMSError
		if onError == "" {
			onError = "fail_closed"
		}

		// Resolve dynamic placeholders in token_ref (e.g. "token_{query.account_id}").
		resolvedRef, err := resolveTokenRef(cfg.TokenRef, r)
		if err != nil {
			a.logger.Warn("missing required parameter for dynamic token_ref",
				"token_ref", cfg.TokenRef,
				"error", err,
			)
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, fmt.Sprintf(`{"error":"auth: %s"}`, err.Error()), http.StatusBadRequest)
			return
		}

		// Fetch encrypted token using the resolved reference.
		encToken, kmsKeyID, version, err := a.fetcher.GetEncryptedToken(r.Context(), resolvedRef)
		if err != nil {
			a.logger.Error("failed to fetch encrypted token",
				"token_ref", resolvedRef,
				"error", err,
			)
			if onError == "serve_stale" {
				if stale := a.getStale(resolvedRef); stale != "" {
					a.logger.Warn("serving stale token due to fetch error",
						"token_ref", resolvedRef,
					)
					r.Header.Set(cfg.InjectHeader, stale)
					next.ServeHTTP(w, r)
					return
				}
			}
			http.Error(w, `{"error":"auth: token fetch failed"}`, http.StatusBadGateway)
			return
		}

		// Token version check: if the caller pinned a version and the
		// fetched version doesn't match, treat it as a version mismatch
		// and log a warning (still proceed with what was returned).
		if cfg.TokenVersion != "" && version != "" && cfg.TokenVersion != version {
			a.logger.Warn("token version mismatch — config expects different version",
				"token_ref", resolvedRef,
				"expected_version", cfg.TokenVersion,
				"actual_version", version,
			)
		}

		// Use the KMS key from the token response, fallback to config
		keyID := kmsKeyID
		if keyID == "" {
			keyID = cfg.KMSKeyID
		}

		// Decrypt the token
		plainToken, err := a.provider.Decrypt(r.Context(), keyID, encToken)
		if err != nil {
			a.logger.Error("failed to decrypt token",
				"token_ref", resolvedRef,
				"kms_key_id", keyID,
				"error", err,
			)
			if onError == "serve_stale" {
				if stale := a.getStale(resolvedRef); stale != "" {
					a.logger.Warn("serving stale token due to decrypt error",
						"token_ref", resolvedRef,
					)
					r.Header.Set(cfg.InjectHeader, stale)
					next.ServeHTTP(w, r)
					return
				}
			}
			http.Error(w, `{"error":"auth: token decrypt failed"}`, http.StatusBadGateway)
			return
		}

		// Format and inject the header
		headerValue := formatToken(cfg.InjectFormat, string(plainToken))
		r.Header.Set(cfg.InjectHeader, headerValue)

		// Update stale cache on success — keyed by resolved ref to prevent
		// cross-pollution between different sellers/tenants.
		a.setStale(resolvedRef, headerValue)

		a.logger.Debug("injected auth token",
			"token_ref", resolvedRef,
			"header", cfg.InjectHeader,
		)

		next.ServeHTTP(w, r)
	})
}

// resolveTokenRef replaces dynamic placeholders in a token_ref string.
// Supported patterns:
//   - {query.param_name}  → extracted from URL query parameters
//   - {header.Header-Name} → extracted from request headers
//
// Returns an error if a referenced parameter is missing or empty.
func resolveTokenRef(tokenRef string, r *http.Request) (string, error) {
	if !strings.Contains(tokenRef, "{") {
		return tokenRef, nil
	}

	var resolveErr error
	resolved := placeholderRe.ReplaceAllStringFunc(tokenRef, func(match string) string {
		if resolveErr != nil {
			return match // stop on first error
		}
		submatch := placeholderRe.FindStringSubmatch(match)
		source := submatch[1]
		key := submatch[2]

		var val string
		switch source {
		case "query":
			val = r.URL.Query().Get(key)
		case "header":
			val = r.Header.Get(key)
		default:
			resolveErr = fmt.Errorf("unknown placeholder source %q in token_ref %q", source, tokenRef)
			return match
		}

		if val == "" {
			resolveErr = fmt.Errorf("required parameter %s.%s is missing for token_ref %q", source, key, tokenRef)
			return match
		}
		return val
	})

	if resolveErr != nil {
		return "", resolveErr
	}
	return resolved, nil
}

// getStale returns the last successfully decrypted header value for a token ref,
// or "" if none is cached.
func (a *AuthInjector) getStale(tokenRef string) string {
	a.staleMu.RLock()
	defer a.staleMu.RUnlock()
	return a.staleCache[tokenRef]
}

// setStale stores the last successfully decrypted header value for a token ref.
func (a *AuthInjector) setStale(tokenRef, headerValue string) {
	a.staleMu.Lock()
	a.staleCache[tokenRef] = headerValue
	a.staleMu.Unlock()
}

// InvalidateToken clears the stale cache for a specific token_ref.
// Called when the coordinator pushes a token rotation event.
// This ensures that even with on_kms_error=serve_stale, compromised tokens
// are never served after rotation.
func (a *AuthInjector) InvalidateToken(tokenRef string) {
	a.staleMu.Lock()
	delete(a.staleCache, tokenRef)
	a.staleMu.Unlock()
	a.logger.Info("token invalidated from stale cache", "token_ref", tokenRef)
}

// InvalidateAllTokens clears the entire stale cache.
// Used during bulk token rotation or coordinator reconnection.
func (a *AuthInjector) InvalidateAllTokens() {
	a.staleMu.Lock()
	clear(a.staleCache)
	a.staleMu.Unlock()
	a.logger.Info("all tokens invalidated from stale cache")
}

// formatToken replaces {token} placeholder in the format string with the actual token.
func formatToken(format, token string) string {
	if format == "" {
		return token
	}
	return strings.ReplaceAll(format, "{token}", token)
}

// StaticTokenFetcher is a simple in-memory implementation of TokenFetcher
// for development and testing. Maps token_ref -> (encrypted_blob, kms_key_id).
type StaticTokenFetcher struct {
	tokens map[string]staticToken
}

type staticToken struct {
	encryptedToken []byte
	kmsKeyID       string
	version        string
}

// LogValue implements slog.LogValuer to prevent accidental logging of
// the encrypted token blob.
func (t staticToken) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("kms_key_id", t.kmsKeyID),
		slog.String("version", t.version),
		slog.String("encrypted_token", "[REDACTED]"),
	)
}

// NewStaticTokenFetcher creates a StaticTokenFetcher.
func NewStaticTokenFetcher() *StaticTokenFetcher {
	return &StaticTokenFetcher{
		tokens: make(map[string]staticToken),
	}
}

// Add registers an encrypted token for a given reference.
func (f *StaticTokenFetcher) Add(tokenRef string, encryptedToken []byte, kmsKeyID string) {
	f.tokens[tokenRef] = staticToken{
		encryptedToken: encryptedToken,
		kmsKeyID:       kmsKeyID,
		version:        "static",
	}
}

// GetEncryptedToken implements TokenFetcher.
func (f *StaticTokenFetcher) GetEncryptedToken(_ context.Context, tokenRef string) ([]byte, string, string, error) {
	tok, ok := f.tokens[tokenRef]
	if !ok {
		return nil, "", "", fmt.Errorf("token ref %q not found", tokenRef)
	}
	return tok.encryptedToken, tok.kmsKeyID, tok.version, nil
}
