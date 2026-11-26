package authn

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ledatu/csar-core/authntokens"
	"github.com/ledatu/csar-core/caller"
	"github.com/ledatu/csar-core/gatewayctx"
	"github.com/ledatu/csar-core/httpx"
	"github.com/ledatu/csar/internal/apierror"
	"github.com/ledatu/csar/pkg/middleware/authzmw"
)

const defaultTokenCacheTTL = 15 * time.Second
const maxTokenCacheEntries = 10000

type TokenConfig struct {
	Mode              string
	Endpoint          string
	CredentialProfile string
	ResourceNamespace string
	RequiredScope     string
	PlatformResource  bool
	ResourcePathParam string
	Audiences         []string
	SellerPathParam   string
	CacheTTL          time.Duration
	// FreshValidation renews the issuer lease before a signed-origin operation.
	FreshValidation bool
}

type tokenResult struct {
	validUntil   time.Time
	Identity     *caller.Identity `json:"identity,omitempty"`
	Active       bool             `json:"active"`
	Subject      string           `json:"subject"`
	CredentialID string           `json:"credential_id"`
	SellerID     string           `json:"seller_id"`
	Scopes       []string         `json:"scopes"`
	ExpiresAt    time.Time        `json:"expires_at"`
}

type tokenCacheEntry struct {
	result    tokenResult
	fetchedAt time.Time
	expiresAt time.Time
}

type TokenValidator struct {
	client *http.Client
	logger *slog.Logger
	mu     sync.RWMutex
	cache  map[string]tokenCacheEntry
}

func NewTokenValidator(logger *slog.Logger, client *http.Client) *TokenValidator {
	return &TokenValidator{logger: logger, client: client, cache: make(map[string]tokenCacheEntry)}
}

func (v *TokenValidator) Wrap(cfg TokenConfig, next http.Handler) http.Handler {
	if authntokens.IsDelegationV2(cfg.Mode) {
		return v.wrapGrantV2(cfg, next)
	}
	if authntokens.IsDelegation(cfg.Mode) {
		return v.wrapGrant(cfg, next)
	}
	if cfg.Mode != "" && cfg.Mode != "token" {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gatewayctx.StripTrusted(r.Header)
			v.reject(w, http.StatusUnauthorized, "unsupported credential mode")
		})
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = defaultTokenCacheTTL
	}
	if cfg.SellerPathParam == "" {
		cfg.SellerPathParam = "seller_id"
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gatewayctx.StripTrusted(r.Header)
		header, prefix := "Authorization", "aurum_pat_"
		if len(r.Header.Values(header)) != 1 {
			v.reject(w, http.StatusUnauthorized, "one bearer credential required")
			return
		}
		value := r.Header.Get(header)
		if !strings.HasPrefix(value, "Bearer ") || len(value) > 256 {
			v.reject(w, http.StatusUnauthorized, "API key required")
			return
		}
		raw := strings.TrimPrefix(value, "Bearer ")
		if !strings.HasPrefix(raw, prefix) {
			v.reject(w, http.StatusUnauthorized, "invalid API key")
			return
		}
		result, err := v.introspect(r, cfg, raw)
		if err != nil {
			v.logger.Error("API key introspection failed", "error", err)
			apierror.New(apierror.CodeUpstreamError, http.StatusBadGateway,
				"authentication service unavailable").Write(w)
			return
		}
		if !result.Active || result.Subject == "" || result.CredentialID == "" ||
			!time.Now().Before(result.ExpiresAt) {
			v.reject(w, http.StatusUnauthorized, "invalid or expired API key")
			return
		}
		if !slices.Contains(result.Scopes, cfg.RequiredScope) {
			v.reject(w, http.StatusForbidden, "insufficient scope")
			return
		}
		vars := authzmw.PathVarsFromContext(r.Context())
		if result.SellerID == "" || vars[cfg.SellerPathParam] != result.SellerID {
			v.reject(w, 403, "cabinet not allowed for this key")
			return
		}

		// Credentials are consumed at the edge, even if the backend is another
		// trusted service. Only verified gateway context is forwarded.
		clearCredentials(r)
		r.Header.Set(gatewayctx.HeaderScopes, cfg.RequiredScope)
		r.Header.Set(gatewayctx.HeaderSubject, result.Subject)
		r.Header.Set(gatewayctx.HeaderCredentialID, result.CredentialID)
		if result.SellerID != "" {
			r.Header.Set(gatewayctx.HeaderTenant, "wildberries:"+result.SellerID)
		}
		if err := gatewayctx.SetCaller(r.Header, result.Identity); err != nil {
			apierror.New(apierror.CodeUpstreamError, http.StatusBadGateway, "authentication service unavailable").Write(w)
			return
		}
		next.ServeHTTP(w, withSource(r, result.Identity, result.validUntil))
	})
}

func (v *TokenValidator) introspect(r *http.Request, cfg TokenConfig, raw string) (tokenResult, error) {
	now := time.Now()
	cacheable := cfg.Mode == "" || cfg.Mode == "token"
	var cacheKey string
	if cacheable {
		digest := sha256.Sum256([]byte(raw))
		cacheKey = cfg.Endpoint + ":" + hex.EncodeToString(digest[:])
		v.mu.RLock()
		entry, ok := v.cache[cacheKey]
		v.mu.RUnlock()
		if !cfg.FreshValidation && ok && now.Before(entry.expiresAt) && now.Before(entry.fetchedAt.Add(cfg.CacheTTL)) {
			entry.result.validUntil = entry.expiresAt
			if current := entry.fetchedAt.Add(cfg.CacheTTL); current.Before(entry.result.validUntil) {
				entry.result.validUntil = current
			}
			return entry.result, nil
		}
	}
	payload := map[string]string{"token": raw}
	var result tokenResult
	if err := v.postIntrospection(r, cfg.Endpoint, payload, &result); err != nil {
		return tokenResult{}, err
	}

	if result.Active {
		if err := validateIssuerCaller(result.Identity, result.Subject, result.CredentialID, caller.APIKey); err != nil {
			return tokenResult{}, err // Never cache inconsistent issuer metadata.
		}
		result.validUntil = result.ExpiresAt
	}
	if cacheable && !result.Active {
		v.mu.Lock()
		delete(v.cache, cacheKey)
		v.mu.Unlock()
	}
	if cacheable && result.Active && result.ExpiresAt.After(now) {
		expires := now.Add(cfg.CacheTTL)
		if result.ExpiresAt.Before(expires) {
			expires = result.ExpiresAt
		}
		result.validUntil = expires
		v.mu.Lock()
		if len(v.cache) >= maxTokenCacheEntries {
			for key := range v.cache {
				if !now.Before(v.cache[key].expiresAt) {
					delete(v.cache, key)
				}
			}
			if len(v.cache) >= maxTokenCacheEntries {
				// Keep memory bounded under many distinct keys. A miss only adds
				// one authn lookup; it never changes the authorization result.
				v.cache = make(map[string]tokenCacheEntry)
			}
		}
		v.cache[cacheKey] = tokenCacheEntry{result: result, fetchedAt: now, expiresAt: expires}
		v.mu.Unlock()
	}
	return result, nil
}

func (v *TokenValidator) reject(w http.ResponseWriter, status int, message string) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="aurum-api"`)
	code := apierror.CodeAuthFailed
	if status == http.StatusForbidden {
		code = apierror.CodeAccessDenied
	}
	apierror.New(code, status, message).Write(w)
}

func clearCredentials(r *http.Request) {
	r.Header.Del("Authorization")
	r.Header.Del("Cookie")
	r.Header.Del(gatewayctx.HeaderCsarAuthorization)
}

func (v *TokenValidator) postIntrospection(r *http.Request, endpoint string, payload, result any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := v.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("introspection returned HTTP %d", resp.StatusCode)
	}

	if _, v2 := result.(*authntokens.DelegationResultV2); v2 {
		return httpx.ReadStrictJSON(&http.Request{Body: http.MaxBytesReader(nil, resp.Body, 16<<10)}, result)
	}
	if err := decodeTokenResponse(resp.Body, result); err != nil {
		return fmt.Errorf("decode introspection: %w", err)
	}
	return nil
}

func decodeTokenResponse(body io.Reader, result any) error {
	const limit = 16 << 10
	buf, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return err
	}
	if len(buf) > limit {
		return fmt.Errorf("introspection response too large")
	}
	return json.Unmarshal(buf, result)
}
