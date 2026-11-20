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

	"github.com/ledatu/csar-core/gatewayctx"
	"github.com/ledatu/csar/internal/apierror"
	"github.com/ledatu/csar/pkg/middleware/authzmw"
)

const defaultTokenCacheTTL = 15 * time.Second
const maxTokenCacheEntries = 10000

type TokenConfig struct {
	Mode            string
	Endpoint        string
	RequiredScope   string
	SellerPathParam string
	CacheTTL        time.Duration
}

type tokenResult struct {
	AccountGrant   bool      `json:"account_grant"`
	Discovery      bool      `json:"discovery"`
	DelegatedToken string    `json:"delegated_token"`
	Active         bool      `json:"active"`
	Subject        string    `json:"subject"`
	CredentialID   string    `json:"credential_id"`
	SellerID       string    `json:"seller_id"`
	Scopes         []string  `json:"scopes"`
	ExpiresAt      time.Time `json:"expires_at"`
}

type tokenCacheEntry struct {
	result    tokenResult
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
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = defaultTokenCacheTTL
	}
	if cfg.SellerPathParam == "" {
		cfg.SellerPathParam = "seller_id"
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header, prefix := "Authorization", "aurum_pat_"
		switch cfg.Mode {
		case "mcp", "mcp-account":
			prefix = "aurum_mcp_"
		case "delegated", "delegated-discovery":
			header, prefix = gatewayctx.HeaderCsarAuthorization, "aurum_dlg_"
		}
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
		switch cfg.Mode {
		case "mcp":
			if result.SellerID == "" {
				v.reject(w, 403, "missing grant")
				return
			}
		case "mcp-account":
			if !result.AccountGrant {
				v.reject(w, http.StatusForbidden, "account grant required")
				return
			}
		case "delegated-discovery":
			if !result.Discovery || !result.AccountGrant {
				v.reject(w, 403, "discovery grant required")
				return
			}
		default:
			if result.Discovery || result.SellerID == "" || vars[cfg.SellerPathParam] != result.SellerID {
				v.reject(w, 403, "cabinet not allowed for this key")
				return
			}
		}
		// Credentials are consumed at the edge, even if the backend is another
		// trusted service. Only verified gateway context is forwarded.
		r.Header.Del("Authorization")
		r.Header.Del("Cookie")
		r.Header.Del(gatewayctx.HeaderCsarAuthorization)
		if cfg.Mode == "mcp" || cfg.Mode == "mcp-account" {
			if !strings.HasPrefix(result.DelegatedToken, "aurum_dlg_") || len(result.DelegatedToken) != len("aurum_dlg_")+43 {
				v.reject(w, http.StatusUnauthorized, "delegation unavailable")
				return
			}
			r.Header.Set("Authorization", "Bearer "+result.DelegatedToken)
		}
		r.Header.Set(gatewayctx.HeaderScopes, cfg.RequiredScope)
		r.Header.Set(gatewayctx.HeaderSubject, result.Subject)
		r.Header.Set(gatewayctx.HeaderCredentialID, result.CredentialID)
		if result.SellerID != "" && cfg.Mode != "delegated-discovery" {
			r.Header.Set(gatewayctx.HeaderTenant, "wildberries:"+result.SellerID)
		}
		next.ServeHTTP(w, r)
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
		if ok && now.Before(entry.expiresAt) {
			return entry.result, nil
		}
	}
	payload := map[string]string{"token": raw}
	if cfg.Mode == "delegated" {
		seller := authzmw.PathVarsFromContext(r.Context())[cfg.SellerPathParam]
		if seller == "" {
			return tokenResult{}, nil
		}
		payload["seller_id"] = seller
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return tokenResult{}, err
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, cfg.Endpoint, bytes.NewReader(body))
	if err != nil {
		return tokenResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := v.client.Do(req)
	if err != nil {
		return tokenResult{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return tokenResult{}, fmt.Errorf("introspection returned HTTP %d", resp.StatusCode)
	}
	var result tokenResult
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&result); err != nil {
		return tokenResult{}, fmt.Errorf("decode introspection: %w", err)
	}
	if cacheable && result.Active && result.ExpiresAt.After(now) {
		expires := now.Add(cfg.CacheTTL)
		if result.ExpiresAt.Before(expires) {
			expires = result.ExpiresAt
		}
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
		v.cache[cacheKey] = tokenCacheEntry{result: result, expiresAt: expires}
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
