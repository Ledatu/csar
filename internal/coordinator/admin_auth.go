package coordinator

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/ledatu/csar/internal/authn"
)

// AdminClaims holds the extracted JWT claims relevant to admin API authorization.
type AdminClaims struct {
	Sub            string
	Iss            string
	Scope          string
	Tenant         string
	TokenPrefix    string
	AllowedKMSKeys []string
}

type adminClaimsContextKey struct{}

// AdminClaimsFromContext returns the AdminClaims stored in the request context
// by the JWT auth middleware. Returns nil if the request was not authenticated.
func AdminClaimsFromContext(ctx context.Context) *AdminClaims {
	c, _ := ctx.Value(adminClaimsContextKey{}).(*AdminClaims)
	return c
}

// AdminAuthMiddleware creates HTTP middleware that validates JWT tokens from
// csar-authn using the existing authn.JWTValidator and extracts admin-specific
// claims into the request context.
func AdminAuthMiddleware(validator *authn.JWTValidator, cfg AdminAuthConfig, logger *slog.Logger) func(http.Handler) http.Handler {
	authnCfg := authn.Config{
		JWKSURL:     cfg.JWKSUrl,
		Issuer:      cfg.Issuer,
		Audiences:   cfg.Audiences,
		HeaderName:  "Authorization",
		TokenPrefix: "Bearer ",
		CacheTTL:    5 * time.Minute,
		ForwardClaims: map[string]string{
			"sub":              "X-Admin-Sub",
			"scope":            "X-Admin-Scope",
			"tenant":           "X-Admin-Tenant",
			"token_prefix":     "X-Admin-Token-Prefix",
			"allowed_kms_keys": "X-Admin-Allowed-KMS-Keys",
		},
	}

	return func(next http.Handler) http.Handler {
		validated := validator.Wrap(authnCfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := &AdminClaims{
				Sub:         r.Header.Get("X-Admin-Sub"),
				Iss:         cfg.Issuer,
				Scope:       r.Header.Get("X-Admin-Scope"),
				Tenant:      r.Header.Get("X-Admin-Tenant"),
				TokenPrefix: r.Header.Get("X-Admin-Token-Prefix"),
			}

			if raw := r.Header.Get("X-Admin-Allowed-KMS-Keys"); raw != "" {
				claims.AllowedKMSKeys = parseKMSKeysClaim(raw)
			}

			// Clean up forwarded headers.
			r.Header.Del("X-Admin-Sub")
			r.Header.Del("X-Admin-Scope")
			r.Header.Del("X-Admin-Tenant")
			r.Header.Del("X-Admin-Token-Prefix")
			r.Header.Del("X-Admin-Allowed-KMS-Keys")

			ctx := context.WithValue(r.Context(), adminClaimsContextKey{}, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		}))

		return validated
	}
}

// parseKMSKeysClaim parses the allowed_kms_keys claim which may be either
// a JSON array string or a comma-separated list.
func parseKMSKeysClaim(raw string) []string {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "[") {
		var keys []string
		if err := json.Unmarshal([]byte(raw), &keys); err == nil {
			return keys
		}
	}
	var keys []string
	for _, k := range strings.Split(raw, ",") {
		k = strings.TrimSpace(k)
		if k != "" {
			keys = append(keys, k)
		}
	}
	return keys
}

// adminRejectJSON writes a JSON error response.
func adminRejectJSON(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"error":%q}`, message)
}
