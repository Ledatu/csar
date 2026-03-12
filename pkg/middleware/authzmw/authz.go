// Package authzmw provides HTTP middleware for csar-authz integration.
// It strips spoofable headers, resolves placeholders, calls CheckAccess,
// and injects enriched headers into the upstream request.
package authzmw

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	authzv1 "github.com/ledatu/csar-proto/csar/authz/v1"
	"github.com/ledatu/csar/internal/apierror"
	"github.com/ledatu/csar/internal/authz"
	"github.com/ledatu/csar/internal/config"
)

// placeholderRe matches {source.key} patterns used in authz config templates.
var placeholderRe = regexp.MustCompile(`\{(query|header|path)\.([^}]+)\}`)

type pathVarsKey struct{}

// WithPathVars stores path variable bindings in the request context.
// Must be called before path rewriting so values reflect the original URL.
func WithPathVars(ctx context.Context, vars map[string]string) context.Context {
	return context.WithValue(ctx, pathVarsKey{}, vars)
}

// PathVarsFromContext retrieves path variable bindings from the context.
func PathVarsFromContext(ctx context.Context) map[string]string {
	vars, _ := ctx.Value(pathVarsKey{}).(map[string]string)
	return vars
}

// Config holds the per-route authz middleware configuration.
type Config struct {
	RouteConfig *config.AuthzRouteConfig
}

// Middleware wraps an http.Handler with authz checking.
type Middleware struct {
	client    *authz.Client
	requestID func(*http.Request) string
}

// New creates an authz Middleware.
func New(client *authz.Client, requestIDFn func(*http.Request) string) *Middleware {
	return &Middleware{client: client, requestID: requestIDFn}
}

// Wrap returns an http.Handler that enforces authz before calling next.
func (m *Middleware) Wrap(cfg Config, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, h := range cfg.RouteConfig.StripHeaders {
			r.Header.Del(h)
		}

		pathVars := PathVarsFromContext(r.Context())

		subject, err := resolvePlaceholder(cfg.RouteConfig.Subject, r, pathVars)
		if err != nil {
			apierror.New(apierror.CodeAuthFailed, http.StatusBadRequest,
				"authz: cannot resolve subject").WithDetail(err.Error()).
				WithRequestID(m.requestID(r)).Write(w)
			return
		}

		resource, err := resolvePlaceholder(cfg.RouteConfig.Resource, r, pathVars)
		if err != nil {
			apierror.New(apierror.CodeAuthFailed, http.StatusBadRequest,
				"authz: cannot resolve resource").WithDetail(err.Error()).
				WithRequestID(m.requestID(r)).Write(w)
			return
		}

		action, err := resolvePlaceholder(cfg.RouteConfig.Action, r, pathVars)
		if err != nil {
			apierror.New(apierror.CodeAuthFailed, http.StatusBadRequest,
				"authz: cannot resolve action").WithDetail(err.Error()).
				WithRequestID(m.requestID(r)).Write(w)
			return
		}

		scopeType := cfg.RouteConfig.ScopeType
		scopeID := ""
		if cfg.RouteConfig.ScopeID != "" {
			scopeID, err = resolvePlaceholder(cfg.RouteConfig.ScopeID, r, pathVars)
			if err != nil {
				apierror.New(apierror.CodeAuthFailed, http.StatusBadRequest,
					"authz: cannot resolve scope_id").WithDetail(err.Error()).
					WithRequestID(m.requestID(r)).Write(w)
				return
			}
		}

		result, err := m.client.CheckAccess(r.Context(), &authzv1.CheckAccessRequest{
			Subject:   subject,
			Resource:  resource,
			Action:    action,
			ScopeType: scopeType,
			ScopeId:   scopeID,
		})
		if err != nil {
			apierror.New(apierror.CodeUpstreamError, http.StatusBadGateway,
				"authz service unavailable").WithDetail(err.Error()).
				WithRequestID(m.requestID(r)).Write(w)
			return
		}

		if !result.Allowed {
			apierror.New(apierror.CodeAccessDenied, http.StatusForbidden,
				"access denied by authorization policy").
				WithRequestID(m.requestID(r)).Write(w)
			return
		}

		for k, v := range result.EnrichedHeaders {
			r.Header.Set(k, v)
		}

		next.ServeHTTP(w, r)
	})
}

// resolvePlaceholder replaces {source.key} patterns in a template string.
func resolvePlaceholder(tmpl string, r *http.Request, pathVars map[string]string) (string, error) {
	if !strings.Contains(tmpl, "{") {
		return tmpl, nil
	}

	var resolveErr error
	resolved := placeholderRe.ReplaceAllStringFunc(tmpl, func(match string) string {
		if resolveErr != nil {
			return match
		}
		submatch := placeholderRe.FindStringSubmatch(match)
		source := submatch[1]
		key := submatch[2]

		var val string
		switch source {
		case "query":
			values := r.URL.Query()[key]
			if len(values) > 1 {
				resolveErr = fmt.Errorf("duplicate query parameter %q (HTTP parameter pollution)", key)
				return match
			}
			if len(values) == 1 {
				val = values[0]
			}
		case "header":
			val = r.Header.Get(key)
		case "path":
			val = pathVars[key]
		default:
			resolveErr = fmt.Errorf("unknown placeholder source %q", source)
			return match
		}

		if val == "" {
			resolveErr = fmt.Errorf("required parameter %s.%s is missing", source, key)
			return match
		}
		return val
	})

	if resolveErr != nil {
		return "", resolveErr
	}
	return resolved, nil
}
