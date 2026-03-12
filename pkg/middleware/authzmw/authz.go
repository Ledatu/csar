// Package authzmw provides HTTP middleware for csar-authz integration.
// It strips spoofable headers, resolves placeholders, calls CheckAccess,
// and injects enriched headers into the upstream request.
package authzmw

import (
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

// pathVarRe matches named path variables like {varname} or {varname:pattern}.
var pathVarRe = regexp.MustCompile(`\{([^:}]+)(?::[^}]+)?\}`)

// Config holds the per-route authz middleware configuration.
type Config struct {
	RouteConfig  *config.AuthzRouteConfig
	OriginalPath string // route definition path (e.g. "/api/v1/users/{id:[0-9]+}")
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
	pathVarNames := extractPathVarNames(cfg.OriginalPath)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, h := range cfg.RouteConfig.StripHeaders {
			r.Header.Del(h)
		}

		pathVars := resolvePathVars(cfg.OriginalPath, pathVarNames, r.URL.Path)

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

// extractPathVarNames returns the ordered list of variable names from a route path.
func extractPathVarNames(routePath string) []string {
	matches := pathVarRe.FindAllStringSubmatch(routePath, -1)
	names := make([]string, 0, len(matches))
	for _, m := range matches {
		names = append(names, m[1])
	}
	return names
}

// resolvePathVars extracts named path variables by segment comparison between
// the route definition and the actual request path.
func resolvePathVars(routePath string, varNames []string, actualPath string) map[string]string {
	if len(varNames) == 0 {
		return nil
	}

	routeSegments := strings.Split(strings.Trim(routePath, "/"), "/")
	actualSegments := strings.Split(strings.Trim(actualPath, "/"), "/")

	vars := make(map[string]string, len(varNames))
	varIdx := 0
	for i, seg := range routeSegments {
		if varIdx >= len(varNames) {
			break
		}
		if i >= len(actualSegments) {
			break
		}
		if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
			vars[varNames[varIdx]] = actualSegments[i]
			varIdx++
		}
	}
	return vars
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
			val = r.URL.Query().Get(key)
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
