// Package authzmw provides HTTP middleware for csar-authz integration.
// It strips spoofable headers, resolves placeholders, calls CheckAccess for
// each configured branch, and injects enriched headers into the upstream
// request when a branch allows.
package authzmw

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/ledatu/csar-core/gatewayctx"
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

// Checker evaluates one access check against csar-authz.
type Checker interface {
	CheckAccess(ctx context.Context, req *authzv1.CheckAccessRequest) (*authz.CheckAccessResult, error)
}

// Middleware wraps an http.Handler with authz checking.
type Middleware struct {
	client    Checker
	requestID func(*http.Request) string
}

// New creates an authz Middleware.
func New(client Checker, requestIDFn func(*http.Request) string) *Middleware {
	return &Middleware{client: client, requestID: requestIDFn}
}

// Wrap returns an http.Handler that enforces authz before calling next.
//
// A single-check route behaves as before: an unresolvable placeholder is a
// 400, a deny is a 403. A composite route (any_of) evaluates its branches in
// order and lets the first allow through; a branch whose placeholders cannot
// be resolved is skipped so that, for example, a tenant branch keyed on a
// header a platform user never sends still falls through to the platform
// branch. The route is a 400 only when no branch could be evaluated at all.
func (m *Middleware) Wrap(cfg Config, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, h := range cfg.RouteConfig.StripHeaders {
			r.Header.Del(h)
		}

		pathVars := PathVarsFromContext(r.Context())
		branches := cfg.RouteConfig.Branches()
		single := !cfg.RouteConfig.IsComposite()

		var (
			evaluated  int
			resolveErr error
		)
		for i := range branches {
			branch := &branches[i]
			req, err := buildCheckRequest(branch, r, pathVars)
			if err != nil {
				if single {
					m.writeResolveError(w, r, err)
					return
				}
				resolveErr = err
				continue
			}
			evaluated++

			result, err := m.client.CheckAccess(r.Context(), req)
			if err != nil {
				apierror.New(apierror.CodeUpstreamError, http.StatusBadGateway,
					"authz service unavailable").WithDetail(err.Error()).
					WithRequestID(m.requestID(r)).Write(w)
				return
			}
			if !result.Allowed {
				continue
			}

			for k, v := range result.EnrichedHeaders {
				r.Header.Set(k, v)
			}
			if branch.PolicyName != "" {
				r.Header.Set(gatewayctx.HeaderAuthzPolicy, branch.PolicyName)
			}
			next.ServeHTTP(w, r)
			return
		}

		if evaluated == 0 {
			m.writeResolveError(w, r, resolveErr)
			return
		}
		apierror.New(apierror.CodeAccessDenied, http.StatusForbidden,
			"access denied by authorization policy").
			WithRequestID(m.requestID(r)).Write(w)
	})
}

// resolveFieldError reports which authz field could not be resolved.
type resolveFieldError struct {
	field string
	err   error
}

func (e *resolveFieldError) Error() string { return e.err.Error() }
func (e *resolveFieldError) Unwrap() error { return e.err }

func (m *Middleware) writeResolveError(w http.ResponseWriter, r *http.Request, err error) {
	msg := "authz: cannot resolve policy"
	var fe *resolveFieldError
	if errors.As(err, &fe) {
		msg = "authz: cannot resolve " + fe.field
	}
	apierror.New(apierror.CodeAuthFailed, http.StatusBadRequest, msg).
		WithDetail(err.Error()).
		WithRequestID(m.requestID(r)).Write(w)
}

// buildCheckRequest resolves every placeholder of one branch into a CheckAccess request.
func buildCheckRequest(branch *config.AuthzRouteConfig, r *http.Request, pathVars map[string]string) (*authzv1.CheckAccessRequest, error) {
	subject, err := resolveField("subject", branch.Subject, r, pathVars)
	if err != nil {
		return nil, err
	}
	resource, err := resolveField("resource", branch.Resource, r, pathVars)
	if err != nil {
		return nil, err
	}
	action, err := resolveField("action", branch.Action, r, pathVars)
	if err != nil {
		return nil, err
	}
	scopeID := ""
	if branch.ScopeID != "" {
		scopeID, err = resolveField("scope_id", branch.ScopeID, r, pathVars)
		if err != nil {
			return nil, err
		}
	}
	return &authzv1.CheckAccessRequest{
		Subject:   subject,
		Resource:  resource,
		Action:    action,
		ScopeType: branch.ScopeType,
		ScopeId:   scopeID,
	}, nil
}

func resolveField(field, tmpl string, r *http.Request, pathVars map[string]string) (string, error) {
	val, err := resolvePlaceholder(tmpl, r, pathVars)
	if err != nil {
		return "", &resolveFieldError{field: field, err: err}
	}
	return val, nil
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
