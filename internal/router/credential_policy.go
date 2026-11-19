package router

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/ledatu/csar/internal/config"
	"github.com/ledatu/csar/internal/throttle"
	"golang.org/x/net/http/httpguts"
)

// WithCredentialRejectionRoutes opts exact configured route keys into upstream
// 401 credential quarantine. Other routes do not report or locally quarantine.
// The selection is validated against every new route table, including reloads.
func WithCredentialRejectionRoutes(keys ...string) Option {
	snapshot := append([]string(nil), keys...)
	return func(r *Router) { r.credentialRejectionRoutes = snapshot }
}

func credentialRejectionSelections(keys []string, routes []config.FlatRoute) (map[string]string, error) {
	selected := make(map[string]string, len(keys))
	for _, selection := range keys {
		key, header, explicit := strings.Cut(selection, "#")
		if explicit && !httpguts.ValidHeaderFieldName(header) {
			return nil, fmt.Errorf("credential rejection selection %q has an invalid header", selection)
		}
		method, path, ok := strings.Cut(key, ":")
		if !ok || !httpguts.ValidHeaderFieldName(method) || method != strings.ToUpper(method) || !strings.HasPrefix(path, "/") || strings.TrimSpace(key) != key {
			return nil, fmt.Errorf("credential rejection route %q must use METHOD:/configured/path", key)
		}
		if _, duplicate := selected[key]; duplicate {
			return nil, fmt.Errorf("duplicate credential rejection route %q", key)
		}
		var match *config.FlatRoute
		for i := range routes {
			candidate := &routes[i]
			if throttle.RouteKey(strings.ToUpper(candidate.Method), candidate.Path) != key {
				continue
			}
			if match != nil {
				return nil, fmt.Errorf("ambiguous credential rejection route %q", key)
			}
			match = candidate
		}
		if match == nil {
			return nil, fmt.Errorf("credential rejection route %q is not configured", key)
		}
		if !explicit && len(match.Route.Security) != 1 {
			return nil, fmt.Errorf("credential rejection route %q requires one injected credential or an explicit #Header target", key)
		}
		matches := 0
		for _, entry := range match.Route.Security {
			if explicit && !strings.EqualFold(entry.InjectHeader, header) {
				continue
			}
			if entry.TokenRef == "" || !httpguts.ValidHeaderFieldName(entry.InjectHeader) {
				return nil, fmt.Errorf("credential rejection route %q has an invalid target", key)
			}
			matches++
			if !explicit {
				header = entry.InjectHeader
			}
		}
		if matches != 1 {
			return nil, fmt.Errorf("credential rejection route %q must identify exactly one injected header", key)
		}
		selected[key] = http.CanonicalHeaderKey(header)
	}
	return selected, nil
}
