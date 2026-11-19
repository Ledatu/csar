package router

import (
	"fmt"
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

func credentialRejectionSelections(keys []string, routes []config.FlatRoute) (map[string]struct{}, error) {
	selected := make(map[string]struct{}, len(keys))
	for _, key := range keys {
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
		if len(match.Route.Security) != 1 || match.Route.Security[0].TokenRef == "" || match.Route.Security[0].InjectHeader == "" {
			return nil, fmt.Errorf("credential rejection route %q requires exactly one injected credential ref", key)
		}
		selected[key] = struct{}{}
	}
	return selected, nil
}
