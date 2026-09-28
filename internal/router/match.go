package router

import (
	"strings"

	"github.com/ledatu/csar/internal/throttle"
)

// matchRoute finds the best matching route for the given method and path.
// Priority order: exact match → regex match, most precise template first
// (see routepattern.SpecificityOf) → longest prefix match.
func (r *Router) matchRoute(method, path string) (*route, []string) {
	method = strings.ToUpper(method)

	// 1. Exact match (highest priority)
	key := throttle.RouteKey(method, path)
	if rt, ok := r.routes[key]; ok {
		return rt, nil
	}

	// 2. Regex/parameterised routes — these define specific path structures
	// (e.g. /admin/sessions/{session_id}/revoke) and must be evaluated before
	// generic prefix routes so that broad prefixes like /admin don't shadow them.
	// regexRoutes is sorted most precise first, so the first match is the
	// narrowest template that fits the request.
	for _, rt := range r.regexRoutes {
		if rt.method != method {
			continue
		}
		if matches := rt.pathPattern.FindStringSubmatch(path); matches != nil {
			return rt, matches
		}
	}

	// 3. Longest prefix match (fallback)
	var bestMatch *route
	bestLen := 0

	for routeKey, rt := range r.routes {
		parts := strings.SplitN(routeKey, ":", 2)
		if len(parts) != 2 {
			continue
		}
		routeMethod, routePath := parts[0], parts[1]
		if routeMethod != method {
			continue
		}

		// Match only on path boundaries: exact match OR next char is '/'.
		// This prevents "/api/v1evil" from matching route "/api/v1".
		if strings.HasPrefix(path, routePath) &&
			(len(path) == len(routePath) || path[len(routePath)] == '/') &&
			len(routePath) > bestLen {
			bestMatch = rt
			bestLen = len(routePath)
		}
	}

	if bestMatch != nil {
		return bestMatch, nil
	}

	return nil, nil
}
