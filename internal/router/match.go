package router

import (
	"regexp"
	"strings"

	"github.com/ledatu/csar/internal/throttle"
)

// maxRegexLength is the maximum allowed length for a compiled regex pattern string.
// This prevents ReDoS attacks from overly complex regex configurations (audit §2.2.4).
const maxRegexLength = 1024

// dangerousPatterns detects regex constructs known to cause catastrophic backtracking.
// These include nested quantifiers like (a+)+, (a*)+, (a+)*, etc.
var dangerousPatterns = regexp.MustCompile(`\([^)]*[+*][^)]*\)[+*]|\(\?[^)]*\)[+*]`)

// matchRoute finds the best matching route for the given method and path.
// Priority order: exact match → prefix match → regex match.
func (r *Router) matchRoute(method, path string) (*route, []string) {
	method = strings.ToUpper(method)

	// Try exact match first
	key := throttle.RouteKey(method, path)
	if rt, ok := r.routes[key]; ok {
		return rt, nil
	}

	// Try prefix match: check if any registered path is a prefix
	// e.g. "/api/v1" matches a route registered as "/api/v1"
	// and "/api/v1/foo" matches "/api/v1" if it's a prefix route
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

	// Try regex routes (audit §3.2: path rewriting & regex matching)
	for _, rt := range r.regexRoutes {
		if rt.method != method {
			continue
		}
		if matches := rt.pathPattern.FindStringSubmatch(path); matches != nil {
			return rt, matches
		}
	}

	return nil, nil
}

// compilePathPattern converts a path containing {var:regex} segments into a
// compiled regexp. Returns the regexp and true if the path has regex variables,
// or nil and false for plain paths.
//
// Security audit §2.2.4: Validates regex complexity to prevent ReDoS attacks.
// Rejects patterns that are too long or contain known catastrophic backtracking constructs.
//
// Examples:
//
//	"/api/v1/users/{id:[0-9]+}"       → "^/api/v1/users/([0-9]+)$"
//	"/api/{version:v[0-9]+}/items/{id}" → "^/api/(v[0-9]+)/items/([^/]+)$"
//	"/api/v1/products"                → nil, false (no variables)
func compilePathPattern(path string) (*regexp.Regexp, []string, bool) {
	// Quick check: if no '{' then no variables.
	if !strings.Contains(path, "{") {
		return nil, nil, false
	}

	var b strings.Builder
	var varNames []string
	b.WriteString("^")

	i := 0
	for i < len(path) {
		brace := strings.IndexByte(path[i:], '{')
		if brace < 0 {
			b.WriteString(regexp.QuoteMeta(path[i:]))
			break
		}
		// Write literal part before the brace
		b.WriteString(regexp.QuoteMeta(path[i : i+brace]))

		// Find closing brace
		rest := path[i+brace:]
		closeBrace := strings.IndexByte(rest, '}')
		if closeBrace < 0 {
			b.WriteString(regexp.QuoteMeta(rest))
			break
		}

		// Extract variable content: "name:pattern" or just "name"
		varContent := rest[1:closeBrace]
		if colonIdx := strings.IndexByte(varContent, ':'); colonIdx >= 0 {
			// Has explicit regex: {name:pattern}
			varNames = append(varNames, varContent[:colonIdx])
			userPattern := varContent[colonIdx+1:]

			// ReDoS protection: reject dangerous patterns (audit §2.2.4).
			if dangerousPatterns.MatchString(userPattern) {
				return nil, nil, false
			}

			b.WriteString("(")
			b.WriteString(userPattern)
			b.WriteString(")")
		} else {
			// Plain variable: {name} → match any non-slash segment
			varNames = append(varNames, varContent)
			b.WriteString("([^/]+)")
		}

		i += brace + closeBrace + 1
	}

	b.WriteString("$")

	pattern := b.String()

	// ReDoS protection: reject overly long patterns (audit §2.2.4).
	if len(pattern) > maxRegexLength {
		return nil, nil, false
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, nil, false
	}
	return re, varNames, true
}
