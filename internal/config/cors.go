package config

import "fmt"

// ResolveCORSPolicies replaces CORS policy references with the full
// CORSConfig from cors_policies. Inline fields override policy values
// (shallow merge). Must be called after Load / before Validate.
func (c *Config) ResolveCORSPolicies() error {
	for path, methods := range c.Paths {
		for method := range methods {
			route := methods[method]
			if route.CORS == nil || route.CORS.Use == "" {
				continue
			}
			policyName := route.CORS.Use
			if len(c.CORSPolicies) == 0 {
				return fmt.Errorf("path %s method %s: CORS policy %q referenced but no cors_policies defined",
					path, method, policyName)
			}
			policy, ok := c.CORSPolicies[policyName]
			if !ok {
				return fmt.Errorf("path %s method %s: CORS policy %q not found in cors_policies",
					path, method, policyName)
			}
			merged := policy
			if len(route.CORS.AllowedOrigins) > 0 {
				merged.AllowedOrigins = route.CORS.AllowedOrigins
			}
			if len(route.CORS.AllowedMethods) > 0 {
				merged.AllowedMethods = route.CORS.AllowedMethods
			}
			if len(route.CORS.AllowedHeaders) > 0 {
				merged.AllowedHeaders = route.CORS.AllowedHeaders
			}
			if len(route.CORS.ExposedHeaders) > 0 {
				merged.ExposedHeaders = route.CORS.ExposedHeaders
			}
			if route.CORS.AllowCredentials {
				merged.AllowCredentials = route.CORS.AllowCredentials
			}
			if route.CORS.MaxAge != 0 {
				merged.MaxAge = route.CORS.MaxAge
			}
			merged.Use = ""
			route.CORS = &merged
			annotatePolicy(&route, "x-csar-cors", policyName)
			methods[method] = route
		}
	}
	return nil
}
