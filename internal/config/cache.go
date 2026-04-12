package config

import "fmt"

// ResolveCachePolicies replaces cache policy references with the full
// CacheConfig from cache_policies. Scalar inline fields override policy values;
// list fields are additive, with inline TTL rules evaluated before policy rules.
func (c *Config) ResolveCachePolicies() error {
	for path, methods := range c.Paths {
		for method := range methods {
			route := methods[method]
			if route.Cache == nil || route.Cache.Use == "" {
				continue
			}
			policyName := route.Cache.Use
			if len(c.CachePolicies) == 0 {
				return fmt.Errorf("path %s method %s: cache policy %q referenced but no cache_policies defined",
					path, method, policyName)
			}
			policy, ok := c.CachePolicies[policyName]
			if !ok {
				return fmt.Errorf("path %s method %s: cache policy %q not found in cache_policies",
					path, method, policyName)
			}

			merged := mergeCachePolicy(policy, *route.Cache)
			merged.Use = ""
			route.Cache = &merged
			annotatePolicy(&route, "x-csar-cache", policyName)
			methods[method] = route
		}
	}
	return nil
}

// ResolveCacheInvalidationPolicies replaces cache invalidation policy references
// with the full CacheInvalidationConfig from cache_invalidation_policies.
func (c *Config) ResolveCacheInvalidationPolicies() error {
	for path, methods := range c.Paths {
		for method := range methods {
			route := methods[method]
			if route.CacheInvalidate == nil || route.CacheInvalidate.Use == "" {
				continue
			}
			policyName := route.CacheInvalidate.Use
			if len(c.CacheInvalidationPolicies) == 0 {
				return fmt.Errorf("path %s method %s: cache invalidation policy %q referenced but no cache_invalidation_policies defined",
					path, method, policyName)
			}
			policy, ok := c.CacheInvalidationPolicies[policyName]
			if !ok {
				return fmt.Errorf("path %s method %s: cache invalidation policy %q not found in cache_invalidation_policies",
					path, method, policyName)
			}

			merged := mergeCacheInvalidationPolicy(policy, *route.CacheInvalidate)
			merged.Use = ""
			route.CacheInvalidate = &merged
			annotatePolicy(&route, "x-csar-cache-invalidate", policyName)
			methods[method] = route
		}
	}
	return nil
}

func mergeCachePolicy(policy, inline CacheConfig) CacheConfig {
	merged := policy
	if inline.Enabled != nil {
		merged.Enabled = inline.Enabled
	}
	if inline.Store != "" {
		merged.Store = inline.Store
	}
	if inline.Key != "" {
		merged.Key = inline.Key
	}
	if inline.FailMode != "" {
		merged.FailMode = inline.FailMode
	}
	if inline.OperationTimeout.Duration != 0 {
		merged.OperationTimeout = inline.OperationTimeout
	}
	if inline.TTL.Duration != 0 {
		merged.TTL = inline.TTL
	}
	if inline.TTLJitter != "" {
		merged.TTLJitter = inline.TTLJitter
	}
	if inline.MaxEntries != 0 {
		merged.MaxEntries = inline.MaxEntries
	}
	if inline.MaxBodySize != 0 {
		merged.MaxBodySize = inline.MaxBodySize
	}
	if inline.KeyQuery != nil {
		merged.KeyQuery = inline.KeyQuery
	}
	if inline.StaleIfError.Duration != 0 {
		merged.StaleIfError = inline.StaleIfError
	}
	if inline.StaleWhileRevalidate.Duration != 0 {
		merged.StaleWhileRevalidate = inline.StaleWhileRevalidate
	}
	if inline.Bypass != nil {
		merged.Bypass = inline.Bypass
	}
	if inline.Coalesce != nil {
		merged.Coalesce = inline.Coalesce
	}
	merged.TTLRules = append(append([]CacheTTLRule(nil), inline.TTLRules...), merged.TTLRules...)
	merged.ResponseTTLRules = append(append([]CacheResponseTTLRule(nil), inline.ResponseTTLRules...), merged.ResponseTTLRules...)
	merged.Tags = appendUniqueStrings(merged.Tags, inline.Tags)
	merged.ResponseTags = append(append([]CacheResponseTag(nil), merged.ResponseTags...), inline.ResponseTags...)
	merged.Namespaces = appendUniqueStrings(merged.Namespaces, inline.Namespaces)
	merged.ContentTypes = appendUniqueStrings(merged.ContentTypes, inline.ContentTypes)
	merged.VaryHeaders = appendUniqueStrings(merged.VaryHeaders, inline.VaryHeaders)
	merged.Methods = appendUniqueStrings(merged.Methods, inline.Methods)
	merged.CacheStatuses = appendUniqueStrings(merged.CacheStatuses, inline.CacheStatuses)
	return merged
}

func mergeCacheInvalidationPolicy(policy, inline CacheInvalidationConfig) CacheInvalidationConfig {
	merged := policy
	if inline.Enabled != nil {
		merged.Enabled = inline.Enabled
	}
	if inline.Store != "" {
		merged.Store = inline.Store
	}
	if inline.OperationTimeout.Duration != 0 {
		merged.OperationTimeout = inline.OperationTimeout
	}
	if inline.Debounce.Duration != 0 {
		merged.Debounce = inline.Debounce
	}
	merged.Tags = appendUniqueStrings(merged.Tags, inline.Tags)
	merged.BumpNamespaces = appendUniqueStrings(merged.BumpNamespaces, inline.BumpNamespaces)
	merged.OnStatus = appendUniqueStrings(merged.OnStatus, inline.OnStatus)
	return merged
}

func appendUniqueStrings(base, extra []string) []string {
	if len(base) == 0 {
		return append([]string(nil), extra...)
	}
	out := append([]string(nil), base...)
	seen := make(map[string]struct{}, len(out)+len(extra))
	for _, v := range out {
		seen[v] = struct{}{}
	}
	for _, v := range extra {
		if _, ok := seen[v]; ok {
			continue
		}
		out = append(out, v)
		seen[v] = struct{}{}
	}
	return out
}
