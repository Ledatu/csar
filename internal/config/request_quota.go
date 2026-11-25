package config

import (
	"fmt"

	"github.com/ledatu/csar/internal/requestquota"
)

// RequestQuota is an additional rolling request cap, independent of GCRA burst.
// Name and Key stay stable across reloads so limit changes retain spent attempts.
type RequestQuota struct {
	Name     string   `yaml:"name" json:"name"`
	Key      string   `yaml:"key" json:"key"`
	Requests int      `yaml:"requests" json:"requests"`
	Window   Duration `yaml:"window" json:"window"`
}

func (c *Config) ValidateRequestQuotas() error {
	seen := map[string]RequestQuota{}
	for path, methods := range c.Paths {
		for method := range methods {
			t := methods[method].Traffic
			if t == nil || len(t.Quotas) == 0 {
				continue
			}
			if t.Backend != "redis" || t.Key == "" || t.MaxWait.Duration != 0 || len(t.VIPOverrides) > 0 || len(t.ExcludeIPs) > 0 {
				return fmt.Errorf("route %s %s: request quotas require dynamic Redis admission without waits or bypasses", method, path)
			}
			route := methods[method]
			if route.Retry != nil && route.Retry.MaxAttempts != 1 {
				return fmt.Errorf("route %s %s: request quotas require a single upstream attempt", method, path)
			}
			if route.TransparentRetryEnabled() {
				return fmt.Errorf("route %s %s: request quotas forbid transparent retries", method, path)
			}
			policies := make([]requestquota.Policy, len(t.Quotas))
			for i, q := range t.Quotas {
				policies[i] = requestquota.Policy{Name: q.Name, Key: q.Key, Requests: q.Requests, Window: q.Window.Duration}
			}
			if err := requestquota.Validate(policies); err != nil {
				return fmt.Errorf("route %s %s: %w", method, path, err)
			}
			for _, q := range t.Quotas {
				if prior, ok := seen[q.Name]; ok && prior != q {
					return fmt.Errorf("request quota %s has conflicting limits", q.Name)
				}
				seen[q.Name] = q
			}
		}
	}
	return nil
}
