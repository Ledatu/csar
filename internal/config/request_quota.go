package config

import (
	"fmt"
	"regexp"
	"time"
)

// RequestQuota is an additional rolling request cap, independent of GCRA burst.
// Name and Key stay stable across reloads so limit changes retain spent attempts.
type RequestQuota struct {
	Name     string   `yaml:"name" json:"name"`
	Key      string   `yaml:"key" json:"key"`
	Requests int      `yaml:"requests" json:"requests"`
	Window   Duration `yaml:"window" json:"window"`
}

var quotaName = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,64}$`)

func (c *Config) ValidateRequestQuotas() error {
	seen := map[string]RequestQuota{}
	for path, methods := range c.Paths {
		for method := range methods {
			t := methods[method].Traffic
			if t == nil || len(t.Quotas) == 0 {
				continue
			}
			if t.Backend != "redis" || t.Key == "" || t.MaxWait.Duration != 0 || len(t.VIPOverrides) > 0 || len(t.ExcludeIPs) > 0 || len(t.Quotas) > 8 {
				return fmt.Errorf("route %s %s: request quotas require dynamic Redis admission without waits or bypasses", method, path)
			}
			names := map[string]bool{}
			for _, q := range t.Quotas {
				if !quotaName.MatchString(q.Name) || q.Key == "" || len(q.Key) > 256 || q.Key != t.Quotas[0].Key || names[q.Name] || q.Requests < 1 || q.Requests > 10000 || q.Window.Duration < time.Second || q.Window.Duration > 24*time.Hour {
					return fmt.Errorf("route %s %s: invalid request quota", method, path)
				}
				names[q.Name] = true
				if prior, ok := seen[q.Name]; ok && prior != q {
					return fmt.Errorf("request quota %s has conflicting limits", q.Name)
				}
				seen[q.Name] = q
			}
		}
	}
	return nil
}
