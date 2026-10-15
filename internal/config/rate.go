package config

import (
	"fmt"
	"math"

	"gopkg.in/yaml.v3"
)

// validateRateSyntax checks presence before decoding loses explicit zero/null
// values, and rejects fractional counts that yaml.v3 would truncate to int.
// Decoding a map also handles YAML aliases and merge keys.
func validateRateSyntax(node *yaml.Node, legacy string) error {
	var fields map[string]any
	if err := node.Decode(&fields); err != nil {
		return err
	}
	count, hasCount := fields["requests"]
	period, hasPeriod := fields["period"]
	if !hasCount && !hasPeriod {
		return nil
	}
	if _, exists := fields[legacy]; exists {
		return fmt.Errorf("%s and requests/period are mutually exclusive", legacy)
	}
	if !hasCount || !hasPeriod || count == nil || period == nil {
		return fmt.Errorf("requests and period must both be set")
	}
	switch n := count.(type) {
	case int, uint64:
	case float64:
		if math.IsNaN(n) || math.IsInf(n, 0) || math.Trunc(n) != n {
			return fmt.Errorf("requests must be an integer")
		}
	default:
		return fmt.Errorf("requests must be an integer")
	}
	return nil
}

// normalizeRate consumes authoring units. Runtime consumers, compiled YAML and
// the coordinator protocol continue to use the existing per-second field.
func normalizeRate(rps *float64, requests **int, period **Duration) error {
	if *requests != nil || *period != nil {
		if *requests == nil || *period == nil {
			return fmt.Errorf("requests and period must both be set")
		}
		if *rps != 0 {
			return fmt.Errorf("per-second rate and requests/period are mutually exclusive")
		}
		if **requests <= 0 || (*period).Duration <= 0 {
			return fmt.Errorf("requests and period must be > 0")
		}
		*rps = float64(**requests) / (*period).Seconds()
		*requests, *period = nil, nil
	}
	if math.IsNaN(*rps) || math.IsInf(*rps, 0) || *rps < 0 {
		return fmt.Errorf("per-second rate must be finite and non-negative")
	}
	return nil
}

// UnmarshalYAML accepts either the legacy rate or the requests/period pair.
func (p *ThrottlingPolicy) UnmarshalYAML(node *yaml.Node) error {
	type plain ThrottlingPolicy
	var decoded plain
	if err := node.Decode(&decoded); err != nil {
		return err
	}
	if err := validateRateSyntax(node, "rate"); err != nil {
		return err
	}
	*p = ThrottlingPolicy(decoded)
	return nil
}

// UnmarshalYAML accepts either the legacy rate or the requests/period pair.
func (g *GlobalThrottleConfig) UnmarshalYAML(node *yaml.Node) error {
	type plain GlobalThrottleConfig
	var decoded plain
	if err := node.Decode(&decoded); err != nil {
		return err
	}
	if err := validateRateSyntax(node, "rate"); err != nil {
		return err
	}
	*g = GlobalThrottleConfig(decoded)
	return nil
}
