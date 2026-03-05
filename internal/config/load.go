package config

import (
	"fmt"
	"os"
	"reflect"

	"gopkg.in/yaml.v3"
)

// Load reads and parses a CSAR config file from the given path.
// Environment variables referenced as ${VAR} or $VAR in string fields are
// expanded after YAML parsing, so secrets can be injected without hardcoding.
//
// Expansion happens post-unmarshal to prevent YAML injection: even if an
// environment variable contains YAML control characters (quotes, newlines,
// colons), they cannot corrupt the parsed configuration structure.
//
// Bare numeric references like $1, $2 are NOT expanded — these are regex
// back-references used in path_rewrite rules and must be preserved.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file %s: %w", path, err)
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config file %s: %w", path, err)
	}

	// Expand environment variables in all string fields AFTER unmarshaling.
	// This is YAML-injection-safe: env var values cannot alter the parsed
	// configuration structure regardless of their content.
	expandEnvInStruct(reflect.ValueOf(cfg).Elem())

	// Resolve security profile references before validation so that
	// Validate() sees the fully-resolved SecurityConfig for each route.
	if err := cfg.ResolveSecurityProfiles(); err != nil {
		return nil, fmt.Errorf("resolving security profiles: %w", err)
	}

	// Resolve throttle policy references before validation so that
	// Validate() sees the fully-resolved TrafficConfig for each route.
	if err := cfg.ResolveThrottlePolicies(); err != nil {
		return nil, fmt.Errorf("resolving throttle policies: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	return cfg, nil
}
