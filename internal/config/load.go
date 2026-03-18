package config

import (
	"fmt"
	"reflect"
)

// Load reads and parses a CSAR config file from the given path.
// If the config contains an `include` directive, referenced files are
// recursively loaded and merged before the main config is processed.
//
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
	// Recursive load with cycle detection and merge.
	l := &loader{registry: make(map[string]*Config)}
	cfg, err := l.loadRoot(path)
	if err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}

	// Expand environment variables in all string fields AFTER unmarshaling.
	// This is YAML-injection-safe: env var values cannot alter the parsed
	// configuration structure regardless of their content.
	expandEnvInStruct(reflect.ValueOf(cfg).Elem())

	if err := cfg.resolveAndValidate(); err != nil {
		return nil, err
	}

	return cfg, nil
}
