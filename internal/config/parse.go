package config

import (
	"fmt"
	"reflect"

	"gopkg.in/yaml.v3"
)

// ParseBytes parses a CSAR YAML config from raw bytes without include support.
//
// This function is designed for configs loaded from remote sources (S3, HTTP)
// where file-system-based include resolution is not possible. If the parsed
// config contains an `include` directive, an error is returned.
//
// The processing pipeline is identical to Load():
//
//	unmarshal → env expansion → policy resolution → validation
func ParseBytes(data []byte) (*Config, error) {
	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	// Include directives require file-system access and are not supported
	// for remote config sources.
	if len(cfg.Include) > 0 {
		return nil, fmt.Errorf("include directives are not supported for remote config sources (found %d include(s))", len(cfg.Include))
	}

	// Expand environment variables in all string fields AFTER unmarshaling.
	expandEnvInStruct(reflect.ValueOf(cfg).Elem())

	if err := cfg.resolveAndValidate(); err != nil {
		return nil, err
	}

	return cfg, nil
}
