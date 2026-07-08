package config

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// AuditMode controls when the router emits access audit events for a route.
type AuditMode string

const (
	AuditModeOff    AuditMode = "off"
	AuditModeAll    AuditMode = "all"
	AuditModeErrors AuditMode = "errors"
)

// ParseAuditMode normalizes a config value. Boolean true/false map to all/off.
func ParseAuditMode(v string) (AuditMode, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "off", "false":
		return AuditModeOff, nil
	case "all", "true":
		return AuditModeAll, nil
	case "errors":
		return AuditModeErrors, nil
	default:
		return "", fmt.Errorf("invalid audit mode %q (want off, all, or errors)", v)
	}
}

// UnmarshalYAML accepts boolean or string values for x-csar-audit.
func (m *AuditMode) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.ScalarNode {
		return fmt.Errorf("x-csar-audit must be a boolean or string")
	}
	if value.Tag == "!!bool" {
		if value.Value == "true" {
			*m = AuditModeAll
			return nil
		}
		if value.Value == "false" {
			*m = AuditModeOff
			return nil
		}
	}
	mode, err := ParseAuditMode(value.Value)
	if err != nil {
		return err
	}
	*m = mode
	return nil
}

// RequiresAuditClient reports whether the mode needs a configured audit client.
func (m AuditMode) RequiresAuditClient() bool {
	return m == AuditModeAll || m == AuditModeErrors
}

// IsActive reports whether the audit wrapper should run for this mode.
func (m AuditMode) IsActive() bool {
	return m != AuditModeOff
}
