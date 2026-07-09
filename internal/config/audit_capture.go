package config

import "fmt"

const defaultAuditCaptureMaxBytes = 16 * 1024

// ResolveAuditCapturePolicies replaces audit capture policy references with
// merged inline configs. Must be called after Load / before Validate.
func (c *Config) ResolveAuditCapturePolicies() error {
	global := c.auditCaptureDefaults()

	for path, methods := range c.Paths {
		for method := range methods {
			route := methods[method]
			if route.AuditCapture == nil {
				continue
			}

			merged, err := c.resolveAuditCaptureRoute(route.AuditCapture, global)
			if err != nil {
				return fmt.Errorf("path %s method %s: %w", path, method, err)
			}
			if route.AuditCapture.Use != "" {
				annotatePolicy(&route, "x-csar-audit-capture", route.AuditCapture.Use)
			}
			merged.Use = ""
			route.AuditCapture = &merged
			methods[method] = route
		}
	}
	return nil
}

func (c *Config) auditCaptureDefaults() AuditCaptureConfig {
	if c.Audit == nil || c.Audit.Capture == nil {
		return AuditCaptureConfig{
			MaxBytes: defaultAuditCaptureMaxBytes,
			Mask:     jsonredactDefaultMask(),
		}
	}
	d := *c.Audit.Capture
	if d.MaxBytes <= 0 {
		d.MaxBytes = defaultAuditCaptureMaxBytes
	}
	if d.Mask == "" {
		d.Mask = jsonredactDefaultMask()
	}
	return d
}

func jsonredactDefaultMask() string {
	return "[REDACTED]"
}

func (c *Config) resolveAuditCaptureRoute(route *AuditCaptureConfig, global AuditCaptureConfig) (AuditCaptureConfig, error) {
	var merged AuditCaptureConfig

	if route.Use != "" {
		if len(c.AuditCapturePolicies) == 0 {
			return merged, fmt.Errorf("audit capture policy %q referenced but no audit_capture_policies defined", route.Use)
		}
		policy, ok := c.AuditCapturePolicies[route.Use]
		if !ok {
			return merged, fmt.Errorf("audit capture policy %q not found in audit_capture_policies", route.Use)
		}
		merged = policy
	}

	// Shallow merge: inline route fields override policy/global.
	if route.Request != nil {
		merged.Request = route.Request
	}
	if route.MaxBytes > 0 {
		merged.MaxBytes = route.MaxBytes
	}
	if route.Redact != "" {
		merged.Redact = route.Redact
	}
	if len(route.Fields) > 0 {
		merged.Fields = route.Fields
	}
	if route.IncludeQuery != nil {
		merged.IncludeQuery = route.IncludeQuery
	}
	if route.Mask != "" {
		merged.Mask = route.Mask
	}

	if merged.MaxBytes <= 0 {
		merged.MaxBytes = global.MaxBytes
	}
	if merged.Mask == "" {
		merged.Mask = global.Mask
	}
	if merged.IncludeQuery == nil && global.IncludeQuery != nil {
		merged.IncludeQuery = global.IncludeQuery
	}
	if len(merged.SensitiveFields) == 0 && len(global.SensitiveFields) > 0 {
		merged.SensitiveFields = append([]string(nil), global.SensitiveFields...)
	}

	// Resolve redact policy ref into inline fields.
	if merged.Redact != "" {
		if len(c.RedactPolicies) == 0 {
			return merged, fmt.Errorf("audit capture redact policy %q referenced but no redact_policies defined", merged.Redact)
		}
		rp, ok := c.RedactPolicies[merged.Redact]
		if !ok {
			return merged, fmt.Errorf("audit capture redact policy %q not found in redact_policies", merged.Redact)
		}
		if len(rp.Fields) > 0 {
			merged.Fields = appendUniqueStringFields(merged.Fields, rp.Fields...)
		}
		if rp.Mask != "" && merged.Mask == global.Mask {
			merged.Mask = rp.Mask
		}
		merged.Redact = ""
	}

	return merged, nil
}

func appendUniqueStringFields(base []string, extra ...string) []string {
	seen := make(map[string]struct{}, len(base))
	for _, s := range base {
		seen[s] = struct{}{}
	}
	for _, s := range extra {
		if _, ok := seen[s]; !ok {
			base = append(base, s)
			seen[s] = struct{}{}
		}
	}
	return base
}

// CaptureRequestEnabled reports whether request body capture is active.
func (c AuditCaptureConfig) CaptureRequestEnabled() bool {
	return c.Request != nil && *c.Request
}

// IncludeQueryEnabled reports whether query params should be captured.
func (c AuditCaptureConfig) IncludeQueryEnabled() bool {
	return c.IncludeQuery == nil || *c.IncludeQuery
}

// RedactionEnabled reports whether captured payloads should be redacted.
// Policies without redact refs, fields, or sensitive_fields store raw values.
func (c AuditCaptureConfig) RedactionEnabled() bool {
	return len(c.Fields) > 0 || len(c.SensitiveFields) > 0
}
