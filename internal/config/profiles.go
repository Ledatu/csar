package config

import "fmt"

// ResolveSecurityProfiles replaces profile references with the full
// SecurityConfig from security_profiles. Inline fields override profile
// values (shallow merge). Must be called after Load / before Validate.
func (c *Config) ResolveSecurityProfiles() error {
	if len(c.SecurityProfiles) == 0 {
		// Fast path: no profiles defined. Verify no route references one.
		for path, methods := range c.Paths {
			for method := range methods {
				route := methods[method]
				for _, sec := range route.Security {
					if sec.Profile != "" {
						return fmt.Errorf("path %s method %s: security profile %q referenced but no security_profiles defined",
							path, method, sec.Profile)
					}
				}
			}
		}
		return nil
	}

	for path, methods := range c.Paths {
		for method := range methods {
			route := methods[method]
			for i, sec := range route.Security {
				if sec.Profile == "" {
					continue
				}
				base, ok := c.SecurityProfiles[sec.Profile]
				if !ok {
					return fmt.Errorf("path %s method %s: security profile %q not found in security_profiles",
						path, method, sec.Profile)
				}
				// Merge: inline fields override profile defaults.
				merged := base
				if sec.KMSKeyID != "" {
					merged.KMSKeyID = sec.KMSKeyID
				}
				if sec.TokenRef != "" {
					merged.TokenRef = sec.TokenRef
				}
				if sec.InjectHeader != "" {
					merged.InjectHeader = sec.InjectHeader
				}
				if sec.InjectFormat != "" {
					merged.InjectFormat = sec.InjectFormat
				}
				if sec.OnKMSError != "" {
					merged.OnKMSError = sec.OnKMSError
				}
				if sec.TokenVersion != "" {
					merged.TokenVersion = sec.TokenVersion
				}
				if sec.StripTokenParams != nil {
					merged.StripTokenParams = sec.StripTokenParams
				}
				merged.Profile = "" // clear ref after resolution
				route.Security[i] = merged

				// Annotate source metadata for inherited fields.
				annotatePolicy(&route, "x-csar-security", sec.Profile)
			}
			methods[method] = route
		}
	}
	return nil
}

// enforceProfileRules applies deployment-profile constraints at config load time.
// These mirror the rules in internal/helper/profiles.go so that running
// cmd/csar directly enforces the same policy as csar-helper validate.
//
// Note: the KMS provider check here uses the config-declared value (c.KMS.Provider).
// The *resolved* runtime provider (CLI flag → config fallback) is validated
// separately via ValidateResolvedKMSProvider, which cmd/csar must call after
// resolving the effective provider name.
func (c *Config) enforceProfileRules() error {
	switch c.Profile {
	case "prod-single", "prod-distributed":
		// Reject insecure coordinator transport
		if c.Coordinator.AllowInsecure {
			return fmt.Errorf("profile %q rejects coordinator.allow_insecure: true", c.Profile)
		}
		// Reject dev environment
		if c.SecurityPolicy != nil && c.SecurityPolicy.Environment == "dev" {
			return fmt.Errorf("profile %q rejects security_policy.environment: \"dev\"", c.Profile)
		}
		// Require TLS when secure routes exist
		if c.HasSecureRoutes() && c.TLS == nil {
			return fmt.Errorf("profile %q requires TLS when secure routes are configured", c.Profile)
		}
		// Reject local KMS in prod when secure routes exist (config-declared value)
		if c.HasSecureRoutes() && c.KMS != nil && c.KMS.Provider == "local" {
			return fmt.Errorf("profile %q rejects kms.provider: \"local\" when secure routes exist; use a cloud KMS", c.Profile)
		}
	}

	if c.Profile == "prod-distributed" {
		// Require coordinator enabled with address
		if !c.Coordinator.Enabled || c.Coordinator.Address == "" {
			return fmt.Errorf("profile %q requires coordinator.enabled: true with a non-empty address", c.Profile)
		}
		// Require coordinator CA file for TLS
		if c.Coordinator.Enabled && c.Coordinator.CAFile == "" {
			return fmt.Errorf("profile %q requires coordinator.ca_file for TLS", c.Profile)
		}
	}

	return nil
}

// ValidateResolvedKMSProvider checks whether the runtime-resolved KMS provider
// (after CLI flag + config fallback resolution) is permitted by the declared profile.
//
// This must be called by cmd/csar after resolving the effective provider name,
// because the CLI flag --kms-provider can override the config-declared value.
// Without this check, a prod profile could pass config validation while still
// running with --kms-provider=local if kms.provider is unset in YAML.
func (c *Config) ValidateResolvedKMSProvider(resolvedProvider string) error {
	if c.Profile == "" {
		return nil // no profile — nothing to enforce
	}

	switch c.Profile {
	case "prod-single", "prod-distributed":
		if c.HasSecureRoutes() && resolvedProvider == "local" {
			return fmt.Errorf("profile %q rejects KMS provider \"local\" when secure routes exist; "+
				"use --kms-provider=yandexapi or set kms.provider in config", c.Profile)
		}
	}

	return nil
}
