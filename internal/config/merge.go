package config

import "fmt"

// mergeConfigs merges overlay into base. Map fields are merged by key with
// duplicate-key detection. Singleton fields (scalars that belong only in the
// root config) in the overlay are ignored with a warning. Slice fields in
// the overlay replace base slices entirely.
//
// overlayFile is used for error messages and warnings.
func mergeConfigs(base, overlay *Config, overlayFile string) error {
	// --- Singleton fields: warn and skip if overlay sets them ---
	if overlay.ListenAddr != "" {
		base.Warnings = append(base.Warnings,
			fmt.Sprintf("include %s: listen_addr is a root-only field — ignored", overlayFile))
	}
	if overlay.TLS != nil {
		base.Warnings = append(base.Warnings,
			fmt.Sprintf("include %s: tls is a root-only field — ignored", overlayFile))
	}
	if overlay.AccessControl != nil {
		base.Warnings = append(base.Warnings,
			fmt.Sprintf("include %s: access_control is a root-only field — ignored", overlayFile))
	}
	if overlay.SecurityPolicy != nil {
		base.Warnings = append(base.Warnings,
			fmt.Sprintf("include %s: security_policy is a root-only field — ignored", overlayFile))
	}
	if overlay.SSRF != nil {
		base.Warnings = append(base.Warnings,
			fmt.Sprintf("include %s: ssrf_protection is a root-only field — ignored", overlayFile))
	}
	if overlay.KMS != nil {
		base.Warnings = append(base.Warnings,
			fmt.Sprintf("include %s: kms is a root-only field — ignored", overlayFile))
	}
	if overlay.Coordinator.Enabled || overlay.Coordinator.Address != "" {
		base.Warnings = append(base.Warnings,
			fmt.Sprintf("include %s: coordinator is a root-only field — ignored", overlayFile))
	}
	if overlay.Redis != nil {
		base.Warnings = append(base.Warnings,
			fmt.Sprintf("include %s: redis is a root-only field — ignored", overlayFile))
	}
	if overlay.GlobalThrottle != nil {
		base.Warnings = append(base.Warnings,
			fmt.Sprintf("include %s: global_throttle is a root-only field — ignored", overlayFile))
	}
	if overlay.Profile != "" {
		base.Warnings = append(base.Warnings,
			fmt.Sprintf("include %s: profile is a root-only field — ignored", overlayFile))
	}

	// --- Map fields: merge by key, error on duplicates ---

	// Paths
	if err := mergePaths(base, overlay, overlayFile); err != nil {
		return err
	}

	// SecurityProfiles
	if err := mergeMap(base.SecurityProfiles, overlay.SecurityProfiles, &base.SecurityProfiles, overlayFile, "security_profiles"); err != nil {
		return err
	}

	// CircuitBreakers
	if err := mergeMap(base.CircuitBreakers, overlay.CircuitBreakers, &base.CircuitBreakers, overlayFile, "circuit_breakers"); err != nil {
		return err
	}

	// ThrottlingPolicies
	if err := mergeMap(base.ThrottlingPolicies, overlay.ThrottlingPolicies, &base.ThrottlingPolicies, overlayFile, "throttling_policies"); err != nil {
		return err
	}

	// CORSPolicies
	if err := mergeMap(base.CORSPolicies, overlay.CORSPolicies, &base.CORSPolicies, overlayFile, "cors_policies"); err != nil {
		return err
	}

	// RetryPolicies
	if err := mergeMap(base.RetryPolicies, overlay.RetryPolicies, &base.RetryPolicies, overlayFile, "retry_policies"); err != nil {
		return err
	}

	// RedactPolicies
	if err := mergeMap(base.RedactPolicies, overlay.RedactPolicies, &base.RedactPolicies, overlayFile, "redact_policies"); err != nil {
		return err
	}

	// AuthValidatePolicies
	if err := mergeMap(base.AuthValidatePolicies, overlay.AuthValidatePolicies, &base.AuthValidatePolicies, overlayFile, "auth_validate_policies"); err != nil {
		return err
	}

	// AuthzPolicies
	if err := mergeMap(base.AuthzPolicies, overlay.AuthzPolicies, &base.AuthzPolicies, overlayFile, "authz_policies"); err != nil {
		return err
	}

	// BackendTLSPolicies
	if err := mergeMap(base.BackendTLSPolicies, overlay.BackendTLSPolicies, &base.BackendTLSPolicies, overlayFile, "backend_tls_policies"); err != nil {
		return err
	}

	return nil
}

// mergePaths merges overlay paths into base paths. Each unique combination
// of path+method must appear in exactly one file — duplicates are errors.
func mergePaths(base, overlay *Config, overlayFile string) error {
	if len(overlay.Paths) == 0 {
		return nil
	}
	if base.Paths == nil {
		base.Paths = make(map[string]PathConfig)
	}
	for path, overlayMethods := range overlay.Paths {
		baseMethods, exists := base.Paths[path]
		if !exists {
			base.Paths[path] = overlayMethods
			continue
		}
		// Path exists — check individual methods for conflicts.
		for method := range overlayMethods {
			if _, dup := baseMethods[method]; dup {
				return fmt.Errorf("duplicate route %s %s: declared in both root config and %s",
					method, path, overlayFile)
			}
			baseMethods[method] = overlayMethods[method]
		}
		base.Paths[path] = baseMethods
	}
	return nil
}

// mergeMap is a generic helper for merging string-keyed maps with duplicate detection.
func mergeMap[V any](base, overlay map[string]V, dest *map[string]V, overlayFile, section string) error {
	if len(overlay) == 0 {
		return nil
	}
	if *dest == nil {
		*dest = make(map[string]V)
	}
	for k, v := range overlay {
		if _, dup := (*dest)[k]; dup {
			return fmt.Errorf("duplicate %s key %q: declared in both root config and %s",
				section, k, overlayFile)
		}
		(*dest)[k] = v
	}
	return nil
}
