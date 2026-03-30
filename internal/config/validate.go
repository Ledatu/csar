package config

import (
	"fmt"
	"net"
	"strings"
)

// Validate checks the configuration for required fields and consistency.
func (c *Config) Validate() error {
	if c.ListenAddr == "" {
		return fmt.Errorf("listen_addr is required")
	}
	if len(c.Paths) == 0 {
		return fmt.Errorf("at least one path must be defined")
	}

	// --- Profile enforcement ---
	// If a deployment profile is declared, enforce its rules at startup so that
	// running `cmd/csar` directly cannot bypass profile guardrails (audit §3).
	if c.Profile != "" {
		validProfiles := []string{"dev-local", "prod-single", "prod-distributed"}
		profileValid := false
		for _, p := range validProfiles {
			if c.Profile == p {
				profileValid = true
				break
			}
		}
		if !profileValid {
			return fmt.Errorf("unknown profile %q; valid profiles: %v", c.Profile, validProfiles)
		}

		if err := c.enforceProfileRules(); err != nil {
			return err
		}
	}

	// Preserve warnings from include/merge phase.
	warnings := append([]string{}, c.Warnings...)

	isProd := c.SecurityPolicy != nil && c.SecurityPolicy.Environment == "prod"

	// --- Security policy enforcement ---
	if isProd {
		// In prod, forbid insecure coordinator transport if policy says so.
		if c.SecurityPolicy.ForbidInsecureInProd {
			if c.Coordinator.Enabled && c.Coordinator.AllowInsecure && c.Coordinator.CAFile == "" {
				return fmt.Errorf("security_policy: environment is \"prod\" with forbid_insecure_in_prod — " +
					"coordinator.allow_insecure is not permitted; set coordinator.ca_file for TLS")
			}
			// Forbid running without inbound TLS in prod — this is a hard error,
			// not a warning, to prevent accidental plaintext exposure.
			if c.TLS == nil {
				return fmt.Errorf("security_policy: environment is \"prod\" with forbid_insecure_in_prod — " +
					"inbound TLS is not configured; set tls.cert_file and tls.key_file for production")
			}
		}
		if c.SecurityPolicy.RequireMTLSForCoordinator && c.Coordinator.Enabled {
			if c.Coordinator.CertFile == "" || c.Coordinator.KeyFile == "" {
				return fmt.Errorf("security_policy: require_mtls_for_coordinator is true but " +
					"coordinator.cert_file/key_file are not set")
			}
		}
	}

	// Validate security_policy.environment values
	if c.SecurityPolicy != nil {
		env := c.SecurityPolicy.Environment
		if env != "" && env != "dev" && env != "stage" && env != "prod" {
			return fmt.Errorf("security_policy.environment must be \"dev\", \"stage\", or \"prod\", got %q", env)
		}
	}

	// Validate KMS config
	if c.KMS != nil {
		if c.KMS.Provider != "" && c.KMS.Provider != "local" && c.KMS.Provider != "yandexapi" {
			return fmt.Errorf("kms.provider must be \"local\" or \"yandexapi\", got %q", c.KMS.Provider)
		}
		if c.KMS.Provider == "yandexapi" && c.KMS.Yandex == nil {
			warnings = append(warnings, "kms.provider is \"yandexapi\" but kms.yandex section is not configured")
		}
		if c.KMS.Retry != nil {
			warnings = append(warnings,
				"kms.retry is configured but not yet enforced at runtime — "+
					"this option is reserved for a future release")
		}
	}

	// Validate inbound TLS config
	if c.TLS != nil {
		if c.TLS.CertFile == "" || c.TLS.KeyFile == "" {
			return fmt.Errorf("tls: both cert_file and key_file are required")
		}
		if v := c.TLS.MinVersion; v != "" && v != "1.2" && v != "1.3" {
			return fmt.Errorf("tls: min_version must be \"1.2\" or \"1.3\", got %q", v)
		}
	}

	// Validate coordinator transport config
	coord := c.Coordinator
	if coord.Enabled {
		if coord.Address == "" {
			return fmt.Errorf("coordinator.address is required when coordinator.enabled is true")
		}

		// mTLS client cert/key must come as a pair
		if (coord.CertFile != "") != (coord.KeyFile != "") {
			return fmt.Errorf("coordinator: cert_file and key_file must both be set for mTLS (got cert_file=%q, key_file=%q)",
				coord.CertFile, coord.KeyFile)
		}

		// Client cert requires CA (mTLS needs the CA to verify the server)
		if coord.CertFile != "" && coord.CAFile == "" {
			return fmt.Errorf("coordinator: cert_file/key_file (mTLS) requires ca_file to be set")
		}

		// Contradictory: ca_file + allow_insecure
		if coord.CAFile != "" && coord.AllowInsecure {
			warnings = append(warnings,
				"SECURITY WARNING: coordinator.allow_insecure is true but ca_file is also set; "+
					"ca_file takes precedence (TLS will be used)")
		}

		// If no transport security is configured at all, that's an error
		if coord.CAFile == "" && !coord.AllowInsecure {
			return fmt.Errorf("coordinator: transport security is required — " +
				"set coordinator.ca_file for TLS, or coordinator.allow_insecure: true for development")
		}

		// Validate invalidation buffer size if explicitly set.
		if coord.InvalidationBufferSize != 0 && coord.InvalidationBufferSize < 100 {
			return fmt.Errorf("coordinator.invalidation_buffer_size must be >= 100, got %d", coord.InvalidationBufferSize)
		}
	} else if coord.CAFile != "" || coord.CertFile != "" || coord.KeyFile != "" {
		warnings = append(warnings,
			"coordinator is disabled but TLS fields (ca_file/cert_file/key_file) are set — these have no effect")
	}

	// Validate global access control
	if c.AccessControl != nil {
		for _, cidr := range c.AccessControl.AllowCIDRs {
			if err := validateCIDROrIP(cidr); err != nil {
				return fmt.Errorf("access_control.allow_cidrs: %w", err)
			}
		}
	}

	// Validate global throttle config
	if c.GlobalThrottle != nil {
		if c.GlobalThrottle.RPS <= 0 {
			return fmt.Errorf("global_throttle.rate must be > 0")
		}
		if c.GlobalThrottle.Burst <= 0 {
			return fmt.Errorf("global_throttle.burst must be > 0")
		}
	}

	// Validate backend TLS policy definitions.
	// Note: the "use" field is structurally rejected — BackendTLSPolicy has no
	// Use field, and the JSON schema sets additionalProperties: false.
	for name, policy := range c.BackendTLSPolicies {
		if (policy.CertFile != "") != (policy.KeyFile != "") {
			return fmt.Errorf("backend_tls_policies.%s: cert_file and key_file must both be set for mTLS", name)
		}
	}

	for path, methods := range c.Paths {
		for method := range methods {
			route := methods[method]
			if route.Backend.TargetURL == "" {
				return fmt.Errorf("path %s method %s: x-csar-backend.target_url is required", path, method)
			}
			if route.Resilience != nil && route.Resilience.CircuitBreaker != "" {
				if _, ok := c.CircuitBreakers[route.Resilience.CircuitBreaker]; !ok {
					return fmt.Errorf("path %s method %s: circuit_breaker profile %q not defined in circuit_breakers",
						path, method, route.Resilience.CircuitBreaker)
				}
			}

			// Validate path_mode
			if pm := route.Backend.PathMode; pm != "" && pm != "replace" && pm != "append" {
				return fmt.Errorf("path %s method %s: x-csar-backend.path_mode must be \"replace\" or \"append\", got %q", path, method, pm)
			}

			// Validate backend TLS config
			if bt := route.Backend.TLS; bt != nil {
				if bt.Use != "" {
					return fmt.Errorf("path %s method %s: x-csar-backend.tls has unresolved policy reference %q — "+
						"call ResolveBackendTLSPolicies() before Validate()", path, method, bt.Use)
				}
				if bt.CertFile != "" && bt.KeyFile == "" {
					return fmt.Errorf("path %s method %s: backend tls cert_file requires key_file", path, method)
				}
				if bt.KeyFile != "" && bt.CertFile == "" {
					return fmt.Errorf("path %s method %s: backend tls key_file requires cert_file", path, method)
				}
			}

			// Validate security config: if x-csar-security is present,
			// require the essential fields that the auth injection pipeline needs.
			for i, sec := range route.Security {
				idx := fmt.Sprintf("[%d]", i)
				if len(route.Security) == 1 {
					idx = "" // cleaner error messages for the common single-entry case
				}
				// Belt-and-suspenders: catch unresolved profile references.
				// ResolveSecurityProfiles() should have been called before Validate(),
				// but if a caller built a Config programmatically and forgot to
				// resolve, produce a clear diagnostic instead of a confusing field error.
				if sec.Profile != "" {
					return fmt.Errorf("path %s method %s: x-csar-security%s has unresolved profile reference %q — "+
						"call ResolveSecurityProfiles() before Validate()", path, method, idx, sec.Profile)
				}
				if sec.TokenRef == "" {
					return fmt.Errorf("path %s method %s: x-csar-security%s.token_ref is required when security config is present", path, method, idx)
				}
				if sec.InjectHeader == "" {
					return fmt.Errorf("path %s method %s: x-csar-security%s.inject_header is required when security config is present", path, method, idx)
				}
				if sec.KMSKeyID == "" {
					return fmt.Errorf("path %s method %s: x-csar-security%s.kms_key_id is required when security config is present", path, method, idx)
				}
				if oe := sec.OnKMSError; oe != "" && oe != "fail_closed" && oe != "serve_stale" {
					return fmt.Errorf("path %s method %s: x-csar-security%s.on_kms_error must be \"fail_closed\" or \"serve_stale\", got %q", path, method, idx, oe)
				}
			}

			// Validate retry config
			if route.Retry != nil {
				if route.Retry.MaxAttempts < 0 {
					return fmt.Errorf("path %s method %s: x-csar-retry.max_attempts must be >= 0", path, method)
				}
				for _, code := range route.Retry.RetryableStatusCodes {
					if code < 100 || code > 599 {
						return fmt.Errorf("path %s method %s: x-csar-retry.retryable_status_codes contains invalid HTTP status %d", path, method, code)
					}
				}
			}

			// Validate auth-validate config (JWT or session mode).
			if route.AuthValidate != nil {
				switch route.AuthValidate.Mode {
				case "session":
					if route.AuthValidate.SessionEndpoint == "" {
						return fmt.Errorf("path %s method %s: x-csar-authn-validate.session_endpoint is required for session mode", path, method)
					}
					if !strings.HasPrefix(route.AuthValidate.SessionEndpoint, "https://") && !strings.HasPrefix(route.AuthValidate.SessionEndpoint, "http://") {
						return fmt.Errorf("path %s method %s: x-csar-authn-validate.session_endpoint must start with http:// or https://", path, method)
					}
					if route.AuthValidate.CookieName == "" {
						return fmt.Errorf("path %s method %s: x-csar-authn-validate.cookie_name is required for session mode", path, method)
					}
				case "", "jwt":
					if route.AuthValidate.JWKSURL == "" {
						return fmt.Errorf("path %s method %s: x-csar-authn-validate.jwks_url is required", path, method)
					}
					if !strings.HasPrefix(route.AuthValidate.JWKSURL, "https://") && !strings.HasPrefix(route.AuthValidate.JWKSURL, "http://") {
						return fmt.Errorf("path %s method %s: x-csar-authn-validate.jwks_url must start with http:// or https://", path, method)
					}
					if route.AuthValidate.JWKSTLS != "" {
						if _, ok := c.BackendTLSPolicies[route.AuthValidate.JWKSTLS]; !ok {
							return fmt.Errorf("path %s method %s: x-csar-authn-validate.jwks_tls policy %q not found in backend_tls_policies",
								path, method, route.AuthValidate.JWKSTLS)
						}
					}
				default:
					return fmt.Errorf("path %s method %s: x-csar-authn-validate.mode %q is not recognized (expected \"jwt\" or \"session\")", path, method, route.AuthValidate.Mode)
				}
			}

			// Validate redact (DLP) config
			if route.Redact != nil && route.Redact.IsEnabled() {
				if len(route.Redact.Fields) == 0 {
					return fmt.Errorf("path %s method %s: x-csar-redact.fields must contain at least one field path", path, method)
				}
			}

			// Validate tenant config
			if route.Tenant != nil {
				if route.Tenant.Header == "" {
					return fmt.Errorf("path %s method %s: x-csar-tenant.header is required", path, method)
				}
				if len(route.Tenant.Backends) == 0 {
					return fmt.Errorf("path %s method %s: x-csar-tenant.backends must contain at least one entry", path, method)
				}
			}

			// Validate per-route access control
			if route.Access != nil {
				for _, cidr := range route.Access.AllowCIDRs {
					if err := validateCIDROrIP(cidr); err != nil {
						return fmt.Errorf("path %s method %s: x-csar-access.allow_cidrs: %w", path, method, err)
					}
				}
			}

			// Validate CORS config
			if route.CORS != nil {
				if len(route.CORS.AllowedOrigins) == 0 {
					return fmt.Errorf("path %s method %s: x-csar-cors.allowed_origins must contain at least one entry", path, method)
				}
			}

			// Validate cache config
			if route.Cache != nil && route.Cache.IsEnabled() {
				if route.Cache.MaxEntries < 0 {
					return fmt.Errorf("path %s method %s: x-csar-cache.max_entries must be >= 0", path, method)
				}
			}

			// Validate load balancer config
			if lb := route.Backend.LoadBalancer; lb != "" && lb != "round_robin" && lb != "random" {
				return fmt.Errorf("path %s method %s: x-csar-backend.load_balancer must be \"round_robin\" or \"random\", got %q", path, method, lb)
			}

			// Validate health check config
			if hc := route.Backend.HealthCheck; hc != nil && hc.Enabled {
				if hc.Mode != "" && hc.Mode != "http" && hc.Mode != "tcp" {
					return fmt.Errorf("path %s method %s: health_check.mode must be \"http\" or \"tcp\", got %q", path, method, hc.Mode)
				}
				if hc.Mode == "http" && hc.Path == "" {
					return fmt.Errorf("path %s method %s: health_check.path is required when mode is \"http\"", path, method)
				}
				if len(route.Backend.AllTargets()) < 2 && route.Backend.LoadBalancer == "" {
					warnings = append(warnings,
						fmt.Sprintf("path %s method %s: health_check is enabled but there is only one target — consider adding multiple targets with load balancing",
							path, method))
				}
			}

			// Validate traffic backend
			if route.Traffic != nil && route.Traffic.Backend != "" {
				switch route.Traffic.Backend {
				case "local", "redis", "coordinator":
					// valid
				default:
					return fmt.Errorf("path %s method %s: x-csar-traffic.backend must be \"local\", \"redis\", or \"coordinator\", got %q",
						path, method, route.Traffic.Backend)
				}
				if route.Traffic.Backend == "redis" && c.Redis == nil {
					return fmt.Errorf("path %s method %s: x-csar-traffic.backend is \"redis\" but no top-level redis config is provided",
						path, method)
				}
				if route.Traffic.Backend == "redis" && c.Redis != nil && c.Redis.Address == "" {
					return fmt.Errorf("path %s method %s: x-csar-traffic.backend is \"redis\" but redis.address is empty",
						path, method)
				}
			}

			// Validate unresolved throttle policy references.
			if route.Traffic != nil && route.Traffic.Use != "" {
				return fmt.Errorf("path %s method %s: x-csar-traffic has unresolved policy reference %q — "+
					"call ResolveThrottlePolicies() before Validate()", path, method, route.Traffic.Use)
			}

			// Validate unresolved CORS policy references.
			if route.CORS != nil && route.CORS.Use != "" {
				return fmt.Errorf("path %s method %s: x-csar-cors has unresolved policy reference %q — "+
					"call ResolveCORSPolicies() before Validate()", path, method, route.CORS.Use)
			}

			// Validate unresolved retry policy references.
			if route.Retry != nil && route.Retry.Use != "" {
				return fmt.Errorf("path %s method %s: x-csar-retry has unresolved policy reference %q — "+
					"call ResolveRetryPolicies() before Validate()", path, method, route.Retry.Use)
			}

			// Validate unresolved redact policy references.
			if route.Redact != nil && route.Redact.Use != "" {
				return fmt.Errorf("path %s method %s: x-csar-redact has unresolved policy reference %q — "+
					"call ResolveRedactPolicies() before Validate()", path, method, route.Redact.Use)
			}

			// Validate unresolved auth-validate policy references.
			if route.AuthValidate != nil && route.AuthValidate.Use != "" {
				return fmt.Errorf("path %s method %s: x-csar-authn-validate has unresolved policy reference %q — "+
					"call ResolveAuthValidatePolicies() before Validate()", path, method, route.AuthValidate.Use)
			}

			// Validate dynamic key requires redis backend.
			if route.Traffic != nil && route.Traffic.Key != "" {
				if route.Traffic.Backend != "redis" {
					return fmt.Errorf("path %s method %s: x-csar-traffic.key requires backend \"redis\" (dynamic keys are distributed by nature)",
						path, method)
				}
			}

			// Validate exclude_ips entries.
			if route.Traffic != nil {
				for _, cidr := range route.Traffic.ExcludeIPs {
					if err := validateCIDROrIP(cidr); err != nil {
						return fmt.Errorf("path %s method %s: x-csar-traffic.exclude_ips: %w", path, method, err)
					}
				}
			}

			// Validate VIP overrides reference existing policies.
			if route.Traffic != nil {
				for _, vip := range route.Traffic.VIPOverrides {
					if vip.Header == "" {
						return fmt.Errorf("path %s method %s: x-csar-traffic.vip_overrides[].header is required", path, method)
					}
					for val, policyName := range vip.Values {
						if _, ok := c.ThrottlingPolicies[policyName]; !ok {
							return fmt.Errorf("path %s method %s: vip_override header %q value %q references unknown policy %q",
								path, method, vip.Header, val, policyName)
						}
					}
				}
			}

			// Validate max_response_size
			if route.MaxResponseSize < 0 {
				return fmt.Errorf("path %s method %s: max_response_size must be >= 0", path, method)
			}

			// Warn if credentials are sent over non-TLS upstream.
			// insecure_skip_verify is irrelevant for http:// — always warn.
			for _, sec := range route.Security {
				if sec.TokenRef != "" && !strings.HasPrefix(route.Backend.TargetURL, "https://") {
					warnings = append(warnings,
						fmt.Sprintf("SECURITY WARNING: path %s method %s injects credentials (%s) over non-TLS upstream %q",
							path, method, sec.InjectHeader, route.Backend.TargetURL))
				}
			}

			// Warn separately if insecure_skip_verify is set on an https:// upstream
			if route.Backend.TLS != nil && route.Backend.TLS.InsecureSkipVerify {
				if strings.HasPrefix(route.Backend.TargetURL, "https://") {
					if isProd && c.SecurityPolicy.ForbidInsecureInProd {
						return fmt.Errorf("path %s method %s: backend tls insecure_skip_verify is not permitted "+
							"in prod with forbid_insecure_in_prod enabled — configure a ca_file for upstream %q",
							path, method, route.Backend.TargetURL)
					}
					// In staging, strongly recommend ca_file instead of insecure_skip_verify
					// to ensure parity with production TLS verification (audit §1.2).
					isStage := c.SecurityPolicy != nil && c.SecurityPolicy.Environment == "stage"
					if isStage {
						warnings = append(warnings,
							fmt.Sprintf("SECURITY WARNING: path %s method %s uses insecure_skip_verify in staging for upstream %q — "+
								"use tls.ca_file instead to ensure parity with production TLS verification",
								path, method, route.Backend.TargetURL))
					} else {
						warnings = append(warnings,
							fmt.Sprintf("SECURITY WARNING: path %s method %s uses insecure_skip_verify on upstream %q — certificate verification is disabled",
								path, method, route.Backend.TargetURL))
					}
				}
			}
		}
	}

	c.Warnings = warnings
	return nil
}

// validateCIDROrIP checks that a string is a valid CIDR range or IP address.
func validateCIDROrIP(s string) error {
	// Try parsing as CIDR first (e.g. "10.0.0.0/24", "::1/128")
	if strings.Contains(s, "/") {
		_, _, err := net.ParseCIDR(s)
		if err != nil {
			return fmt.Errorf("invalid CIDR %q: %w", s, err)
		}
		return nil
	}
	// Try parsing as plain IP (e.g. "10.0.0.1", "::1")
	if net.ParseIP(s) == nil {
		return fmt.Errorf("invalid IP address %q", s)
	}
	return nil
}
