package config

import (
	"strings"

	"github.com/ledatu/csar-core/configutil"
	"github.com/ledatu/csar/internal/logging"
	"gopkg.in/yaml.v3"
)

// SecurityConfigs is a slice of SecurityConfig that supports both a single
// YAML object and a YAML list for backward compatibility.
//
// Single object (old syntax):
//
//	x-csar-security:
//	  kms_key_id: "key-1"
//	  token_ref: "tok"
//	  inject_header: "Authorization"
//
// Array (new syntax, supports multiple credentials):
//
//	x-csar-security:
//	  - kms_key_id: "key-1"
//	    token_ref: "tok"
//	    inject_header: "Authorization"
//	  - kms_key_id: "key-2"
//	    token_ref: "client_secret"
//	    inject_header: "X-Client-Secret"
type SecurityConfigs []SecurityConfig

// UnmarshalYAML handles a bare string (profile reference), a single SecurityConfig
// object, or an array of mixed strings and objects.
//
// Supported syntaxes:
//
//	x-csar-security: "my_profile"                  # bare string → profile ref
//	x-csar-security: { kms_key_id: ..., ... }      # inline object (old syntax)
//	x-csar-security:
//	  - "my_profile"                                # profile ref in array
//	  - { kms_key_id: ..., ... }                    # inline object in array
func (sc *SecurityConfigs) UnmarshalYAML(value *yaml.Node) error {
	// Scalar string → single profile reference.
	if value.Kind == yaml.ScalarNode {
		*sc = SecurityConfigs{{Profile: value.Value}}
		return nil
	}

	// Sequence → mixed array of strings (profile refs) and mapping objects.
	if value.Kind == yaml.SequenceNode {
		var items []SecurityConfig
		for _, item := range value.Content {
			if item.Kind == yaml.ScalarNode {
				items = append(items, SecurityConfig{Profile: item.Value})
			} else {
				var cfg SecurityConfig
				if err := item.Decode(&cfg); err != nil {
					return err
				}
				items = append(items, cfg)
			}
		}
		*sc = items
		return nil
	}

	// Mapping → single inline object, wrap in a slice.
	var single SecurityConfig
	if err := value.Decode(&single); err != nil {
		return err
	}
	*sc = SecurityConfigs{single}
	return nil
}

// Config holds the top-level CSAR configuration.
type Config struct {
	// Include is a list of file paths or glob patterns to merge into this config.
	// Paths are resolved relative to the directory of the file containing the include.
	// Processed before YAML unmarshaling of the main config body.
	Include []string `yaml:"include,omitempty" json:"include,omitempty"`

	// Profile declares the deployment profile: "dev-local", "prod-single", "prod-distributed", or "".
	// Used by csar-helper validate to enforce profile-specific constraints.
	Profile string `yaml:"profile,omitempty" json:"profile,omitempty"`

	// Listen address for the API gateway.
	ListenAddr string `yaml:"listen_addr" json:"listen_addr"`

	// TLS configuration for inbound connections (clients → CSAR).
	TLS *TLSConfig `yaml:"tls,omitempty" json:"tls,omitempty"`

	// AccessControl defines global IP allowlisting. If set, only listed IPs/CIDRs
	// can reach any route (unless overridden per-route).
	AccessControl *AccessControlConfig `yaml:"access_control,omitempty" json:"access_control,omitempty"`

	// SecurityPolicy defines environment-level security constraints.
	// In "prod" mode, insecure options are rejected at startup (fail-fast).
	SecurityPolicy *SecurityPolicyConfig `yaml:"security_policy,omitempty" json:"security_policy,omitempty"`

	// SSRF configures Server-Side Request Forgery protection for outbound requests.
	// Default: blocks private, loopback, link-local and metadata IPs.
	SSRF *SSRFConfig `yaml:"ssrf_protection,omitempty" json:"ssrf_protection,omitempty"`

	// KMS configures the global Key Management Service provider and caching.
	KMS *KMSConfig `yaml:"kms,omitempty" json:"kms,omitempty"`

	// Coordinator settings for the control plane connection.
	Coordinator CoordinatorConfig `yaml:"coordinator" json:"coordinator"`

	// Redis configures an optional Redis backend for distributed rate limiting.
	// When set, routes with traffic.backend = "redis" use this connection
	// for globally coordinated rate limiting across all CSAR pods.
	Redis *RedisConfig `yaml:"redis,omitempty" json:"redis,omitempty"`

	// SecurityProfiles defines named, reusable security configurations.
	// Routes reference them via x-csar-security: "profile_name".
	SecurityProfiles map[string]SecurityConfig `yaml:"security_profiles,omitempty" json:"security_profiles,omitempty"`

	// CircuitBreakers defines named circuit breaker profiles.
	CircuitBreakers map[string]CircuitBreakerProfile `yaml:"circuit_breakers,omitempty" json:"circuit_breakers,omitempty"`

	// ThrottlingPolicies defines named, reusable throttling configurations.
	// Routes reference them via x-csar-traffic: "policy_name" or x-csar-traffic.use: "policy_name".
	// Inline fields on the route override policy defaults (shallow merge).
	ThrottlingPolicies map[string]ThrottlingPolicy `yaml:"throttling_policies,omitempty" json:"throttling_policies,omitempty"`

	// CORSPolicies defines named, reusable CORS configurations.
	// Routes reference them via x-csar-cors: "policy_name".
	CORSPolicies map[string]CORSConfig `yaml:"cors_policies,omitempty" json:"cors_policies,omitempty"`

	// RetryPolicies defines named, reusable retry configurations.
	// Routes reference them via x-csar-retry: "policy_name".
	RetryPolicies map[string]RetryConfig `yaml:"retry_policies,omitempty" json:"retry_policies,omitempty"`

	// RedactPolicies defines named, reusable redaction configurations.
	// Routes reference them via x-csar-redact: "policy_name".
	RedactPolicies map[string]RedactConfig `yaml:"redact_policies,omitempty" json:"redact_policies,omitempty"`

	// AuthValidatePolicies defines named, reusable auth validation configurations.
	// Routes reference them via x-csar-authn-validate: "policy_name".
	AuthValidatePolicies map[string]AuthValidateConfig `yaml:"auth_validate_policies,omitempty" json:"auth_validate_policies,omitempty"`

	// AuthzPolicies defines named, reusable authorization configurations.
	// Routes reference them via x-csar-authz: "policy_name" or x-csar-authz.use: "policy_name".
	AuthzPolicies map[string]AuthzRouteConfig `yaml:"authz_policies,omitempty" json:"authz_policies,omitempty"`

	// GlobalThrottle defines a global rate limit applied to ALL routes as a safety net.
	// Checked before per-route throttle. Uses a fast in-memory atomic counter.
	GlobalThrottle *GlobalThrottleConfig `yaml:"global_throttle,omitempty" json:"global_throttle,omitempty"`

	// Readiness configures the dependency-aware readiness probe endpoint.
	Readiness *ReadinessConfig `yaml:"readiness,omitempty" json:"readiness,omitempty"`

	// DebugHeaders configures traceability headers (X-Request-ID, X-CSAR-Route-ID).
	DebugHeaders *DebugHeadersConfig `yaml:"debug_headers,omitempty" json:"debug_headers,omitempty"`

	// Authz configures the connection to the csar-authz gRPC service.
	// When set, routes with x-csar-authz can evaluate access policies.
	Authz *AuthzClientConfig `yaml:"authz,omitempty" json:"authz,omitempty"`

	// Paths holds the OpenAPI-style route definitions with x-csar-* extensions.
	Paths map[string]PathConfig `yaml:"paths" json:"paths"`

	// Warnings holds non-fatal validation warnings (e.g. credentials over non-TLS).
	// Populated by Validate().
	Warnings []string `yaml:"-" json:"-"`
}

// TLSConfig configures inbound TLS (clients connecting to CSAR).
type TLSConfig struct {
	// CertFile is the path to the TLS certificate (PEM).
	CertFile string `yaml:"cert_file" json:"cert_file"`

	// KeyFile is the path to the TLS private key (PEM).
	KeyFile string `yaml:"key_file" json:"key_file"`

	// ClientCAFile enables mutual TLS — path to the CA that signed client certs.
	ClientCAFile string `yaml:"client_ca_file,omitempty" json:"client_ca_file,omitempty"`

	// MinVersion is the minimum TLS version ("1.2" or "1.3"). Default: "1.2".
	MinVersion string `yaml:"min_version,omitempty" json:"min_version,omitempty"`
}

// CoordinatorConfig holds settings for the control plane.
type CoordinatorConfig struct {
	// Enabled toggles the coordinator mode.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Address is the gRPC address of the coordinator.
	Address string `yaml:"address,omitempty" json:"address,omitempty"`

	// DiscoveryMethod: "static", "dns", "consul", "kubernetes"
	DiscoveryMethod string `yaml:"discovery_method,omitempty" json:"discovery_method,omitempty"`

	// TLS settings for the router → coordinator gRPC connection.
	// CAFile is the path to the CA certificate used to verify the coordinator server.
	CAFile string `yaml:"ca_file,omitempty" json:"ca_file,omitempty"`

	// CertFile is the client certificate (PEM) for mTLS to the coordinator.
	CertFile string `yaml:"cert_file,omitempty" json:"cert_file,omitempty"`

	// KeyFile is the client private key (PEM) for mTLS to the coordinator.
	KeyFile string `yaml:"key_file,omitempty" json:"key_file,omitempty"`

	// AllowInsecure, if true, permits plaintext gRPC to the coordinator.
	// For development only — requires explicit opt-in.
	AllowInsecure bool `yaml:"allow_insecure,omitempty" json:"allow_insecure,omitempty"`

	// InvalidationBufferSize is the number of token invalidation events
	// buffered for replay on router reconnect. Default: 1000, minimum: 100.
	InvalidationBufferSize int `yaml:"invalidation_buffer_size,omitempty" json:"invalidation_buffer_size,omitempty"`
}

// PathConfig holds per-path route definitions keyed by HTTP method.
type PathConfig map[string]RouteConfig // e.g. "get", "post", "put", "delete"

// AccessControlConfig configures IP-based access control.
// Supports individual IPs ("10.0.0.1") and CIDR ranges ("10.0.0.0/24").
type AccessControlConfig struct {
	// AllowCIDRs is the list of allowed client IP addresses or CIDR ranges.
	// If non-empty, only clients matching at least one entry are permitted.
	AllowCIDRs []string `yaml:"allow_cidrs" json:"allow_cidrs"`

	// TrustProxy controls whether X-Forwarded-For / X-Real-IP headers are
	// trusted for extracting the real client IP. Default: false (use RemoteAddr).
	TrustProxy bool `yaml:"trust_proxy,omitempty" json:"trust_proxy,omitempty"`
}

// SourceMeta records where a config field was declared.
// Used for diagnostics and the inspect command — not serialized to YAML/proto.
type SourceMeta struct {
	File   string // absolute path to the source file
	Line   int    // line number in the source file
	Policy string // policy name if inherited, empty if inline
}

// RouteConfig defines a single route entry with x-csar-* extensions.
type RouteConfig struct {
	// Backend configuration.
	Backend BackendConfig `yaml:"x-csar-backend" json:"x-csar-backend"`

	// Security configuration (optional). Supports a single entry or a list.
	// Multiple entries inject multiple credentials into the same request.
	Security SecurityConfigs `yaml:"x-csar-security,omitempty" json:"x-csar-security,omitempty"`

	// Headers are static key-value pairs injected into every upstream request
	// for this route. Useful for fixed headers like User-Agent or x-client-secret.
	Headers map[string]string `yaml:"x-csar-headers,omitempty" json:"x-csar-headers,omitempty"`

	// AuthValidate configures inbound identity validation (JWT/JWKS).
	// Requests are rejected if the token is missing, expired, or signature-invalid.
	AuthValidate *AuthValidateConfig `yaml:"x-csar-authn-validate,omitempty" json:"x-csar-authn-validate,omitempty"`

	// Access control — per-route IP allowlist (optional).
	// If set, overrides the global access_control for this route.
	Access *AccessControlConfig `yaml:"x-csar-access,omitempty" json:"x-csar-access,omitempty"`

	// Traffic shaping configuration (optional).
	Traffic *TrafficConfig `yaml:"x-csar-traffic,omitempty" json:"x-csar-traffic,omitempty"`

	// Resilience configuration (optional).
	Resilience *ResilienceConfig `yaml:"x-csar-resilience,omitempty" json:"x-csar-resilience,omitempty"`

	// Retry configuration (optional).
	// Automatically retries idempotent upstream requests on transient failures.
	Retry *RetryConfig `yaml:"x-csar-retry,omitempty" json:"x-csar-retry,omitempty"`

	// Redact configures response payload redaction (DLP).
	// Specified JSON fields are masked before returning to the client.
	Redact *RedactConfig `yaml:"x-csar-redact,omitempty" json:"x-csar-redact,omitempty"`

	// Tenant configures multi-tenant routing.
	// Selects a backend based on a tenant identifier from headers.
	Tenant *TenantConfig `yaml:"x-csar-tenant,omitempty" json:"x-csar-tenant,omitempty"`

	// CORS configures Cross-Origin Resource Sharing for this route.
	// Automatically handles preflight OPTIONS requests.
	CORS *CORSConfig `yaml:"x-csar-cors,omitempty" json:"x-csar-cors,omitempty"`

	// Cache configures HTTP response caching for this route.
	Cache *CacheConfig `yaml:"x-csar-cache,omitempty" json:"x-csar-cache,omitempty"`

	// MaxResponseSize limits the maximum response body size in bytes for this route.
	// If the upstream response exceeds this, it is truncated and an error is returned.
	// Applies to DLP and Retry middleware buffering. Default: 0 (unlimited).
	MaxResponseSize int64 `yaml:"max_response_size,omitempty" json:"max_response_size,omitempty"`

	// Protocol configures per-route SDK protocol behavior.
	Protocol *ProtocolPolicy `yaml:"x-csar-protocol,omitempty" json:"x-csar-protocol,omitempty"`

	// Authz configures per-route authorization via csar-authz.
	// When present, CSAR strips spoofable headers, evaluates the access policy
	// against csar-authz, and injects trusted headers (e.g. X-User-Roles).
	Authz *AuthzRouteConfig `yaml:"x-csar-authz,omitempty" json:"x-csar-authz,omitempty"`

	// SourceInfo records which file and line each field was declared in.
	// Populated during multi-file loading for diagnostics. Not serialized.
	SourceInfo map[string]SourceMeta `yaml:"-" json:"-"`
}

// BackendConfig configures the upstream target.
type BackendConfig struct {
	// TargetURL is the upstream service URL (single target).
	TargetURL string `yaml:"target_url" json:"target_url"`

	// Targets is an array of upstream URLs for load balancing.
	// If both target_url and targets are set, target_url is prepended to targets.
	Targets []string `yaml:"targets,omitempty" json:"targets,omitempty"`

	// LoadBalancer selects the load balancing strategy.
	// Supported: "round_robin" (default), "random".
	LoadBalancer string `yaml:"load_balancer,omitempty" json:"load_balancer,omitempty"`

	// HealthCheck configures active health checking for load-balanced targets.
	// When enabled, unhealthy targets are temporarily removed from rotation.
	HealthCheck *HealthCheckConfig `yaml:"health_check,omitempty" json:"health_check,omitempty"`

	// PathRewrite replaces the matched path before proxying.
	// Supports regex capture group back-references ($1, $2, etc.)
	// when the route path contains regex variables.
	// Example: path "/api/v1/users/{id:[0-9]+}" with path_rewrite "/users/$1"
	// rewrites "/api/v1/users/42" → "/users/42".
	PathRewrite string `yaml:"path_rewrite,omitempty" json:"path_rewrite,omitempty"`

	// PathMode controls how the upstream URL path is constructed.
	// "replace" (default): target_url path replaces the incoming request path entirely.
	// "append": incoming request path is appended to target_url path.
	PathMode string `yaml:"path_mode,omitempty" json:"path_mode,omitempty"`

	// TLS configures the outbound TLS connection to this upstream.
	TLS *BackendTLSConfig `yaml:"tls,omitempty" json:"tls,omitempty"`
}

// IsAppendPathMode returns true if path_mode is explicitly "append".
func (bc *BackendConfig) IsAppendPathMode() bool {
	return strings.EqualFold(bc.PathMode, "append")
}

// HealthCheckConfig configures active health checking for load-balanced targets.
type HealthCheckConfig struct {
	// Enabled turns active health checking on (default: false).
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Mode is the health check protocol: "http" (default) or "tcp".
	Mode string `yaml:"mode,omitempty" json:"mode,omitempty"`

	// Path is the HTTP endpoint to probe (for mode "http"), e.g. "/health".
	Path string `yaml:"path,omitempty" json:"path,omitempty"`

	// Interval is the time between health check probes (default: "10s").
	Interval Duration `yaml:"interval,omitempty" json:"interval,omitempty"`

	// Timeout is the maximum time to wait for a health check response (default: "3s").
	Timeout Duration `yaml:"timeout,omitempty" json:"timeout,omitempty"`

	// UnhealthyThreshold is the number of consecutive failures before
	// marking a target as unhealthy (default: 3).
	UnhealthyThreshold int `yaml:"unhealthy_threshold,omitempty" json:"unhealthy_threshold,omitempty"`

	// HealthyThreshold is the number of consecutive successes before
	// marking a target as healthy again (default: 2).
	HealthyThreshold int `yaml:"healthy_threshold,omitempty" json:"healthy_threshold,omitempty"`
}

// AllTargets returns the complete list of upstream URLs including target_url.
func (bc *BackendConfig) AllTargets() []string {
	var targets []string
	if bc.TargetURL != "" {
		targets = append(targets, bc.TargetURL)
	}
	targets = append(targets, bc.Targets...)
	return targets
}

// BackendTLSConfig configures outbound TLS to an upstream.
type BackendTLSConfig struct {
	// InsecureSkipVerify disables certificate verification (dev only!).
	InsecureSkipVerify bool `yaml:"insecure_skip_verify,omitempty" json:"insecure_skip_verify,omitempty"`

	// CAFile is the path to a custom CA bundle for verifying the upstream cert.
	CAFile string `yaml:"ca_file,omitempty" json:"ca_file,omitempty"`

	// CertFile is the client certificate for mTLS to the upstream.
	CertFile string `yaml:"cert_file,omitempty" json:"cert_file,omitempty"`

	// KeyFile is the client key for mTLS to the upstream.
	KeyFile string `yaml:"key_file,omitempty" json:"key_file,omitempty"`
}

// SecurityConfig configures token injection via KMS.
type SecurityConfig struct {
	// Profile is an optional reference to a named security_profiles entry.
	// When set, all other fields are inherited from the profile; any
	// inline fields override the profile's values (merge, not replace).
	Profile string `yaml:"profile,omitempty" json:"profile,omitempty"`

	// KMSKeyID is the KMS key identifier for decryption.
	KMSKeyID string `yaml:"kms_key_id" json:"kms_key_id"`

	// TokenRef is the reference passed to AuthService to fetch the encrypted token.
	TokenRef string `yaml:"token_ref" json:"token_ref"`

	// TokenVersion is an opaque version string for cache-invalidation.
	// When the coordinator rotates a token, bumping the version causes
	// routers to re-fetch instead of serving a stale cached value.
	TokenVersion string `yaml:"token_version,omitempty" json:"token_version,omitempty"`

	// InjectHeader is the HTTP header to inject the decrypted token into (e.g. "Authorization").
	InjectHeader string `yaml:"inject_header" json:"inject_header"`

	// InjectFormat is the format template for the header value (e.g. "Bearer {token}").
	InjectFormat string `yaml:"inject_format" json:"inject_format"`

	// OnKMSError controls behavior when the KMS provider is unavailable.
	// "fail_closed" (default) — reject the request with 502.
	// "serve_stale" — use the last successfully decrypted value from cache.
	OnKMSError string `yaml:"on_kms_error,omitempty" json:"on_kms_error,omitempty"`

	// StripTokenParams controls whether query parameters used in token_ref
	// placeholders (e.g. {query.seller_id}) are removed from the request URL
	// before forwarding to the upstream. Default: true (strip).
	StripTokenParams *bool `yaml:"strip_token_params,omitempty" json:"strip_token_params,omitempty"`
}

// ShouldStripTokenParams returns whether query parameters referenced in
// token_ref should be stripped before proxying. Default: true.
func (s *SecurityConfig) ShouldStripTokenParams() bool {
	if s.StripTokenParams == nil {
		return true // default: strip
	}
	return *s.StripTokenParams
}

// SecurityPolicyConfig defines environment-level security constraints.
// In "prod" mode the bootstrap enforces strict security invariants at startup.
type SecurityPolicyConfig struct {
	// Environment is the deployment tier: "dev", "stage", or "prod".
	Environment string `yaml:"environment" json:"environment"`

	// ForbidInsecureInProd, when true (the default for prod), rejects configurations
	// that use allow_insecure or omit TLS in production.
	ForbidInsecureInProd bool `yaml:"forbid_insecure_in_prod" json:"forbid_insecure_in_prod"`

	// RequireMTLSForCoordinator, when true, requires mTLS between routers
	// and the coordinator in production.
	RequireMTLSForCoordinator bool `yaml:"require_mtls_for_coordinator" json:"require_mtls_for_coordinator"`

	// RedactSensitiveLogs controls whether token values, KMS key IDs, and other
	// security-relevant fields are redacted from structured logs.
	RedactSensitiveLogs bool `yaml:"redact_sensitive_logs" json:"redact_sensitive_logs"`
}

// KMSConfig configures the global KMS provider used for token encryption/decryption.
type KMSConfig struct {
	// Provider selects the KMS backend: "local", "yandexapi".
	Provider string `yaml:"provider" json:"provider"`

	// DefaultKeyID is the default KMS key used when a route doesn't specify one.
	DefaultKeyID string `yaml:"default_key_id,omitempty" json:"default_key_id,omitempty"`

	// OperationTimeout caps individual encrypt/decrypt calls.
	OperationTimeout Duration `yaml:"operation_timeout,omitempty" json:"operation_timeout,omitempty"`

	// Retry configures automatic retry for transient KMS errors.
	Retry *KMSRetryConfig `yaml:"retry,omitempty" json:"retry,omitempty"`

	// Cache configures the decrypt result cache.
	Cache *KMSCacheConfig `yaml:"cache,omitempty" json:"cache,omitempty"`

	// Yandex holds provider-specific settings for "yandexapi".
	Yandex *YandexKMSConfig `yaml:"yandex,omitempty" json:"yandex,omitempty"`

	// LocalKeys holds key=passphrase mappings for the "local" provider.
	LocalKeys map[string]string `yaml:"local_keys,omitempty" json:"local_keys,omitempty"`
}

// KMSRetryConfig configures retry/backoff for KMS operations.
type KMSRetryConfig struct {
	MaxAttempts int      `yaml:"max_attempts" json:"max_attempts"`
	BaseDelay   Duration `yaml:"base_delay" json:"base_delay"`
	MaxDelay    Duration `yaml:"max_delay" json:"max_delay"`
	Jitter      bool     `yaml:"jitter" json:"jitter"`
}

// KMSCacheConfig configures in-memory caching for KMS decrypt results.
type KMSCacheConfig struct {
	Enabled    bool     `yaml:"enabled" json:"enabled"`
	TTL        Duration `yaml:"ttl" json:"ttl"`
	MaxEntries int      `yaml:"max_entries,omitempty" json:"max_entries,omitempty"`
}

// YandexKMSConfig holds Yandex Cloud KMS specific settings.
type YandexKMSConfig struct {
	// Endpoint is the KMS API endpoint (default: https://kms.api.cloud.yandex.net/kms/v1/keys).
	Endpoint string `yaml:"endpoint,omitempty" json:"endpoint,omitempty"`

	// AuthMode selects the credential source: "iam_token", "oauth_token", "metadata".
	AuthMode string `yaml:"auth_mode,omitempty" json:"auth_mode,omitempty"`

	// IAMToken is a static IAM token (for dev/testing only).
	// Implements slog.LogValuer — always logs as "[REDACTED]".
	IAMToken logging.Secret `yaml:"iam_token,omitempty" json:"iam_token,omitempty"`

	// OAuthToken is a Yandex OAuth token exchanged for IAM tokens.
	// Implements slog.LogValuer — always logs as "[REDACTED]".
	OAuthToken logging.Secret `yaml:"oauth_token,omitempty" json:"oauth_token,omitempty"`

	// SAKeyFile is the path to a service account key file (JSON).
	SAKeyFile string `yaml:"sa_key_file,omitempty" json:"sa_key_file,omitempty"`
}

// TrafficConfig configures rate limiting / traffic shaping.
//
// Supports three YAML syntaxes:
//
//	x-csar-traffic: "standard-api"                    # bare string → policy ref
//	x-csar-traffic: { rps: 10, burst: 20, ... }       # inline object
//	x-csar-traffic: { use: "heavy-task", max_wait: "60s" }  # policy ref + overrides
type TrafficConfig struct {
	// Use is an optional reference to a named throttling_policies entry.
	// When set, all other fields are inherited from the policy; any
	// inline fields override the policy's values (shallow merge).
	Use string `yaml:"use,omitempty" json:"use,omitempty"`

	// RPS is the allowed requests per second.
	RPS float64 `yaml:"rps,omitempty" json:"rps,omitempty"`

	// Burst is the maximum burst size for the token bucket.
	Burst int `yaml:"burst,omitempty" json:"burst,omitempty"`

	// MaxWait is the maximum time a request can wait in the queue.
	MaxWait Duration `yaml:"max_wait,omitempty" json:"max_wait,omitempty"`

	// Backend selects the rate limiting implementation.
	// "local" (default): in-memory token bucket per pod.
	// "redis": distributed GCRA via Redis (requires top-level redis config).
	// "coordinator": local token bucket with quotas dynamically assigned by the coordinator.
	Backend string `yaml:"backend,omitempty" json:"backend,omitempty"`

	// Key is a dynamic throttle key template for per-entity rate limiting.
	// Uses placeholders like {query.seller_id} or {header.X-API-Key}.
	// When set, each unique resolved key gets its own rate limiter (requires Redis backend).
	Key string `yaml:"key,omitempty" json:"key,omitempty"`

	// ExcludeIPs is a list of IPs/CIDRs that bypass this route's throttle entirely.
	// Useful for internal monitoring services or health checkers.
	ExcludeIPs []string `yaml:"exclude_ips,omitempty" json:"exclude_ips,omitempty"`

	// VIPOverrides allows specific API keys (identified by a header value)
	// to use an alternate throttling policy instead of the default one.
	VIPOverrides []VIPOverride `yaml:"vip_overrides,omitempty" json:"vip_overrides,omitempty"`

	// AdaptiveBackpressure enables upstream backpressure awareness.
	// When enabled, the router reads Retry-After / X-RateLimit-Reset headers
	// from upstream 429 responses and suspends the token bucket accordingly.
	AdaptiveBackpressure *AdaptiveBackpressureConfig `yaml:"adaptive_backpressure,omitempty" json:"adaptive_backpressure,omitempty"`

	// ClientLimitMode controls how the X-CSAR-Client-Limit header is handled.
	// "ignore" (default): header is logged at debug level only.
	// "advisory": header is logged and counted in metrics.
	// "enforce": header is used as an input signal for adaptive throttling.
	ClientLimitMode string `yaml:"client_limit_mode,omitempty" json:"client_limit_mode,omitempty"`
}

// UnmarshalYAML handles bare string (policy reference) and inline object syntax.
//
// Supported:
//
//	x-csar-traffic: "standard-api"           → Use = "standard-api"
//	x-csar-traffic: { rps: 10, burst: 20 }   → inline fields
//	x-csar-traffic: { use: "heavy-task", max_wait: "60s" }  → policy ref + overrides
func (tc *TrafficConfig) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		tc.Use = value.Value
		return nil
	}

	// Alias to avoid infinite recursion.
	type trafficAlias TrafficConfig
	var alias trafficAlias
	if err := value.Decode(&alias); err != nil {
		return err
	}
	*tc = TrafficConfig(alias)
	return nil
}

// ThrottlingPolicy defines a named, reusable throttling configuration.
// Defined at the top-level throttling_policies map, referenced by name in routes.
type ThrottlingPolicy struct {
	// RPS is the allowed requests per second.
	RPS float64 `yaml:"rate" json:"rate"`

	// Burst is the maximum burst size for the token bucket.
	Burst int `yaml:"burst" json:"burst"`

	// MaxWait is the maximum time a request can wait in the queue.
	MaxWait Duration `yaml:"max_wait,omitempty" json:"max_wait,omitempty"`

	// Backend selects the rate limiting implementation.
	// "local" (default), "redis", or "coordinator".
	Backend string `yaml:"backend,omitempty" json:"backend,omitempty"`

	// Key is a dynamic throttle key template for per-entity rate limiting.
	// Uses placeholders: {query.seller_id}, {header.X-API-Key}.
	Key string `yaml:"key,omitempty" json:"key,omitempty"`

	// ExcludeIPs is a list of IPs/CIDRs that bypass this throttle entirely.
	ExcludeIPs []string `yaml:"exclude_ips,omitempty" json:"exclude_ips,omitempty"`

	// VIPOverrides allows header-based policy switching for VIP clients.
	VIPOverrides []VIPOverride `yaml:"vip_overrides,omitempty" json:"vip_overrides,omitempty"`

	// ClientLimitMode controls how the X-CSAR-Client-Limit header is handled.
	// "ignore" (default), "advisory", or "enforce".
	ClientLimitMode string `yaml:"client_limit_mode,omitempty" json:"client_limit_mode,omitempty"`
}

// GlobalThrottleConfig defines a global rate limit applied to all routes as a fallback.
// Uses a fast in-memory atomic counter (not Redis). Checked before per-route throttle.
type GlobalThrottleConfig struct {
	// RPS is the global requests per second limit across all routes.
	RPS float64 `yaml:"rate" json:"rate"`

	// Burst is the maximum burst size.
	Burst int `yaml:"burst" json:"burst"`

	// MaxWait is the maximum time a request can wait. Default: "0s" (reject immediately).
	MaxWait Duration `yaml:"max_wait,omitempty" json:"max_wait,omitempty"`
}

// VIPOverride maps a header value to an alternate throttling policy.
// When a request's header matches one of the Values, the alternate policy is used.
type VIPOverride struct {
	// Header is the HTTP header to check (e.g. "X-API-Key").
	Header string `yaml:"header" json:"header"`

	// Values maps header values to alternate throttling policy names.
	// Example: {"vip-key-123": "vip-unlimited", "partner-key": "partner-tier"}
	Values map[string]string `yaml:"values" json:"values"`
}

// ResilienceConfig configures circuit breaking.
type ResilienceConfig struct {
	// CircuitBreaker is the name of a circuit breaker profile.
	CircuitBreaker string `yaml:"circuit_breaker" json:"circuit_breaker"`
}

// ReadinessConfig configures the dependency-aware readiness probe.
type ReadinessConfig struct {
	// Enabled toggles the readiness endpoint. Default: true.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Path is the HTTP path for the readiness probe. Default: "/readiness".
	Path string `yaml:"path,omitempty" json:"path,omitempty"`

	// IncludeDetails includes per-check details in the response. Default: true.
	IncludeDetails *bool `yaml:"include_details,omitempty" json:"include_details,omitempty"`
}

// DebugHeadersConfig configures traceability and debug headers.
type DebugHeadersConfig struct {
	// Enabled toggles debug headers. Automatically disabled in prod unless explicitly set.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// EmitRouteID emits X-CSAR-Route-ID with the matched route key. Default: true.
	EmitRouteID *bool `yaml:"emit_route_id,omitempty" json:"emit_route_id,omitempty"`

	// RequestIDHeader is the header name for request ID propagation. Default: "X-Request-ID".
	RequestIDHeader string `yaml:"request_id_header,omitempty" json:"request_id_header,omitempty"`
}

// ProtocolPolicy configures per-route SDK protocol behavior.
type ProtocolPolicy struct {
	// EmitWaitMS controls whether X-CSAR-Wait-MS is emitted on successful responses.
	// nil = global default (true).
	EmitWaitMS *bool `yaml:"emit_wait_ms,omitempty" json:"emit_wait_ms,omitempty"`

	// TransparentRetry controls whether transparent upstream 429 retry is enabled.
	// nil = use x-csar-retry.auto_retry_429.
	TransparentRetry *bool `yaml:"transparent_retry,omitempty" json:"transparent_retry,omitempty"`

	// EmitClientHint controls whether the server emits X-CSAR-Client-Limit guidance.
	// nil = global default.
	EmitClientHint *bool `yaml:"emit_client_hint,omitempty" json:"emit_client_hint,omitempty"`
}

// RetryConfig configures automatic retry for upstream requests.
// Only idempotent methods (GET, HEAD, OPTIONS by default) are retried.
//
// Supports bare string syntax for policy references:
//
//	x-csar-retry: "safe-retry"             # bare string → policy ref
//	x-csar-retry: { max_attempts: 3, ... } # inline object
//	x-csar-retry: { use: "safe-retry", max_attempts: 5 } # policy ref + overrides
type RetryConfig struct {
	// Use is an optional reference to a named retry_policies entry.
	Use string `yaml:"use,omitempty" json:"use,omitempty"`

	// MaxAttempts is the maximum number of total attempts (including the original).
	// Default: 3.
	MaxAttempts int `yaml:"max_attempts" json:"max_attempts"`

	// Backoff is the base delay between retries (exponential backoff with jitter).
	// Default: "1s".
	Backoff Duration `yaml:"backoff" json:"backoff"`

	// MaxBackoff is the maximum delay between retries.
	// Default: "10s".
	MaxBackoff Duration `yaml:"max_backoff,omitempty" json:"max_backoff,omitempty"`

	// RetryableStatusCodes is the set of HTTP status codes that trigger a retry.
	// Default: [502, 503, 504].
	RetryableStatusCodes []int `yaml:"retryable_status_codes,omitempty" json:"retryable_status_codes,omitempty"`

	// RetryableMethods is the set of HTTP methods eligible for retry.
	// Default: ["GET", "HEAD", "OPTIONS"].
	RetryableMethods []string `yaml:"retryable_methods,omitempty" json:"retryable_methods,omitempty"`

	// AutoRetry429 enables transparent internal retries for upstream 429 responses.
	// When true and the upstream provides Retry-After, the router holds the client
	// connection, sleeps for the upstream-specified delay, and retries internally.
	// The client receives a 200 without ever seeing the 429.
	AutoRetry429 bool `yaml:"auto_retry_429,omitempty" json:"auto_retry_429,omitempty"`

	// MaxInternalWait is the maximum time the router will hold a client connection
	// while waiting for an upstream backpressure period to pass.
	// If the upstream asks to wait longer than this, the router returns 503 + X-CSAR-Status.
	// Default: "30s".
	MaxInternalWait Duration `yaml:"max_internal_wait,omitempty" json:"max_internal_wait,omitempty"`
}

// UnmarshalYAML handles bare string (policy reference) and inline object syntax for RetryConfig.
func (rc *RetryConfig) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		rc.Use = value.Value
		return nil
	}
	type retryAlias RetryConfig
	var alias retryAlias
	if err := value.Decode(&alias); err != nil {
		return err
	}
	*rc = RetryConfig(alias)
	return nil
}

// AdaptiveBackpressureConfig configures upstream backpressure awareness.
// When enabled, the router reads rate-limit headers from upstream 429 responses
// and dynamically suspends the token bucket to avoid hammering the upstream.
type AdaptiveBackpressureConfig struct {
	// Enabled toggles adaptive backpressure.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// RespectHeaders is the ordered list of response headers to check for wait time.
	// Default: ["Retry-After", "X-RateLimit-Reset"].
	RespectHeaders []string `yaml:"respect_headers,omitempty" json:"respect_headers,omitempty"`

	// SuspendBucket pauses token generation for the route when backpressure is detected.
	// Any incoming client requests during the suspension period wait in the queue
	// (up to their max_wait), preventing them from hitting the upstream.
	SuspendBucket bool `yaml:"suspend_bucket,omitempty" json:"suspend_bucket,omitempty"`

	// MaxBodyBuffer caps the request body size (in bytes) that the backpressure
	// middleware will buffer for transparent retry replay. Bodies larger than
	// this bypass interception entirely and are proxied directly.
	// Default: 10 MiB. Set to 0 to use the default.
	MaxBodyBuffer int64 `yaml:"max_body_buffer,omitempty" json:"max_body_buffer,omitempty"`
}

// AuthValidateConfig configures inbound JWT/JWKS validation (audit §3.3.1).
// When present on a route, CSAR validates the bearer token before proxying.
//
// Supports bare string syntax for policy references:
//
//	x-csar-authn-validate: "jwt-internal"          # bare string → policy ref
//	x-csar-authn-validate: { jwks_url: "...", ... } # inline object
type AuthValidateConfig struct {
	// Use is an optional reference to a named auth_validate_policies entry.
	Use string `yaml:"use,omitempty" json:"use,omitempty"`

	// JWKSURL is the endpoint serving the JSON Web Key Set.
	// Example: "https://auth.example.com/.well-known/jwks.json"
	JWKSURL string `yaml:"jwks_url" json:"jwks_url"`

	// Issuer, if set, validates the "iss" claim matches.
	Issuer string `yaml:"issuer,omitempty" json:"issuer,omitempty"`

	// Audiences, if set, validates the "aud" claim contains at least one entry.
	Audiences []string `yaml:"audiences,omitempty" json:"audiences,omitempty"`

	// HeaderName is the HTTP header carrying the token. Default: "Authorization".
	HeaderName string `yaml:"header_name,omitempty" json:"header_name,omitempty"`

	// TokenPrefix is stripped from the header value before parsing.
	// Default: "Bearer " (with trailing space).
	TokenPrefix string `yaml:"token_prefix,omitempty" json:"token_prefix,omitempty"`

	// CacheTTL controls how long JWKS keys are cached. Default: 5m.
	CacheTTL Duration `yaml:"cache_ttl,omitempty" json:"cache_ttl,omitempty"`

	// RequiredClaims specifies claim key=value pairs that must be present.
	// Example: {"role": "admin"}
	RequiredClaims map[string]string `yaml:"required_claims,omitempty" json:"required_claims,omitempty"`

	// ForwardClaims copies specified JWT claims into request headers
	// before proxying. Map key = claim name, value = header name.
	// Example: {"sub": "X-User-ID", "email": "X-User-Email"}
	ForwardClaims map[string]string `yaml:"forward_claims,omitempty" json:"forward_claims,omitempty"`

	// CookieName, if set, reads the JWT from the named cookie instead of
	// a request header. When set, HeaderName and TokenPrefix are ignored.
	// Useful for browser-based auth where csar-authn issues session cookies.
	CookieName string `yaml:"cookie_name,omitempty" json:"cookie_name,omitempty"`
}

// UnmarshalYAML handles bare string (policy reference) and inline object syntax for AuthValidateConfig.
func (av *AuthValidateConfig) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		av.Use = value.Value
		return nil
	}
	type avAlias AuthValidateConfig
	var alias avAlias
	if err := value.Decode(&alias); err != nil {
		return err
	}
	*av = AuthValidateConfig(alias)
	return nil
}

// RedactConfig configures response payload redaction / DLP (audit §3.3.2).
// Matching JSON fields are masked before the response is returned to the client.
//
// Supports bare string syntax for policy references:
//
//	x-csar-redact: "pii-mask"                    # bare string → policy ref
//	x-csar-redact: { fields: ["email"], ... }    # inline object
type RedactConfig struct {
	// Use is an optional reference to a named redact_policies entry.
	Use string `yaml:"use,omitempty" json:"use,omitempty"`

	// Fields is a list of JSON field paths to redact.
	// Supports dot notation (e.g. "user.email", "data.ssn").
	// Nested wildcards: "users.*.email" redacts email in every array element.
	Fields []string `yaml:"fields" json:"fields"`

	// Mask is the replacement string. Default: "***REDACTED***".
	Mask string `yaml:"mask,omitempty" json:"mask,omitempty"`

	// Enabled allows disabling redaction without removing the config.
	// Default: true (if the block is present, redaction is on).
	Enabled *bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`
}

// IsEnabled returns true if redaction is active.
func (rc *RedactConfig) IsEnabled() bool {
	if rc.Enabled == nil {
		return true // default when block is present
	}
	return *rc.Enabled
}

// UnmarshalYAML handles bare string (policy reference) and inline object syntax for RedactConfig.
func (rc *RedactConfig) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		rc.Use = value.Value
		return nil
	}
	type redactAlias RedactConfig
	var alias redactAlias
	if err := value.Decode(&alias); err != nil {
		return err
	}
	*rc = RedactConfig(alias)
	return nil
}

// TenantConfig configures multi-tenant routing (audit §3.3.3).
// A tenant identifier is extracted from headers and used to select
// a backend from the Backends map.
type TenantConfig struct {
	// Header is the HTTP header used to identify the tenant.
	// Common choices: "Host", "X-Tenant-ID".
	Header string `yaml:"header" json:"header"`

	// Backends maps tenant identifiers to target URLs.
	// Example: {"acme": "https://api-acme.example.com", "globex": "https://api-globex.example.com"}
	Backends map[string]string `yaml:"backends" json:"backends"`

	// Default is the fallback target URL when no tenant header matches.
	// If empty, unmatched tenants receive 404.
	Default string `yaml:"default,omitempty" json:"default,omitempty"`
}

// CORSConfig configures Cross-Origin Resource Sharing (CORS) for a route.
// When present, CSAR automatically handles preflight OPTIONS requests
// and injects CORS headers into responses.
//
// Supports bare string syntax for policy references:
//
//	x-csar-cors: "standard-cors"                         # bare string → policy ref
//	x-csar-cors: { allowed_origins: ["*"], ... }         # inline object
type CORSConfig struct {
	// Use is an optional reference to a named cors_policies entry.
	Use string `yaml:"use,omitempty" json:"use,omitempty"`

	// AllowedOrigins is the list of allowed origins.
	// Use "*" to allow all origins (not recommended for production).
	AllowedOrigins []string `yaml:"allowed_origins" json:"allowed_origins"`

	// AllowedMethods is the list of allowed HTTP methods.
	// Default: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"].
	AllowedMethods []string `yaml:"allowed_methods,omitempty" json:"allowed_methods,omitempty"`

	// AllowedHeaders is the list of allowed request headers.
	// Default: ["Content-Type", "Authorization"].
	AllowedHeaders []string `yaml:"allowed_headers,omitempty" json:"allowed_headers,omitempty"`

	// ExposedHeaders is the list of headers exposed to the browser.
	ExposedHeaders []string `yaml:"exposed_headers,omitempty" json:"exposed_headers,omitempty"`

	// AllowCredentials indicates whether the request can include cookies.
	AllowCredentials bool `yaml:"allow_credentials,omitempty" json:"allow_credentials,omitempty"`

	// MaxAge is the max time (in seconds) a preflight response can be cached.
	// Default: 86400 (24 hours).
	MaxAge int `yaml:"max_age,omitempty" json:"max_age,omitempty"`
}

// UnmarshalYAML handles bare string (policy reference) and inline object syntax for CORSConfig.
func (cc *CORSConfig) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		cc.Use = value.Value
		return nil
	}
	type corsAlias CORSConfig
	var alias corsAlias
	if err := value.Decode(&alias); err != nil {
		return err
	}
	*cc = CORSConfig(alias)
	return nil
}

// CacheConfig configures HTTP response caching for a route.
// Caches responses from idempotent methods respecting Cache-Control / ETag.
type CacheConfig struct {
	// Enabled allows disabling caching without removing the config.
	// Default: true (if the block is present, caching is on).
	Enabled *bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`

	// TTL is the default cache TTL if no Cache-Control header is present.
	// Default: "5m".
	TTL Duration `yaml:"ttl,omitempty" json:"ttl,omitempty"`

	// MaxEntries is the maximum number of cached responses.
	// Default: 1000. Uses LRU eviction.
	MaxEntries int `yaml:"max_entries,omitempty" json:"max_entries,omitempty"`

	// MaxBodySize is the maximum response body size to cache (in bytes).
	// Responses larger than this are not cached. Default: 1MB.
	MaxBodySize int64 `yaml:"max_body_size,omitempty" json:"max_body_size,omitempty"`

	// Methods is the set of HTTP methods to cache.
	// Default: ["GET", "HEAD"].
	Methods []string `yaml:"methods,omitempty" json:"methods,omitempty"`
}

// IsEnabled returns true if caching is active.
func (cc *CacheConfig) IsEnabled() bool {
	if cc.Enabled == nil {
		return true
	}
	return *cc.Enabled
}

// SSRFConfig configures SSRF protection for the proxy.
type SSRFConfig struct {
	// BlockPrivate blocks connections to RFC 1918 private subnets.
	// Default: true.
	BlockPrivate *bool `yaml:"block_private,omitempty" json:"block_private,omitempty"`

	// BlockLoopback blocks connections to loopback addresses (127.0.0.0/8, ::1).
	// Default: true.
	BlockLoopback *bool `yaml:"block_loopback,omitempty" json:"block_loopback,omitempty"`

	// BlockLinkLocal blocks connections to link-local addresses (169.254.0.0/16, fe80::/10).
	// Default: true.
	BlockLinkLocal *bool `yaml:"block_link_local,omitempty" json:"block_link_local,omitempty"`

	// BlockMetadata blocks connections to cloud metadata endpoints (169.254.169.254).
	// Default: true.
	BlockMetadata *bool `yaml:"block_metadata,omitempty" json:"block_metadata,omitempty"`

	// AllowedInternalHosts is an explicit allowlist of internal hosts that may be accessed.
	AllowedInternalHosts []string `yaml:"allowed_internal_hosts,omitempty" json:"allowed_internal_hosts,omitempty"`
}

// IsBlockPrivate returns whether private subnet blocking is enabled.
func (s *SSRFConfig) IsBlockPrivate() bool {
	if s.BlockPrivate == nil {
		return true
	}
	return *s.BlockPrivate
}

// IsBlockLoopback returns whether loopback blocking is enabled.
func (s *SSRFConfig) IsBlockLoopback() bool {
	if s.BlockLoopback == nil {
		return true
	}
	return *s.BlockLoopback
}

// IsBlockLinkLocal returns whether link-local blocking is enabled.
func (s *SSRFConfig) IsBlockLinkLocal() bool {
	if s.BlockLinkLocal == nil {
		return true
	}
	return *s.BlockLinkLocal
}

// IsBlockMetadata returns whether metadata endpoint blocking is enabled.
func (s *SSRFConfig) IsBlockMetadata() bool {
	if s.BlockMetadata == nil {
		return true
	}
	return *s.BlockMetadata
}

// RedisConfig configures a Redis connection for distributed rate limiting.
type RedisConfig struct {
	// Address is the Redis server address (e.g. "localhost:6379").
	Address string `yaml:"address" json:"address"`

	// Password is the Redis AUTH password (optional).
	Password logging.Secret `yaml:"password,omitempty" json:"password,omitempty"`

	// DB is the Redis database number (default: 0).
	DB int `yaml:"db,omitempty" json:"db,omitempty"`

	// KeyPrefix is the prefix for all rate limiting keys (default: "csar:rl:").
	KeyPrefix string `yaml:"key_prefix,omitempty" json:"key_prefix,omitempty"`
}

// CircuitBreakerProfile defines a named circuit breaker configuration.
type CircuitBreakerProfile struct {
	// MaxRequests is the maximum number of requests allowed in half-open state.
	MaxRequests uint32 `yaml:"max_requests" json:"max_requests"`

	// Interval is the cyclic period of the closed state for clearing internal counts.
	Interval Duration `yaml:"interval" json:"interval"`

	// Timeout is the period of the open state, after which the state becomes half-open.
	Timeout Duration `yaml:"timeout" json:"timeout"`

	// FailureThreshold is the number of failures before opening the circuit.
	FailureThreshold uint32 `yaml:"failure_threshold" json:"failure_threshold"`
}

// Duration is a type alias for the shared configutil.Duration.
type Duration = configutil.Duration

// RouteKey uniquely identifies a route by path and method.
type RouteKey struct {
	Path   string
	Method string
}

// FlatRoutes returns a flat list of all routes with their path and method for easy iteration.
func (c *Config) FlatRoutes() []FlatRoute {
	var routes []FlatRoute
	for path, methods := range c.Paths {
		for method := range methods {
			route := methods[method]
			routes = append(routes, FlatRoute{
				Path:   path,
				Method: method,
				Route:  route,
			})
		}
	}
	return routes
}

// HasSecureRoutes returns true if any route has x-csar-security configuration.
// Used by the bootstrap to decide whether an AuthInjector must be wired in.
func (c *Config) HasSecureRoutes() bool {
	for _, methods := range c.Paths {
		for method := range methods {
			route := methods[method]
			for _, sec := range route.Security {
				if sec.InjectHeader != "" {
					return true
				}
			}
		}
	}
	return false
}

// FlatRoute is a denormalized route for easy iteration.
type FlatRoute struct {
	Path   string
	Method string
	Route  RouteConfig
}

// AuthzClientConfig configures the gRPC connection to the csar-authz service.
type AuthzClientConfig struct {
	// Address is the gRPC address of the csar-authz service (e.g. "localhost:9091").
	Address string `yaml:"address" json:"address"`

	// TLS settings for the csar → csar-authz gRPC connection.
	CAFile   string `yaml:"ca_file,omitempty" json:"ca_file,omitempty"`
	CertFile string `yaml:"cert_file,omitempty" json:"cert_file,omitempty"`
	KeyFile  string `yaml:"key_file,omitempty" json:"key_file,omitempty"`

	// AllowInsecure permits plaintext gRPC to csar-authz (dev only).
	AllowInsecure bool `yaml:"allow_insecure,omitempty" json:"allow_insecure,omitempty"`

	// Timeout is the per-call deadline for CheckAccess RPCs. Default: "500ms".
	Timeout Duration `yaml:"timeout,omitempty" json:"timeout,omitempty"`
}

// AuthzRouteConfig configures per-route authorization via csar-authz.
// Placeholders use the same syntax as token_ref: {header.X-User-Id}, {query.id}, {path.id}.
//
// Supports bare string syntax for policy references:
//
//	x-csar-authz: "tenant-docs"                       # bare string → policy ref
//	x-csar-authz: { subject: "{header.X-User-Id}", ... } # inline object
//	x-csar-authz: { use: "tenant-docs", action: "write" } # policy ref + overrides
type AuthzRouteConfig struct {
	// Use is an optional reference to a named authz_policies entry.
	// When set, all other fields are inherited from the policy; any
	// inline fields override the policy's values (shallow merge).
	Use string `yaml:"use,omitempty" json:"use,omitempty"`

	// Subject is the principal identifier. Example: "{header.X-User-Id}".
	Subject string `yaml:"subject,omitempty" json:"subject,omitempty"`

	// Resource is the target resource path. Example: "document:{path.id}".
	Resource string `yaml:"resource,omitempty" json:"resource,omitempty"`

	// Action is the operation being performed. Example: "read".
	Action string `yaml:"action,omitempty" json:"action,omitempty"`

	// ScopeType is the assignment scope: "platform" or "tenant".
	ScopeType string `yaml:"scope_type,omitempty" json:"scope_type,omitempty"`

	// ScopeID identifies the scope instance. Example: "{header.X-Tenant-Id}".
	ScopeID string `yaml:"scope_id,omitempty" json:"scope_id,omitempty"`

	// StripHeaders lists headers to unconditionally remove from client requests
	// before calling csar-authz (prevents spoofing). Example: ["X-User-Roles", "X-Authz-Decision"].
	StripHeaders []string `yaml:"strip_headers,omitempty" json:"strip_headers,omitempty"`
}

// UnmarshalYAML handles bare string (policy reference) and inline object syntax for AuthzRouteConfig.
func (a *AuthzRouteConfig) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		a.Use = value.Value
		return nil
	}
	type authzAlias AuthzRouteConfig
	var alias authzAlias
	if err := value.Decode(&alias); err != nil {
		return err
	}
	*a = AuthzRouteConfig(alias)
	return nil
}
