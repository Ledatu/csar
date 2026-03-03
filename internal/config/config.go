package config

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

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

// UnmarshalYAML handles both a single SecurityConfig object and an array.
func (sc *SecurityConfigs) UnmarshalYAML(value *yaml.Node) error {
	// YAML sequence → decode as []SecurityConfig
	if value.Kind == yaml.SequenceNode {
		var items []SecurityConfig
		if err := value.Decode(&items); err != nil {
			return err
		}
		*sc = items
		return nil
	}
	// YAML mapping → single object, wrap in a slice
	var single SecurityConfig
	if err := value.Decode(&single); err != nil {
		return err
	}
	*sc = SecurityConfigs{single}
	return nil
}

// Config holds the top-level CSAR configuration.
type Config struct {
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

	// CircuitBreakers defines named circuit breaker profiles.
	CircuitBreakers map[string]CircuitBreakerProfile `yaml:"circuit_breakers,omitempty" json:"circuit_breakers,omitempty"`

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
	AuthValidate *AuthValidateConfig `yaml:"x-csar-auth-validate,omitempty" json:"x-csar-auth-validate,omitempty"`

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

	// TLS configures the outbound TLS connection to this upstream.
	TLS *BackendTLSConfig `yaml:"tls,omitempty" json:"tls,omitempty"`
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
type TrafficConfig struct {
	// RPS is the allowed requests per second.
	RPS float64 `yaml:"rps" json:"rps"`

	// Burst is the maximum burst size for the token bucket.
	Burst int `yaml:"burst" json:"burst"`

	// MaxWait is the maximum time a request can wait in the queue.
	MaxWait Duration `yaml:"max_wait" json:"max_wait"`

	// Backend selects the rate limiting implementation.
	// "local" (default): in-memory token bucket per pod.
	// "redis": distributed sliding window via Redis (requires top-level redis config).
	// "coordinator": local token bucket with quotas dynamically assigned by the coordinator.
	Backend string `yaml:"backend,omitempty" json:"backend,omitempty"`
}

// ResilienceConfig configures circuit breaking.
type ResilienceConfig struct {
	// CircuitBreaker is the name of a circuit breaker profile.
	CircuitBreaker string `yaml:"circuit_breaker" json:"circuit_breaker"`
}

// RetryConfig configures automatic retry for upstream requests.
// Only idempotent methods (GET, HEAD, OPTIONS by default) are retried.
type RetryConfig struct {
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
}

// AuthValidateConfig configures inbound JWT/JWKS validation (audit §3.3.1).
// When present on a route, CSAR validates the bearer token before proxying.
type AuthValidateConfig struct {
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
}

// RedactConfig configures response payload redaction / DLP (audit §3.3.2).
// Matching JSON fields are masked before the response is returned to the client.
type RedactConfig struct {
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
type CORSConfig struct {
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

// Duration is a time.Duration that supports YAML string unmarshalling (e.g. "30s").
type Duration struct {
	time.Duration
}

// UnmarshalYAML parses a duration string like "30s", "5m", "1h".
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	d.Duration = dur
	return nil
}

// MarshalYAML writes the duration as a string.
func (d Duration) MarshalYAML() (interface{}, error) {
	return d.Duration.String(), nil
}

// Load reads and parses a CSAR config file from the given path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file %s: %w", path, err)
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config file %s: %w", path, err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	return cfg, nil
}

// Validate checks the configuration for required fields and consistency.
func (c *Config) Validate() error {
	if c.ListenAddr == "" {
		return fmt.Errorf("listen_addr is required")
	}
	if len(c.Paths) == 0 {
		return fmt.Errorf("at least one path must be defined")
	}

	var warnings []string

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
			return fmt.Errorf("coordinator: transport security is required — "+
				"set coordinator.ca_file for TLS, or coordinator.allow_insecure: true for development")
		}
	} else {
		// Coordinator is disabled — warn if TLS fields are set (dead config)
		if coord.CAFile != "" || coord.CertFile != "" || coord.KeyFile != "" {
			warnings = append(warnings,
				"coordinator is disabled but TLS fields (ca_file/cert_file/key_file) are set — these have no effect")
		}
	}

	// Validate global access control
	if c.AccessControl != nil {
		for _, cidr := range c.AccessControl.AllowCIDRs {
			if err := validateCIDROrIP(cidr); err != nil {
				return fmt.Errorf("access_control.allow_cidrs: %w", err)
			}
		}
	}

	for path, methods := range c.Paths {
		for method, route := range methods {
			if route.Backend.TargetURL == "" {
				return fmt.Errorf("path %s method %s: x-csar-backend.target_url is required", path, method)
			}
			if route.Resilience != nil && route.Resilience.CircuitBreaker != "" {
				if _, ok := c.CircuitBreakers[route.Resilience.CircuitBreaker]; !ok {
					return fmt.Errorf("path %s method %s: circuit_breaker profile %q not defined in circuit_breakers",
						path, method, route.Resilience.CircuitBreaker)
				}
			}

			// Validate backend TLS config
			if bt := route.Backend.TLS; bt != nil {
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

		// Validate auth-validate (JWT/JWKS) config
		if route.AuthValidate != nil {
			if route.AuthValidate.JWKSURL == "" {
				return fmt.Errorf("path %s method %s: x-csar-auth-validate.jwks_url is required", path, method)
			}
			if !strings.HasPrefix(route.AuthValidate.JWKSURL, "https://") && !strings.HasPrefix(route.AuthValidate.JWKSURL, "http://") {
				return fmt.Errorf("path %s method %s: x-csar-auth-validate.jwks_url must start with http:// or https://", path, method)
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

// RouteKey uniquely identifies a route by path and method.
type RouteKey struct {
	Path   string
	Method string
}

// FlatRoutes returns a flat list of all routes with their path and method for easy iteration.
func (c *Config) FlatRoutes() []FlatRoute {
	var routes []FlatRoute
	for path, methods := range c.Paths {
		for method, route := range methods {
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
		for _, route := range methods {
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
