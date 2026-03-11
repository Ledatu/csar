package coordinator

import (
	"fmt"
	"time"
)

// AdminAPIConfig holds configuration for the coordinator's internal admin
// HTTP API used for token lifecycle management.
type AdminAPIConfig struct {
	Enabled    bool
	ListenAddr string

	TLS           AdminTLSConfig
	Auth          AdminAuthConfig
	Authorization AdminAuthzConfig
	Limits        AdminLimitsConfig

	// S3ManagesEncryption controls whether the coordinator writes plaintext
	// to S3 and relies on S3's server-side encryption (SSE-S3, SSE-KMS),
	// or encrypts via CSAR KMS before writing.
	//
	// This field is REQUIRED (no default). Startup fails if not explicitly set.
	//   true  -> plaintext written to S3, S3 SSE handles at-rest encryption
	//   false -> CSAR KMS encrypts before S3 write, kms_key_id required
	S3ManagesEncryption *bool

	// AllowInsecure bypasses the TLS requirement for the admin API.
	// Intended ONLY for local development and testing.
	AllowInsecure bool
}

// AdminTLSConfig holds TLS settings for the admin API listener.
type AdminTLSConfig struct {
	CertFile     string
	KeyFile      string
	ClientCAFile string // optional, enables mTLS if set
}

// AdminAuthConfig holds JWT authentication settings for the admin API.
type AdminAuthConfig struct {
	JWKSUrl   string
	Issuer    string
	Audiences []string
}

// AdminAuthzConfig holds authorization policy settings.
type AdminAuthzConfig struct {
	RequiredScopes          map[string]string // operation -> scope (e.g. "write" -> "csar.token.write")
	EnforceTokenPrefixClaim bool
	EnforceAllowedKMSKeys   bool
	AllowedKMSKeys          []string
}

// AdminLimitsConfig holds request limits for the admin API.
type AdminLimitsConfig struct {
	MaxTokenSize   int64         // max body size in bytes (default 16384)
	RequestTimeout time.Duration // per-request timeout (default 5s)
}

// Validate checks that the AdminAPIConfig is well-formed. Returns an error
// describing the first problem found.
func (c *AdminAPIConfig) Validate() error {
	if !c.Enabled {
		return nil
	}

	if c.ListenAddr == "" {
		return fmt.Errorf("admin_api: listen_addr is required when admin API is enabled")
	}

	if c.S3ManagesEncryption == nil {
		return fmt.Errorf("admin_api: s3_manages_encryption must be explicitly set (true or false) — " +
			"this field has no default value to force an explicit encryption strategy choice")
	}

	if !c.AllowInsecure && (c.TLS.CertFile == "" || c.TLS.KeyFile == "") {
		return fmt.Errorf("admin_api: TLS cert and key are required when admin API is enabled " +
			"(set --admin-allow-insecure for local development only)")
	}

	if c.Auth.JWKSUrl == "" {
		return fmt.Errorf("admin_api: auth.jwks_url is required")
	}
	if c.Auth.Issuer == "" {
		return fmt.Errorf("admin_api: auth.issuer is required")
	}
	if len(c.Auth.Audiences) == 0 {
		return fmt.Errorf("admin_api: auth.audiences must contain at least one value")
	}

	if c.Limits.MaxTokenSize <= 0 {
		c.Limits.MaxTokenSize = 16384
	}
	if c.Limits.RequestTimeout <= 0 {
		c.Limits.RequestTimeout = 5 * time.Second
	}

	return nil
}
