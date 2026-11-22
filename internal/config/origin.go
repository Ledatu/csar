package config

import (
	"fmt"
	"net/url"
	"path"
	"strings"
)

// OriginIssuerConfig is immutable for the lifetime of the router process.
// Inline TLS settings deliberately do not follow reloadable backend policies.
type OriginIssuerConfig struct {
	Endpoint string           `yaml:"endpoint" json:"endpoint"`
	Issuer   string           `yaml:"issuer" json:"issuer"`
	JWKSURL  string           `yaml:"jwks_url" json:"jwks_url"`
	TLS      BackendTLSPolicy `yaml:"tls" json:"tls"`
}

func (c *OriginIssuerConfig) Validate() error {
	if c == nil {
		return nil
	}
	if strings.TrimSpace(c.Issuer) == "" || c.TLS.InsecureSkipVerify || c.TLS.CertFile == "" || c.TLS.KeyFile == "" {
		return fmt.Errorf("origin_issuer requires issuer and verified mTLS with cert_file/key_file")
	}
	for _, endpoint := range []string{c.Endpoint, c.JWKSURL} {
		u, err := url.Parse(endpoint)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.Path == "" || u.RawPath != "" || path.Clean(u.Path) != u.Path || strings.HasPrefix(u.Path, "//") || strings.ContainsAny(u.Path, "\\\x00\r\n") {
			return fmt.Errorf("origin_issuer requires canonical HTTPS endpoint and jwks_url without userinfo/query/fragment")
		}
	}
	return nil
}

// OriginPolicyVersion and OriginPolicyCapability describe preservation support,
// not whether root issuance has been configured on a particular router.
const (
	OriginPolicyVersion    uint32 = 1
	OriginPolicyCapability        = "csar.origin_policy_version"
)

func (c *Config) HasOriginReceivers() bool {
	for _, methods := range c.Paths {
		for method := range methods {
			if methods[method].OriginReceiver != "" {
				return true
			}
		}
	}
	return false
}
