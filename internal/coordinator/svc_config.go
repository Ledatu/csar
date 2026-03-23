package coordinator

import "fmt"

// SvcAPIConfig holds configuration for the coordinator's service-facing token
// API, which allows backend services (via the csar router) to write/delete
// tokens within their own namespace.
type SvcAPIConfig struct {
	// PrefixMap maps service subject (from X-Gateway-Subject) to the
	// allowed token_ref prefix. For example:
	//   "svc:aurumskynet-campaigns" -> "campaigns/"
	// An empty map disables all service-facing token operations.
	PrefixMap map[string]string
}

// AllowedPrefix returns the token_ref prefix that the given subject is
// permitted to operate on. Returns ("", false) if the subject has no entry.
func (c *SvcAPIConfig) AllowedPrefix(subject string) (string, bool) {
	if c == nil || len(c.PrefixMap) == 0 {
		return "", false
	}
	p, ok := c.PrefixMap[subject]
	return p, ok
}

// Validate checks the SvcAPIConfig for obvious problems.
func (c *SvcAPIConfig) Validate() error {
	for subject, prefix := range c.PrefixMap {
		if subject == "" {
			return fmt.Errorf("svc_api: empty subject in prefix map")
		}
		if prefix == "" {
			return fmt.Errorf("svc_api: empty prefix for subject %q", subject)
		}
	}
	return nil
}
