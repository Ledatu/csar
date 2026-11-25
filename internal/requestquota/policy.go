// Package requestquota owns pure validation for router request-cap policies.
package requestquota

import (
	"fmt"
	"regexp"
	"time"
)

// Policy is a rolling request cap. Zero permits no requests; it is useful when
// an external allowance has not yet been verified, without inventing a default.
type Policy struct {
	Name, Key string
	Requests  int
	Window    time.Duration
}

var validName = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,64}$`)

// Validate checks the common shape used by configuration and runtime admission.
// Route replay/bypass rules and client capabilities remain at their own boundaries.
func Validate(quotas []Policy) error {
	if len(quotas) > 8 {
		return fmt.Errorf("at most 8 request quotas are supported")
	}
	seen := make(map[string]bool, len(quotas))
	for _, q := range quotas {
		if !validName.MatchString(q.Name) || q.Key == "" || len(q.Key) > 256 || q.Key != quotas[0].Key || seen[q.Name] || q.Requests < 0 || q.Requests > 10000 || q.Window < time.Second || q.Window > 24*time.Hour || q.Window%time.Millisecond != 0 {
			return fmt.Errorf("invalid request quota policy")
		}
		seen[q.Name] = true
	}
	return nil
}
