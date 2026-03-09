package coordinator

import (
	"fmt"
	"regexp"
	"strings"
)

const maxTokenRefLength = 256

var tokenRefPattern = regexp.MustCompile(`^[a-zA-Z0-9/_-]+$`)

// ValidateTokenRef checks that a token_ref is safe and well-formed.
// Allowed characters: [a-zA-Z0-9/_-]. No "..", no leading "//", no spaces.
func ValidateTokenRef(ref string) error {
	if ref == "" {
		return fmt.Errorf("token_ref is required")
	}
	if len(ref) > maxTokenRefLength {
		return fmt.Errorf("token_ref exceeds maximum length of %d characters", maxTokenRefLength)
	}
	if strings.Contains(ref, "..") {
		return fmt.Errorf("token_ref must not contain path traversal pattern \"..\"")
	}
	if strings.HasPrefix(ref, "//") {
		return fmt.Errorf("token_ref must not start with \"//\"")
	}
	if strings.HasPrefix(ref, "/") {
		return fmt.Errorf("token_ref must not start with \"/\"")
	}
	if !tokenRefPattern.MatchString(ref) {
		return fmt.Errorf("token_ref contains invalid characters (allowed: a-zA-Z0-9/_-)")
	}
	return nil
}
