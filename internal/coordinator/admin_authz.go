package coordinator

import (
	"fmt"
	"strings"
)

// AdminOperation represents an admin API operation for scope checks.
type AdminOperation string

const (
	OpWrite      AdminOperation = "write"
	OpRotate     AdminOperation = "rotate"
	OpDelete     AdminOperation = "delete"
	OpRead       AdminOperation = "read"
	OpInvalidate AdminOperation = "invalidate"
)

// DefaultRequiredScopes maps operations to their default required JWT scope values.
var DefaultRequiredScopes = map[string]string{
	"write":      "csar.token.write",
	"rotate":     "csar.token.rotate",
	"delete":     "csar.token.delete",
	"read":       "csar.token.read",
	"invalidate": "csar.token.invalidate",
}

// CheckAdminAuthorization verifies that the caller's claims permit the
// requested operation on the specified token_ref with the given kms_key_id.
func CheckAdminAuthorization(claims *AdminClaims, authzCfg AdminAuthzConfig, op AdminOperation, tokenRef, kmsKeyID string) error {
	if claims == nil {
		return fmt.Errorf("authorization: no claims present")
	}

	requiredScopes := authzCfg.RequiredScopes
	if len(requiredScopes) == 0 {
		requiredScopes = DefaultRequiredScopes
	}

	requiredScope, ok := requiredScopes[string(op)]
	if ok && requiredScope != "" {
		if !hasScope(claims.Scope, requiredScope) {
			return fmt.Errorf("authorization: missing required scope %q for operation %q", requiredScope, op)
		}
	}

	if authzCfg.EnforceTokenPrefixClaim {
		if claims.TokenPrefix == "" {
			return fmt.Errorf("authorization: token_prefix claim is required but absent")
		}
		if tokenRef != "" && !strings.HasPrefix(tokenRef, claims.TokenPrefix) {
			return fmt.Errorf("authorization: token_ref %q not within allowed prefix %q", tokenRef, claims.TokenPrefix)
		}
	}

	isMutatingOp := op == OpWrite || op == OpRotate || op == OpDelete
	if authzCfg.EnforceAllowedKMSKeys && kmsKeyID != "" {
		if len(claims.AllowedKMSKeys) == 0 {
			return fmt.Errorf("authorization: allowed_kms_keys claim is required but absent")
		}
		found := false
		for _, allowed := range claims.AllowedKMSKeys {
			if allowed == kmsKeyID {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("authorization: kms_key_id %q not in allowed list", kmsKeyID)
		}
	} else if authzCfg.EnforceAllowedKMSKeys && isMutatingOp && len(claims.AllowedKMSKeys) == 0 && kmsKeyID == "" {
		// For mutating operations, if enforcement is on and the claim is absent,
		// still allow only when kms_key_id is not involved (e.g. s3_manages_encryption=true).
		// This is intentionally permissive for passthrough mode only.
	}

	if len(authzCfg.AllowedKMSKeys) > 0 && kmsKeyID != "" {
		found := false
		for _, allowed := range authzCfg.AllowedKMSKeys {
			if allowed == kmsKeyID {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("authorization: kms_key_id %q not in server-configured allowed list", kmsKeyID)
		}
	}

	return nil
}

// hasScope checks if the space-separated scope string contains the required scope.
func hasScope(scopeStr, required string) bool {
	for _, s := range strings.Fields(scopeStr) {
		if s == required {
			return true
		}
	}
	return false
}
