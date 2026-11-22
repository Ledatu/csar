package authn

import (
	"github.com/ledatu/csar-core/caller"
	"github.com/ledatu/csar-core/gatewayctx"
)

func validateIssuerCaller(id *caller.Identity, subject, credentialID string, kind caller.CredentialKind) error {
	if id == nil {
		return nil // Legacy issuer; do not infer a caller kind from transport.
	}
	if id.ValidateBinding(subject, credentialID) != nil || kind != "" && id.CredentialKind != kind {
		return gatewayctx.ErrInvalidCaller
	}
	return nil
}
