package helper

import "context"

// TokenData represents a token read from an external source.
type TokenData struct {
	Plaintext      string // non-empty if source provides plaintext
	EncryptedToken []byte // non-empty if source provides pre-encrypted blob
	KMSKeyID       string // may be empty (use --kms-key-id default)

	// GrantProfile is non-empty when the entry is a mint descriptor rather
	// than a stored token. Such entries carry no value: the token is minted
	// on demand by the coordinator. Tools must report them, not migrate them.
	GrantProfile string
}

// IsDescriptor reports whether the entry describes a minted credential.
func (t TokenData) IsDescriptor() bool { return t.GrantProfile != "" }

// TokenSource reads plaintext or pre-encrypted tokens from an external system.
type TokenSource interface {
	// Load returns token_ref -> TokenData pairs.
	Load(ctx context.Context) (map[string]TokenData, error)
}
