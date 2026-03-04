package helper

import "context"

// TokenData represents a token read from an external source.
type TokenData struct {
	Plaintext      string // non-empty if source provides plaintext
	EncryptedToken []byte // non-empty if source provides pre-encrypted blob
	KMSKeyID       string // may be empty (use --kms-key-id default)
}

// TokenSource reads plaintext or pre-encrypted tokens from an external system.
type TokenSource interface {
	// Load returns token_ref -> TokenData pairs.
	Load(ctx context.Context) (map[string]TokenData, error)
}
