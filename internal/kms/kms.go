package kms

import "context"

// Provider defines the interface for KMS operations.
// Implementations handle encryption and decryption of data using
// key management services (local, Yandex Cloud KMS, AWS KMS, etc.).
type Provider interface {
	// Name returns a human-readable provider identifier (e.g. "local", "yandexapi").
	Name() string

	// Encrypt encrypts plaintext using the specified KMS key.
	Encrypt(ctx context.Context, keyID string, plaintext []byte) ([]byte, error)

	// Decrypt decrypts ciphertext using the specified KMS key.
	Decrypt(ctx context.Context, keyID string, ciphertext []byte) ([]byte, error)

	// Health performs a lightweight connectivity / auth check.
	// Returning nil means the provider is healthy and ready to serve.
	Health(ctx context.Context) error

	// Close releases any resources held by the provider.
	Close() error
}

// Capability enumerates optional features a provider may support.
type Capability string

const (
	// CapEncrypt means the provider supports the Encrypt operation.
	CapEncrypt Capability = "encrypt"
	// CapDecrypt means the provider supports the Decrypt operation.
	CapDecrypt Capability = "decrypt"
	// CapKeyRotation means the provider supports automatic key rotation.
	CapKeyRotation Capability = "key_rotation"
)

// ProviderWithCapabilities is an optional extension that providers can implement
// to declare which features they support.
type ProviderWithCapabilities interface {
	Provider
	Capabilities() []Capability
}
