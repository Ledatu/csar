package kms

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/scrypt"
)

const (
	localKeyLength = 32
	scryptN        = 32768
	scryptR        = 8
	scryptP        = 1
)

// LocalProvider implements Provider using AES-256-GCM with a local master key.
// Intended for development and testing only — NOT for production use.
// In production, use YandexProvider or another cloud KMS.
type LocalProvider struct {
	// keys maps keyID -> derived AES-256 key
	keys map[string][]byte
}

// NewLocalProvider creates a LocalProvider. Each keyID maps to a passphrase
// that is derived with scrypt to produce a 256-bit AES key.
func NewLocalProvider(keyPassphrases map[string]string) (*LocalProvider, error) {
	if len(keyPassphrases) == 0 {
		return nil, fmt.Errorf("at least one key passphrase is required")
	}

	keys := make(map[string][]byte, len(keyPassphrases))
	for id, passphrase := range keyPassphrases {
		if id == "" {
			return nil, fmt.Errorf("key ID must not be empty")
		}
		if passphrase == "" {
			return nil, fmt.Errorf("passphrase for key %q must not be empty", id)
		}

		key, err := deriveLocalKey(id, passphrase)
		if err != nil {
			return nil, fmt.Errorf("deriving key %q: %w", id, err)
		}
		keys[id] = key
	}

	return &LocalProvider{keys: keys}, nil
}

func deriveLocalKey(keyID, passphrase string) ([]byte, error) {
	salt := []byte("github.com/ledatu/csar/internal/kms/local:" + keyID)
	return scrypt.Key([]byte(passphrase), salt, scryptN, scryptR, scryptP, localKeyLength)
}

// Name returns the provider identifier.
func (p *LocalProvider) Name() string { return "local" }

// Health always returns nil — local provider has no external dependencies.
func (p *LocalProvider) Health(_ context.Context) error { return nil }

// Encrypt encrypts plaintext using AES-256-GCM with the key identified by keyID.
func (p *LocalProvider) Encrypt(_ context.Context, keyID string, plaintext []byte) ([]byte, error) {
	key, ok := p.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("key %q not found", keyID)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}

	// Ciphertext format: nonce || encrypted_data_with_tag
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts ciphertext using AES-256-GCM with the key identified by keyID.
func (p *LocalProvider) Decrypt(_ context.Context, keyID string, ciphertext []byte) ([]byte, error) {
	key, ok := p.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("key %q not found", keyID)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, encData := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, encData, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// Close is a no-op for LocalProvider.
func (p *LocalProvider) Close() error {
	return nil
}
