package middleware

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ledatu/csar/internal/kms"
)

func TestLoadTokenFile_OK(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.yaml")
	content := `
api_main:
  plaintext: "super-secret-api-token"
  kms_key_id: "key1"
orders_main:
  plaintext: "orders-api-key-xyz"
  kms_key_id: "key1"
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	provider, _ := kms.NewLocalProvider(map[string]string{"key1": "test-pass"})
	fetcher, err := LoadTokenFile(path, provider)
	if err != nil {
		t.Fatalf("LoadTokenFile: %v", err)
	}

	// Verify we can fetch and decrypt "api_main"
	enc, keyID, _, err := fetcher.GetEncryptedToken(context.Background(), "api_main")
	if err != nil {
		t.Fatalf("GetEncryptedToken(api_main): %v", err)
	}
	if keyID != "key1" {
		t.Errorf("kms_key_id = %q, want %q", keyID, "key1")
	}
	plain, err := provider.Decrypt(context.Background(), keyID, enc)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(plain) != "super-secret-api-token" {
		t.Errorf("decrypted = %q, want %q", plain, "super-secret-api-token")
	}

	// Verify "orders_main" too
	enc2, _, _, err := fetcher.GetEncryptedToken(context.Background(), "orders_main")
	if err != nil {
		t.Fatalf("GetEncryptedToken(orders_main): %v", err)
	}
	plain2, _ := provider.Decrypt(context.Background(), "key1", enc2)
	if string(plain2) != "orders-api-key-xyz" {
		t.Errorf("orders_main decrypted = %q, want %q", plain2, "orders-api-key-xyz")
	}
}

func TestLoadTokenFile_EmptyPlaintext(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.yaml")
	content := `
bad_token:
  plaintext: ""
  kms_key_id: "key1"
`
	os.WriteFile(path, []byte(content), 0o600)

	provider, _ := kms.NewLocalProvider(map[string]string{"key1": "pass"})
	_, err := LoadTokenFile(path, provider)
	if err == nil {
		t.Fatal("expected error for empty plaintext")
	}
}

func TestLoadTokenFile_EmptyKMSKeyID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.yaml")
	content := `
bad_token:
  plaintext: "something"
  kms_key_id: ""
`
	os.WriteFile(path, []byte(content), 0o600)

	provider, _ := kms.NewLocalProvider(map[string]string{"key1": "pass"})
	_, err := LoadTokenFile(path, provider)
	if err == nil {
		t.Fatal("expected error for empty kms_key_id")
	}
}

func TestLoadTokenFile_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.yaml")
	os.WriteFile(path, []byte("{}"), 0o600)

	provider, _ := kms.NewLocalProvider(map[string]string{"key1": "pass"})
	_, err := LoadTokenFile(path, provider)
	if err == nil {
		t.Fatal("expected error for empty token file")
	}
}

func TestLoadTokenFile_NotFound(t *testing.T) {
	provider, _ := kms.NewLocalProvider(map[string]string{"key1": "pass"})
	_, err := LoadTokenFile("/nonexistent/tokens.yaml", provider)
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadTokenFile_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.yaml")
	os.WriteFile(path, []byte("not: [valid: yaml: {{{"), 0o600)

	provider, _ := kms.NewLocalProvider(map[string]string{"key1": "pass"})
	_, err := LoadTokenFile(path, provider)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestLoadTokenFile_WrongKMSKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.yaml")
	content := `
token_a:
  plaintext: "my-secret"
  kms_key_id: "nonexistent-key"
`
	os.WriteFile(path, []byte(content), 0o600)

	// Provider has key1 but token asks for nonexistent-key
	provider, _ := kms.NewLocalProvider(map[string]string{"key1": "pass"})
	_, err := LoadTokenFile(path, provider)
	if err == nil {
		t.Fatal("expected error when KMS key doesn't exist")
	}
}
