package crypto

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateKeyPairTightensExistingPrivateKeyPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.key")
	if err := os.WriteFile(path, []byte("old key"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	result, err := GenerateKeyPair(GenerateOptions{OutputDir: dir, KeyName: "test"})
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(result.PrivateKeyPath)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("private key permissions not restricted: %v", err)
	}
	data, err := os.ReadFile(result.PrivateKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("generated private key is not PEM")
	}
	if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		t.Fatalf("generated private key is invalid: %v", err)
	}
}
