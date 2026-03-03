// gen_coord_tokens generates a coordinator-format token file (base64-encoded
// ciphertext) by encrypting known plaintext with the local KMS provider.
//
// Usage:
//
//	go run ./tests/e2e/gen_coord_tokens > tests/e2e/coordinator-tokens.yaml
package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"os"

	"github.com/ledatu/csar/internal/kms"
)

func main() {
	// Same key ID and passphrase the e2e router will use.
	provider, err := kms.NewLocalProvider(map[string]string{
		"e2e-key-1": "e2e-test-passphrase",
	})
	if err != nil {
		log.Fatal(err)
	}

	tokens := map[string]string{
		"e2e_api_token":   "super-secret-bearer-token-12345",
		"e2e_extra_token": "another-secret-key-67890",
	}

	f := os.Stdout
	for ref, plaintext := range tokens {
		encrypted, err := provider.Encrypt(context.Background(), "e2e-key-1", []byte(plaintext))
		if err != nil {
			log.Fatalf("encrypting %q: %v", ref, err)
		}
		b64 := base64.StdEncoding.EncodeToString(encrypted)
		fmt.Fprintf(f, "%s:\n  encrypted_token: \"%s\"\n  kms_key_id: \"e2e-key-1\"\n", ref, b64)
	}
}
