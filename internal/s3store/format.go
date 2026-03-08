package s3store

import (
	"encoding/json"
	"fmt"
)

// TokenObject is the JSON structure stored in each S3 object.
//
// Two formats are supported:
//
// Passthrough (S3-only, SSE handles encryption at rest):
//
//	{"plaintext": "Bearer sk-xxxxx"}
//
// KMS (pre-encrypted with CSAR KMS):
//
//	{"enc_token": "base64-ciphertext", "kms_key_id": "abj-xxx"}
type TokenObject struct {
	// EncryptedToken is the base64-encoded ciphertext (KMS mode).
	EncryptedToken string `json:"enc_token,omitempty"`

	// KMSKeyID is the KMS key used for encryption (KMS mode).
	KMSKeyID string `json:"kms_key_id,omitempty"`

	// Plaintext is the raw token value (passthrough mode).
	Plaintext string `json:"plaintext,omitempty"`
}

// ParseTokenObject parses an S3 object body into a TokenObject.
// Returns an error if the JSON is invalid or if neither plaintext
// nor enc_token is present.
func ParseTokenObject(data []byte) (TokenObject, error) {
	var obj TokenObject
	if err := json.Unmarshal(data, &obj); err != nil {
		return TokenObject{}, fmt.Errorf("s3store: parse token object: %w", err)
	}

	if obj.Plaintext == "" && obj.EncryptedToken == "" {
		return TokenObject{}, fmt.Errorf("s3store: token object must have either \"plaintext\" or \"enc_token\" field")
	}

	if obj.EncryptedToken != "" && obj.KMSKeyID == "" {
		return TokenObject{}, fmt.Errorf("s3store: token object with \"enc_token\" requires \"kms_key_id\"")
	}

	return obj, nil
}
