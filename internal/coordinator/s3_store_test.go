package coordinator

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/Ledatu/csar-core/s3store"
)

// mockS3Client implements the subset of s3store.Client needed for testing.
// We test through the S3TokenStore wrapper which calls the real s3store.Client
// methods. For unit testing here, we use a simple in-memory mock.
type mockS3Client struct {
	objects map[string]s3store.ObjectEntry
}

func (m *mockS3Client) getObject(ref string) (s3store.ObjectEntry, error) {
	e, ok := m.objects[ref]
	if !ok {
		return s3store.ObjectEntry{}, ErrTokenNotFound
	}
	return e, nil
}

func TestS3TokenStore_UpsertToken_Passthrough(t *testing.T) {
	store := newMockMutableStore()

	entry := TokenEntry{
		EncryptedToken: []byte("raw-secret"),
	}
	meta := TokenMetadata{
		UpdatedBy: "test-user",
		Tenant:    "balance",
	}

	version, err := store.UpsertToken(context.Background(), "balance/token", entry, meta)
	if err != nil {
		t.Fatalf("UpsertToken: %v", err)
	}
	if version != "etag-new" {
		t.Errorf("version = %q, want %q", version, "etag-new")
	}

	fetched, err := store.FetchOne(context.Background(), "balance/token")
	if err != nil {
		t.Fatalf("FetchOne: %v", err)
	}
	if string(fetched.EncryptedToken) != "raw-secret" {
		t.Errorf("EncryptedToken = %q, want %q", fetched.EncryptedToken, "raw-secret")
	}
}

func TestS3TokenStore_DeleteToken(t *testing.T) {
	store := newMockMutableStore()
	store.entries["balance/token"] = TokenEntry{
		EncryptedToken: []byte("secret"),
		Version:        "v1",
	}

	err := store.DeleteToken(context.Background(), "balance/token")
	if err != nil {
		t.Fatalf("DeleteToken: %v", err)
	}

	_, err = store.FetchOne(context.Background(), "balance/token")
	if err == nil {
		t.Error("expected ErrTokenNotFound after delete")
	}
}

func TestMarshalParseTokenObject_KMS(t *testing.T) {
	ciphertext := []byte("encrypted-data")
	obj := s3store.TokenObject{
		EncryptedToken: base64.StdEncoding.EncodeToString(ciphertext),
		KMSKeyID:       "key-123",
		SchemaVersion:  1,
		UpdatedBy:      "test",
		Tenant:         "balance",
	}

	data, err := s3store.MarshalTokenObject(obj)
	if err != nil {
		t.Fatalf("MarshalTokenObject: %v", err)
	}

	parsed, err := s3store.ParseTokenObject(data)
	if err != nil {
		t.Fatalf("ParseTokenObject: %v", err)
	}

	if parsed.EncryptedToken != obj.EncryptedToken {
		t.Errorf("EncryptedToken = %q, want %q", parsed.EncryptedToken, obj.EncryptedToken)
	}
	if parsed.KMSKeyID != "key-123" {
		t.Errorf("KMSKeyID = %q, want %q", parsed.KMSKeyID, "key-123")
	}
	if parsed.SchemaVersion != 1 {
		t.Errorf("SchemaVersion = %d, want 1", parsed.SchemaVersion)
	}
}

func TestMarshalParseTokenObject_Passthrough(t *testing.T) {
	obj := s3store.TokenObject{
		Plaintext:     "Bearer sk-xxxxx",
		SchemaVersion: 1,
	}

	data, err := s3store.MarshalTokenObject(obj)
	if err != nil {
		t.Fatalf("MarshalTokenObject: %v", err)
	}

	parsed, err := s3store.ParseTokenObject(data)
	if err != nil {
		t.Fatalf("ParseTokenObject: %v", err)
	}

	if parsed.Plaintext != "Bearer sk-xxxxx" {
		t.Errorf("Plaintext = %q, want %q", parsed.Plaintext, "Bearer sk-xxxxx")
	}
}

func TestMarshalTokenObject_Metadata(t *testing.T) {
	obj := s3store.TokenObject{
		Plaintext:     "secret",
		UpdatedAt:     "2026-03-09T12:00:00Z",
		UpdatedBy:     "svc-deployer",
		Tenant:        "balance",
		SchemaVersion: 1,
	}

	data, err := s3store.MarshalTokenObject(obj)
	if err != nil {
		t.Fatalf("MarshalTokenObject: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if raw["updated_by"] != "svc-deployer" {
		t.Errorf("updated_by = %v, want svc-deployer", raw["updated_by"])
	}
	if raw["tenant"] != "balance" {
		t.Errorf("tenant = %v, want balance", raw["tenant"])
	}
	if raw["schema_version"] != float64(1) {
		t.Errorf("schema_version = %v, want 1", raw["schema_version"])
	}
}
