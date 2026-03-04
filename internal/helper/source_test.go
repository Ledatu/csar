package helper

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// ─── YAML Source Tests ──────────────────────────────────────────────────────────

func TestYAMLSource_SimpleMap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.yaml")
	content := `
api_token: "secret123"
db_token: "password456"
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	src := NewYAMLSource(YAMLSourceConfig{File: path})
	tokens, err := src.Load(context.Background())
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if len(tokens) != 2 {
		t.Fatalf("expected 2 tokens, got %d", len(tokens))
	}
	if tokens["api_token"].Plaintext != "secret123" {
		t.Errorf("api_token = %q, want %q", tokens["api_token"].Plaintext, "secret123")
	}
	if tokens["db_token"].Plaintext != "password456" {
		t.Errorf("db_token = %q, want %q", tokens["db_token"].Plaintext, "password456")
	}
}

func TestYAMLSource_JSONFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.json")
	content := `{"api_token": "secret123", "db_token": "password456"}`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	src := NewYAMLSource(YAMLSourceConfig{File: path})
	tokens, err := src.Load(context.Background())
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if len(tokens) != 2 {
		t.Fatalf("expected 2 tokens, got %d", len(tokens))
	}
	if tokens["api_token"].Plaintext != "secret123" {
		t.Errorf("api_token = %q, want %q", tokens["api_token"].Plaintext, "secret123")
	}
}

func TestYAMLSource_ArrayFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.yaml")
	// "cGFzc3dvcmQ0NTY=" is base64("password456") — encrypted tokens must be base64-encoded
	// to match the output contract of `csar-helper token encrypt`.
	content := `
- token_ref: "api_token"
  token: "secret123"
- token_ref: "db_token"
  token: "cGFzc3dvcmQ0NTY="
  kms_key_id: "key-1"
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	src := NewYAMLSource(YAMLSourceConfig{File: path})
	tokens, err := src.Load(context.Background())
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if len(tokens) != 2 {
		t.Fatalf("expected 2 tokens, got %d", len(tokens))
	}
	if tokens["api_token"].Plaintext != "secret123" {
		t.Errorf("api_token plaintext = %q, want %q", tokens["api_token"].Plaintext, "secret123")
	}
	// db_token has kms_key_id, so it's treated as encrypted (base64-decoded)
	if tokens["db_token"].KMSKeyID != "key-1" {
		t.Errorf("db_token kms_key_id = %q, want %q", tokens["db_token"].KMSKeyID, "key-1")
	}
	if string(tokens["db_token"].EncryptedToken) != "password456" {
		t.Errorf("db_token encrypted token = %q, want decoded %q", string(tokens["db_token"].EncryptedToken), "password456")
	}
}

func TestYAMLSource_FileNotFound(t *testing.T) {
	src := NewYAMLSource(YAMLSourceConfig{File: "/nonexistent/file.yaml"})
	_, err := src.Load(context.Background())
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

// ─── Env Source Tests ───────────────────────────────────────────────────────────

func TestEnvSource_Load(t *testing.T) {
	t.Setenv("CSARTEST_api_key", "secret123")
	t.Setenv("CSARTEST_db_pass", "password456")
	t.Setenv("OTHER_VAR", "should_be_ignored")

	src := NewEnvSource(EnvSourceConfig{Prefix: "CSARTEST_"})
	tokens, err := src.Load(context.Background())
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if len(tokens) != 2 {
		t.Fatalf("expected 2 tokens, got %d", len(tokens))
	}
	if tokens["api_key"].Plaintext != "secret123" {
		t.Errorf("api_key = %q, want %q", tokens["api_key"].Plaintext, "secret123")
	}
	if tokens["db_pass"].Plaintext != "password456" {
		t.Errorf("db_pass = %q, want %q", tokens["db_pass"].Plaintext, "password456")
	}
}

func TestEnvSource_NoPrefix(t *testing.T) {
	src := NewEnvSource(EnvSourceConfig{Prefix: ""})
	_, err := src.Load(context.Background())
	if err == nil {
		t.Error("expected error when prefix is empty")
	}
}

func TestEnvSource_NoMatches(t *testing.T) {
	src := NewEnvSource(EnvSourceConfig{Prefix: "NONEXISTENT_PREFIX_XYZ_"})
	_, err := src.Load(context.Background())
	if err == nil {
		t.Error("expected error when no env vars match prefix")
	}
}

// ─── Profile Validation Tests ───────────────────────────────────────────────────

func TestValidateProfile_DevLocal_NoRestrictions(t *testing.T) {
	input := ProfileCheckInput{
		Profile:             "dev-local",
		CoordinatorInsecure: true,
		SecurityEnvironment: "dev",
		HasSecureRoutes:     true,
		TLSEnabled:          false,
		KMSProvider:         "local",
	}
	violations := ValidateProfile(input)
	if len(violations) != 0 {
		t.Errorf("dev-local should have no violations, got %d: %v", len(violations), violations)
	}
}

func TestValidateProfile_ProdSingle_RejectsInsecure(t *testing.T) {
	input := ProfileCheckInput{
		Profile:             "prod-single",
		CoordinatorInsecure: true,
	}
	violations := ValidateProfile(input)
	found := false
	for _, v := range violations {
		if v.Error() != "" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected at least one violation for insecure coordinator in prod-single")
	}
}

func TestValidateProfile_ProdSingle_RejectsDevEnvironment(t *testing.T) {
	input := ProfileCheckInput{
		Profile:             "prod-single",
		SecurityEnvironment: "dev",
	}
	violations := ValidateProfile(input)
	if len(violations) == 0 {
		t.Error("expected violations for dev environment in prod-single")
	}
}

func TestValidateProfile_ProdSingle_RequiresTLS(t *testing.T) {
	input := ProfileCheckInput{
		Profile:         "prod-single",
		HasSecureRoutes: true,
		TLSEnabled:      false,
	}
	violations := ValidateProfile(input)
	if len(violations) == 0 {
		t.Error("expected violations for missing TLS with secure routes in prod-single")
	}
}

func TestValidateProfile_ProdSingle_RejectsLocalKMS(t *testing.T) {
	input := ProfileCheckInput{
		Profile:         "prod-single",
		HasSecureRoutes: true,
		TLSEnabled:      true,
		KMSProvider:     "local",
	}
	violations := ValidateProfile(input)
	foundKMS := false
	for _, v := range violations {
		if v != nil {
			foundKMS = true
		}
	}
	if !foundKMS {
		t.Error("expected violation for local KMS in prod-single")
	}
}

func TestValidateProfile_ProdDistributed_RequiresCoordinator(t *testing.T) {
	input := ProfileCheckInput{
		Profile:            "prod-distributed",
		CoordinatorEnabled: false,
		TLSEnabled:         true,
	}
	violations := ValidateProfile(input)
	if len(violations) == 0 {
		t.Error("expected violations for disabled coordinator in prod-distributed")
	}
}

func TestValidateProfile_ProdDistributed_RequiresCoordinatorTLS(t *testing.T) {
	input := ProfileCheckInput{
		Profile:            "prod-distributed",
		CoordinatorEnabled: true,
		CoordinatorAddress: "coord:9090",
		CoordinatorCAFile:  "",
		TLSEnabled:         true,
	}
	violations := ValidateProfile(input)
	foundCAViolation := false
	for _, v := range violations {
		if v != nil {
			foundCAViolation = true
		}
	}
	if !foundCAViolation {
		t.Error("expected violation for missing coordinator CA in prod-distributed")
	}
}

func TestValidateProfile_ProdDistributed_PassesAll(t *testing.T) {
	input := ProfileCheckInput{
		Profile:            "prod-distributed",
		CoordinatorEnabled: true,
		CoordinatorAddress: "coord:9090",
		CoordinatorCAFile:  "/path/to/ca.pem",
		HasSecureRoutes:    true,
		TLSEnabled:         true,
		KMSProvider:        "yandexapi",
	}
	violations := ValidateProfile(input)
	if len(violations) != 0 {
		t.Errorf("expected no violations, got %d: %v", len(violations), violations)
	}
}

func TestIsValidProfile(t *testing.T) {
	if !IsValidProfile("dev-local") {
		t.Error("dev-local should be valid")
	}
	if !IsValidProfile("prod-single") {
		t.Error("prod-single should be valid")
	}
	if !IsValidProfile("prod-distributed") {
		t.Error("prod-distributed should be valid")
	}
	if IsValidProfile("unknown") {
		t.Error("unknown should be invalid")
	}
	if IsValidProfile("") {
		t.Error("empty string should be invalid")
	}
}
