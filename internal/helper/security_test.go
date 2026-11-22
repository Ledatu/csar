package helper

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ledatu/csar/internal/config"
)

func TestInvalidDSNDiagnosticDoesNotExposePassword(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte("CSAR_TOKEN_STORE_DSN=postgres://user:private%zz@localhost/db\n"), 0600); err != nil {
		t.Fatal(err)
	}
	result := &StackCheckResult{}
	checkDBDSN(result, path)
	if !result.HasError {
		t.Fatal("malformed DSN was accepted")
	}
	for _, check := range result.Checks {
		if strings.Contains(check.Message, "private") || strings.Contains(check.Message, "postgres://user") {
			t.Fatal("DSN credential appeared in the diagnostic")
		}
	}
}

func TestProfileScaffoldRestrictsFilesAndRequiresPassword(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "profile")
	if err := InitProfile(ProfileProdDistributed, dir, false); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"config.yaml", ".env.example", "docker-compose.yaml"} {
		if err := os.Chmod(filepath.Join(dir, name), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := InitProfile(ProfileProdDistributed, dir, true); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"config.yaml", ".env.example", "docker-compose.yaml"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("scaffold %s is not private: %v", name, err)
		}
	}
	data, err := os.ReadFile(filepath.Join(dir, "docker-compose.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "csar_dev") || !strings.Contains(string(data), "${POSTGRES_PASSWORD:?") {
		t.Fatal("production scaffold uses a known database password")
	}
}

func TestEveryProfileScaffoldsAValidConfiguration(t *testing.T) {
	for _, profile := range ValidProfiles() {
		t.Run(string(profile), func(t *testing.T) {
			dir := t.TempDir()
			if err := InitProfile(profile, dir, false); err != nil {
				t.Fatal(err)
			}
			cfg, err := config.Load(filepath.Join(dir, "config.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Profile != string(profile) {
				t.Fatal("scaffold selected the wrong deployment profile")
			}
		})
	}
}

func TestScaffoldConflictDoesNotWriteOtherFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("existing config"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := InitProfile(ProfileProdDistributed, dir, false); err == nil {
		t.Fatal("scaffold overwrote an existing config without force")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatal("scaffold created partial output before reporting a conflict")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "existing config" {
		t.Fatal("scaffold changed the existing config")
	}
}
