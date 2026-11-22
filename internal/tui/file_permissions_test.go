package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSensitiveFileOverwritesRestrictPermissions(t *testing.T) {
	for _, name := range []string{"config", "private PEM"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "sensitive")
			if err := os.WriteFile(path, []byte("old content"), 0644); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0644); err != nil {
				t.Fatal(err)
			}
			var err error
			if name == "config" {
				err = writeConfigFile(path, []byte("new secret"), false)
			} else {
				err = writePEM(path, "PRIVATE KEY", []byte("new secret"))
			}
			if err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatalf("sensitive file permissions not restricted: %v", err)
			}
		})
	}
}

func TestGeneratedFilesArePrivateAndRequirePostgresPassword(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "generated")
	r := &GenerateResult{OutputDir: dir, IncludePostgres: true, GenerateCompose: true}
	if err := ApplyGenerateResult(r); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"config.yaml", ".env.example", "docker-compose.yaml"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("generated %s is not private: %v", name, err)
		}
	}
	data, err := os.ReadFile(filepath.Join(dir, "docker-compose.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "csar_dev") || !strings.Contains(string(data), "${POSTGRES_PASSWORD:?") {
		t.Fatal("generated database silently uses a known default password")
	}
}

func TestExclusiveConfigCreationPreservesExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeConfigFile(path, []byte("replacement"), true); !os.IsExist(err) {
		t.Fatalf("exclusive create should reject an existing file: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "existing" {
		t.Fatal("exclusive creation overwrote the existing file")
	}
}

func TestGeneratorRejectsDanglingSymlinkWithoutPartialOutput(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "not-created.yaml")
	if err := os.Symlink(target, filepath.Join(dir, "config.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := ApplyGenerateResult(&GenerateResult{OutputDir: dir, GenerateCompose: true}); err == nil {
		t.Fatal("generator followed an existing dangling symlink without force")
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatal("generator wrote through the symlink")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatal("generator created partial output before reporting a symlink conflict")
	}
}
