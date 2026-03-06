package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoad_BasicInclude(t *testing.T) {
	dir := t.TempDir()

	// Child file with routes.
	child := `
paths:
  /api/v1/users:
    get:
      x-csar-backend:
        target_url: "https://users.example.com"
`
	writeFile(t, filepath.Join(dir, "users.yaml"), child)

	// Root file includes the child.
	root := `
listen_addr: ":8080"
include:
  - "users.yaml"
paths:
  /api/v1/products:
    get:
      x-csar-backend:
        target_url: "https://products.example.com"
`
	rootPath := filepath.Join(dir, "config.yaml")
	writeFile(t, rootPath, root)

	cfg, err := Load(rootPath)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if len(cfg.Paths) != 2 {
		t.Errorf("expected 2 paths, got %d", len(cfg.Paths))
	}
	if _, ok := cfg.Paths["/api/v1/users"]; !ok {
		t.Error("missing /api/v1/users from included file")
	}
	if _, ok := cfg.Paths["/api/v1/products"]; !ok {
		t.Error("missing /api/v1/products from root file")
	}
}

func TestLoad_GlobInclude(t *testing.T) {
	dir := t.TempDir()
	routesDir := filepath.Join(dir, "routes")
	os.MkdirAll(routesDir, 0755)

	writeFile(t, filepath.Join(routesDir, "a.yaml"), `
paths:
  /a:
    get:
      x-csar-backend:
        target_url: "https://a.example.com"
`)
	writeFile(t, filepath.Join(routesDir, "b.yaml"), `
paths:
  /b:
    get:
      x-csar-backend:
        target_url: "https://b.example.com"
`)

	rootPath := filepath.Join(dir, "config.yaml")
	writeFile(t, rootPath, `
listen_addr: ":8080"
include:
  - "routes/*.yaml"
paths:
  /c:
    get:
      x-csar-backend:
        target_url: "https://c.example.com"
`)

	cfg, err := Load(rootPath)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if len(cfg.Paths) != 3 {
		t.Errorf("expected 3 paths, got %d", len(cfg.Paths))
	}
}

func TestLoad_CycleDetection(t *testing.T) {
	dir := t.TempDir()

	writeFile(t, filepath.Join(dir, "a.yaml"), `
listen_addr: ":8080"
include:
  - "b.yaml"
paths:
  /a:
    get:
      x-csar-backend:
        target_url: "https://a.example.com"
`)
	writeFile(t, filepath.Join(dir, "b.yaml"), `
include:
  - "a.yaml"
paths:
  /b:
    get:
      x-csar-backend:
        target_url: "https://b.example.com"
`)

	_, err := Load(filepath.Join(dir, "a.yaml"))
	if err == nil {
		t.Fatal("expected cycle detection error")
	}
	if !strings.Contains(err.Error(), "cycle") {
		t.Errorf("error should mention 'cycle', got: %v", err)
	}
}

func TestLoad_DuplicateRouteAcrossFiles(t *testing.T) {
	dir := t.TempDir()

	writeFile(t, filepath.Join(dir, "child.yaml"), `
paths:
  /api/v1/products:
    get:
      x-csar-backend:
        target_url: "https://other.example.com"
`)

	rootPath := filepath.Join(dir, "config.yaml")
	writeFile(t, rootPath, `
listen_addr: ":8080"
include:
  - "child.yaml"
paths:
  /api/v1/products:
    get:
      x-csar-backend:
        target_url: "https://products.example.com"
`)

	_, err := Load(rootPath)
	if err == nil {
		t.Fatal("expected duplicate route error")
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("error should mention 'duplicate', got: %v", err)
	}
}

func TestLoad_SingletonFieldInInclude_Warning(t *testing.T) {
	dir := t.TempDir()

	writeFile(t, filepath.Join(dir, "child.yaml"), `
listen_addr: ":9090"
paths:
  /a:
    get:
      x-csar-backend:
        target_url: "https://a.example.com"
`)

	rootPath := filepath.Join(dir, "config.yaml")
	writeFile(t, rootPath, `
listen_addr: ":8080"
include:
  - "child.yaml"
paths:
  /b:
    get:
      x-csar-backend:
        target_url: "https://b.example.com"
`)

	cfg, err := Load(rootPath)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	// listen_addr should still be the root's value.
	if cfg.ListenAddr != ":8080" {
		t.Errorf("ListenAddr = %q, want :8080 (root value)", cfg.ListenAddr)
	}

	// Should have a warning about the singleton field.
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "listen_addr") && strings.Contains(w, "root-only") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected warning about listen_addr in included file, got warnings: %v", cfg.Warnings)
	}
}

func TestLoad_EmptyGlob_Warning(t *testing.T) {
	dir := t.TempDir()

	rootPath := filepath.Join(dir, "config.yaml")
	writeFile(t, rootPath, `
listen_addr: ":8080"
include:
  - "nonexistent/*.yaml"
paths:
  /a:
    get:
      x-csar-backend:
        target_url: "https://a.example.com"
`)

	cfg, err := Load(rootPath)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "nonexistent") && strings.Contains(w, "matched no files") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected warning about empty glob, got warnings: %v", cfg.Warnings)
	}
}

func TestLoad_NestedIncludes(t *testing.T) {
	dir := t.TempDir()

	writeFile(t, filepath.Join(dir, "c.yaml"), `
paths:
  /c:
    get:
      x-csar-backend:
        target_url: "https://c.example.com"
`)
	writeFile(t, filepath.Join(dir, "b.yaml"), `
include:
  - "c.yaml"
paths:
  /b:
    get:
      x-csar-backend:
        target_url: "https://b.example.com"
`)

	rootPath := filepath.Join(dir, "config.yaml")
	writeFile(t, rootPath, `
listen_addr: ":8080"
include:
  - "b.yaml"
paths:
  /a:
    get:
      x-csar-backend:
        target_url: "https://a.example.com"
`)

	cfg, err := Load(rootPath)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if len(cfg.Paths) != 3 {
		t.Errorf("expected 3 paths from nested includes, got %d", len(cfg.Paths))
	}
}

func TestLoad_IncludeMergesPolicies(t *testing.T) {
	dir := t.TempDir()

	writeFile(t, filepath.Join(dir, "policies.yaml"), `
security_profiles:
  standard:
    kms_key_id: "key-1"
    token_ref: "main_token"
    inject_header: "Authorization"
    inject_format: "Bearer {token}"

throttling_policies:
  standard-api:
    rate: 10
    burst: 20
    max_wait: "500ms"
`)

	rootPath := filepath.Join(dir, "config.yaml")
	writeFile(t, rootPath, `
listen_addr: ":8080"
include:
  - "policies.yaml"
paths:
  /api/v1/products:
    get:
      x-csar-backend:
        target_url: "https://api.example.com/products"
      x-csar-security: "standard"
      x-csar-traffic: "standard-api"
`)

	cfg, err := Load(rootPath)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	route := cfg.Paths["/api/v1/products"]["get"]
	if len(route.Security) == 0 {
		t.Fatal("security should not be empty after profile resolution")
	}
	if route.Security[0].KMSKeyID != "key-1" {
		t.Errorf("KMSKeyID = %q, want key-1 (from included profile)", route.Security[0].KMSKeyID)
	}
	if route.Traffic == nil || route.Traffic.RPS != 10 {
		t.Error("traffic RPS should be 10 from included throttling policy")
	}
}

func TestLoad_DuplicatePolicyKey_Error(t *testing.T) {
	dir := t.TempDir()

	writeFile(t, filepath.Join(dir, "child.yaml"), `
throttling_policies:
  standard-api:
    rate: 5
    burst: 10
    max_wait: "1s"
`)

	rootPath := filepath.Join(dir, "config.yaml")
	writeFile(t, rootPath, `
listen_addr: ":8080"
include:
  - "child.yaml"
throttling_policies:
  standard-api:
    rate: 10
    burst: 20
    max_wait: "500ms"
paths:
  /a:
    get:
      x-csar-backend:
        target_url: "https://a.example.com"
`)

	_, err := Load(rootPath)
	if err == nil {
		t.Fatal("expected duplicate policy key error")
	}
	if !strings.Contains(err.Error(), "duplicate") && !strings.Contains(err.Error(), "standard-api") {
		t.Errorf("error should mention duplicate key, got: %v", err)
	}
}

// --- helpers ---

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}
