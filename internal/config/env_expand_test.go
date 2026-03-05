package config

import (
	"reflect"
	"testing"

	"github.com/ledatu/csar/internal/logging"
)

// ==========================================================================
// safeExpandEnv tests (audit §1 — os.ExpandEnv bug)
// ==========================================================================

func TestSafeExpandEnv_PreservesBackReferences(t *testing.T) {
	// $1, $2 are regex back-references in path_rewrite — they must survive.
	input := `path_rewrite: "/users/$1/orders/$2"`
	result := safeExpandEnv(input)
	if result != input {
		t.Errorf("safeExpandEnv mangled back-references:\n  got:  %s\n  want: %s", result, input)
	}
}

func TestSafeExpandEnv_ExpandsRealEnvVars(t *testing.T) {
	t.Setenv("CSAR_TEST_DSN", "postgres://u:p@h:5432/db")
	input := `dsn: "${CSAR_TEST_DSN}"`
	want := `dsn: "postgres://u:p@h:5432/db"`
	result := safeExpandEnv(input)
	if result != want {
		t.Errorf("safeExpandEnv didn't expand env var:\n  got:  %s\n  want: %s", result, want)
	}
}

func TestSafeExpandEnv_MixedBackRefsAndEnvVars(t *testing.T) {
	t.Setenv("CSAR_TEST_HOST", "api.example.com")
	input := `target_url: "https://${CSAR_TEST_HOST}/users/$1"`
	want := `target_url: "https://api.example.com/users/$1"`
	result := safeExpandEnv(input)
	if result != want {
		t.Errorf("safeExpandEnv:\n  got:  %s\n  want: %s", result, want)
	}
}

func TestSafeExpandEnv_UndefinedEnvVar(t *testing.T) {
	// Undefined env vars expand to empty string (same as os.ExpandEnv).
	input := `value: "${CSAR_UNDEFINED_VAR_12345}"`
	want := `value: ""`
	result := safeExpandEnv(input)
	if result != want {
		t.Errorf("safeExpandEnv:\n  got:  %s\n  want: %s", result, want)
	}
}

func TestSafeExpandEnv_BracedDigitPreserved(t *testing.T) {
	// ${1} is parsed by os.Expand as variable "1" — our mapping returns "$1",
	// so the back-reference value is preserved even though braces are consumed.
	input := `path_rewrite: "/items/${1}/detail"`
	want := `path_rewrite: "/items/$1/detail"`
	result := safeExpandEnv(input)
	if result != want {
		t.Errorf("safeExpandEnv:\n  got:  %s\n  want: %s", result, want)
	}
}

func TestLoad_EnvVarExpansion_PostUnmarshal(t *testing.T) {
	t.Setenv("CSAR_TEST_TARGET_URL", "https://api.example.com/v2")
	t.Setenv("CSAR_TEST_LISTEN", ":9090")
	yamlStr := `
listen_addr: "${CSAR_TEST_LISTEN}"
paths:
  /api:
    get:
      x-csar-backend:
        target_url: "${CSAR_TEST_TARGET_URL}"
      x-csar-headers:
        X-Custom: "prefix-${CSAR_TEST_LISTEN}-suffix"
`
	path := writeTemp(t, yamlStr)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.ListenAddr != ":9090" {
		t.Errorf("ListenAddr = %q, want env-expanded %q", cfg.ListenAddr, ":9090")
	}

	route := cfg.Paths["/api"]["get"]
	if route.Backend.TargetURL != "https://api.example.com/v2" {
		t.Errorf("TargetURL = %q, want env-expanded value", route.Backend.TargetURL)
	}
	wantHeader := "prefix-:9090-suffix"
	if route.Headers["X-Custom"] != wantHeader {
		t.Errorf("Header X-Custom = %q, want %q", route.Headers["X-Custom"], wantHeader)
	}
}

func TestLoad_YAMLInjection_Safe(t *testing.T) {
	// Set an env var containing YAML control characters.
	// With pre-unmarshal expansion, this would corrupt the YAML structure.
	// With post-unmarshal expansion, it is safely contained in the string field.
	t.Setenv("CSAR_TEST_EVIL", "value\"\nmalicious_field: true")
	yamlStr := `
listen_addr: ":8080"
paths:
  /api:
    get:
      x-csar-backend:
        target_url: "https://api.example.com"
      x-csar-headers:
        X-Custom: "${CSAR_TEST_EVIL}"
`
	path := writeTemp(t, yamlStr)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	route := cfg.Paths["/api"]["get"]
	got := route.Headers["X-Custom"]
	want := "value\"\nmalicious_field: true"
	if got != want {
		t.Errorf("Header value = %q, want %q (env var should be safely injected post-unmarshal)", got, want)
	}

	// Verify the malicious field did NOT create a new config key.
	if cfg.ListenAddr != ":8080" {
		t.Errorf("ListenAddr = %q, want %q (should not be altered by injection)", cfg.ListenAddr, ":8080")
	}
}

func TestExpandEnvInStruct_StringFields(t *testing.T) {
	t.Setenv("CSAR_TEST_ADDR", "localhost:9090")
	t.Setenv("CSAR_TEST_URL", "https://backend.local")

	cfg := &Config{
		ListenAddr: "${CSAR_TEST_ADDR}",
		Paths: map[string]PathConfig{
			"/test": {
				"get": RouteConfig{
					Backend: BackendConfig{
						TargetURL:   "${CSAR_TEST_URL}",
						PathRewrite: "/users/$1", // back-reference must survive
					},
				},
			},
		},
	}

	expandEnvInStruct(reflect.ValueOf(cfg).Elem())

	if cfg.ListenAddr != "localhost:9090" {
		t.Errorf("ListenAddr = %q, want %q", cfg.ListenAddr, "localhost:9090")
	}

	route := cfg.Paths["/test"]["get"]
	if route.Backend.TargetURL != "https://backend.local" {
		t.Errorf("TargetURL = %q, want %q", route.Backend.TargetURL, "https://backend.local")
	}
	if route.Backend.PathRewrite != "/users/$1" {
		t.Errorf("PathRewrite = %q, want %q (back-reference mangled)", route.Backend.PathRewrite, "/users/$1")
	}
}

func TestExpandEnvInStruct_SecretFields(t *testing.T) {
	t.Setenv("CSAR_TEST_SECRET", "s3cret-password")

	cfg := &Config{
		Redis: &RedisConfig{
			Address:  "localhost:6379",
			Password: logging.NewSecret("${CSAR_TEST_SECRET}"),
		},
	}

	expandEnvInStruct(reflect.ValueOf(cfg).Elem())

	if cfg.Redis.Password.Plaintext() != "s3cret-password" {
		t.Errorf("Redis.Password = %q, want env-expanded value", cfg.Redis.Password.Plaintext())
	}
}

func TestExpandEnvInStruct_SliceFields(t *testing.T) {
	t.Setenv("CSAR_TEST_HOST1", "host1.example.com")
	t.Setenv("CSAR_TEST_HOST2", "host2.example.com")

	cfg := &Config{
		Paths: map[string]PathConfig{
			"/test": {
				"get": RouteConfig{
					Backend: BackendConfig{
						TargetURL: "https://primary.example.com",
						Targets:   []string{"https://${CSAR_TEST_HOST1}", "https://${CSAR_TEST_HOST2}"},
					},
				},
			},
		},
	}

	expandEnvInStruct(reflect.ValueOf(cfg).Elem())

	route := cfg.Paths["/test"]["get"]
	if route.Backend.Targets[0] != "https://host1.example.com" {
		t.Errorf("Targets[0] = %q, want expanded", route.Backend.Targets[0])
	}
	if route.Backend.Targets[1] != "https://host2.example.com" {
		t.Errorf("Targets[1] = %q, want expanded", route.Backend.Targets[1])
	}
}

func TestLoad_PathRewrite_BackReferencesPreserved(t *testing.T) {
	yamlStr := `
listen_addr: ":8080"
paths:
  /api/v1/users/{id:[0-9]+}:
    get:
      x-csar-backend:
        target_url: "https://users.internal"
        path_rewrite: "/users/$1"
`
	path := writeTemp(t, yamlStr)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	for _, methods := range cfg.Paths {
		for _, route := range methods {
			if route.Backend.PathRewrite != "/users/$1" {
				t.Errorf("path_rewrite = %q, want %q (back-reference mangled by env expansion)",
					route.Backend.PathRewrite, "/users/$1")
			}
			return
		}
	}
	t.Fatal("no route found in config")
}
