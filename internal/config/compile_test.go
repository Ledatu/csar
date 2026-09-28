package config

import (
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func writeCompileFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "seller.yaml"), `
throttling_policies:
  per-seller:
    rate: 0.5
    burst: 1
    max_wait: "65s"
    backend: "redis"
    key: "seller:{path.id}"
paths:
  /seller/{id}/report:
    get:
      x-csar-backend:
        target_url: "${SELLER_BACKEND_URL:-https://seller.example.com}/report"
      x-csar-traffic: "per-seller"
`)
	root := filepath.Join(dir, "config.yaml")
	writeFile(t, root, `
listen_addr: ":8080"
include:
  - "seller.yaml"
redis:
  address: "${REDIS_ADDR:-redis:6379}"
  password: "${REDIS_PASSWORD}"
  key_prefix: "csar:router:"
paths:
  /health:
    get:
      x-csar-backend:
        target_url: "https://health.example.com"
`)
	return root
}

func TestCompile_KeepsEnvReferencesOfTheCompilingProcessOut(t *testing.T) {
	t.Setenv("REDIS_ADDR", "ci-redis:6379")
	t.Setenv("REDIS_PASSWORD", "ci-secret")
	t.Setenv("SELLER_BACKEND_URL", "https://ci.example.com")

	data, err := Compile(writeCompileFixture(t))
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	out := string(data)

	for _, want := range []string{"${REDIS_ADDR:-redis:6379}", "${REDIS_PASSWORD}", "${SELLER_BACKEND_URL:-https://seller.example.com}/report", "/seller/{id}/report"} {
		if !strings.Contains(out, want) {
			t.Errorf("compiled config lacks %q:\n%s", want, out)
		}
	}
	for _, leaked := range []string{"ci-redis", "ci-secret", "ci.example.com", "include:"} {
		if strings.Contains(out, leaked) {
			t.Errorf("compiled config contains %q:\n%s", leaked, out)
		}
	}
}

func TestCompile_LoadsLikeTheSourceInTheLoadingEnvironment(t *testing.T) {
	path := writeCompileFixture(t)
	data, err := Compile(path)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	t.Setenv("REDIS_ADDR", "10.0.0.5:6379")
	t.Setenv("REDIS_PASSWORD", "runtime-secret")
	t.Setenv("SELLER_BACKEND_URL", "https://runtime.example.com")

	fromSource, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	compiled, err := ParseBytes(data)
	if err != nil {
		t.Fatalf("ParseBytes(compiled): %v\n%s", err, data)
	}

	if got := compiled.Redis.Address; got != "10.0.0.5:6379" {
		t.Errorf("redis address = %q, want runtime value", got)
	}
	if got := compiled.Redis.Password.Plaintext(); got != "runtime-secret" {
		t.Errorf("redis password = %q, want runtime value", got)
	}
	if got := compiled.Paths["/seller/{id}/report"]["get"].Backend.TargetURL; got != "https://runtime.example.com/report" {
		t.Errorf("target_url = %q, want runtime value", got)
	}

	want, err := yaml.Marshal(fromSource)
	if err != nil {
		t.Fatal(err)
	}
	got, err := yaml.Marshal(compiled)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Errorf("compiled config loads differently from source\nsource:\n%s\ncompiled:\n%s", want, got)
	}
}

func TestCompile_RejectsInvalidSource(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	writeFile(t, path, `
listen_addr: ":8080"
paths:
  /x:
    get:
      x-csar-traffic: "missing-policy"
      x-csar-backend:
        target_url: "https://x.example.com"
`)
	if _, err := Compile(path); err == nil {
		t.Fatal("Compile accepted a route that references an undefined policy")
	}
}

func TestSetScalar_CreatesMissingParents(t *testing.T) {
	var root yaml.Node
	if err := root.Encode(map[string]any{"listen_addr": ":8080"}); err != nil {
		t.Fatal(err)
	}
	if err := setScalar(&root, []string{"kms", "yandex", "oauth_token"}, "${YANDEX_OAUTH}"); err != nil {
		t.Fatalf("setScalar: %v", err)
	}
	var back struct {
		KMS struct {
			Yandex struct {
				OAuthToken string `yaml:"oauth_token"`
			} `yaml:"yandex"`
		} `yaml:"kms"`
	}
	if err := root.Decode(&back); err != nil {
		t.Fatal(err)
	}
	if back.KMS.Yandex.OAuthToken != "${YANDEX_OAUTH}" {
		t.Errorf("oauth_token = %q", back.KMS.Yandex.OAuthToken)
	}
}
