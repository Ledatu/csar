package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoad_ValidConfig(t *testing.T) {
	yaml := `
listen_addr: ":8080"

circuit_breakers:
  standard:
    max_requests: 5
    interval: "60s"
    timeout: "30s"
    failure_threshold: 3

paths:
  /api/v1/products:
    get:
      x-csar-backend:
        target_url: "https://api.example.com/products"
      x-csar-security:
        kms_key_id: "key-123"
        token_ref: "token_main"
        inject_header: "Authorization"
        inject_format: "Bearer {token}"
      x-csar-traffic:
        rps: 5.0
        burst: 10
        max_wait: "30s"
      x-csar-resilience:
        circuit_breaker: "standard"
    post:
      x-csar-backend:
        target_url: "https://api.example.com/products"
  /health:
    get:
      x-csar-backend:
        target_url: "http://localhost:8080"
`
	path := writeTemp(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.ListenAddr != ":8080" {
		t.Errorf("ListenAddr = %q, want %q", cfg.ListenAddr, ":8080")
	}

	if len(cfg.Paths) != 2 {
		t.Fatalf("len(Paths) = %d, want 2", len(cfg.Paths))
	}

	// Check /api/v1/products GET
	products, ok := cfg.Paths["/api/v1/products"]
	if !ok {
		t.Fatal("missing path /api/v1/products")
	}
	getRoute, ok := products["get"]
	if !ok {
		t.Fatal("missing method GET for /api/v1/products")
	}

	if getRoute.Backend.TargetURL != "https://api.example.com/products" {
		t.Errorf("TargetURL = %q, want %q", getRoute.Backend.TargetURL, "https://api.example.com/products")
	}
	if len(getRoute.Security) == 0 {
		t.Fatal("Security is empty, want at least one entry")
	}
	if getRoute.Security[0].KMSKeyID != "key-123" {
		t.Errorf("KMSKeyID = %q, want %q", getRoute.Security[0].KMSKeyID, "key-123")
	}
	if getRoute.Security[0].InjectHeader != "Authorization" {
		t.Errorf("InjectHeader = %q, want %q", getRoute.Security[0].InjectHeader, "Authorization")
	}
	if getRoute.Security[0].InjectFormat != "Bearer {token}" {
		t.Errorf("InjectFormat = %q, want %q", getRoute.Security[0].InjectFormat, "Bearer {token}")
	}

	if getRoute.Traffic == nil {
		t.Fatal("Traffic is nil, want non-nil")
	}
	if getRoute.Traffic.RPS != 5.0 {
		t.Errorf("RPS = %f, want 5.0", getRoute.Traffic.RPS)
	}
	if getRoute.Traffic.Burst != 10 {
		t.Errorf("Burst = %d, want 10", getRoute.Traffic.Burst)
	}
	if getRoute.Traffic.MaxWait.Duration != 30*time.Second {
		t.Errorf("MaxWait = %v, want 30s", getRoute.Traffic.MaxWait.Duration)
	}

	if getRoute.Resilience == nil {
		t.Fatal("Resilience is nil, want non-nil")
	}
	if getRoute.Resilience.CircuitBreaker != "standard" {
		t.Errorf("CircuitBreaker = %q, want %q", getRoute.Resilience.CircuitBreaker, "standard")
	}

	// Check /api/v1/products POST (no security, traffic, resilience)
	postRoute, ok := products["post"]
	if !ok {
		t.Fatal("missing method POST for /api/v1/products")
	}
	if len(postRoute.Security) != 0 {
		t.Error("POST Security should be empty")
	}
	if postRoute.Traffic != nil {
		t.Error("POST Traffic should be nil")
	}

	// Check circuit breaker profile
	cb, ok := cfg.CircuitBreakers["standard"]
	if !ok {
		t.Fatal("missing circuit_breaker profile 'standard'")
	}
	if cb.MaxRequests != 5 {
		t.Errorf("CB MaxRequests = %d, want 5", cb.MaxRequests)
	}
	if cb.Timeout.Duration != 30*time.Second {
		t.Errorf("CB Timeout = %v, want 30s", cb.Timeout.Duration)
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := Load("/nonexistent/config.yaml")
	if err == nil {
		t.Fatal("Load() should fail for missing file")
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	path := writeTemp(t, `{{{not yaml`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() should fail for invalid YAML")
	}
}

func TestLoad_TLSConfig(t *testing.T) {
	yaml := `
listen_addr: ":8443"
tls:
  cert_file: "/etc/csar/tls/cert.pem"
  key_file: "/etc/csar/tls/key.pem"
  client_ca_file: "/etc/csar/tls/ca.pem"
  min_version: "1.3"
paths:
  /api:
    get:
      x-csar-backend:
        target_url: "https://api.example.com"
        tls:
          insecure_skip_verify: true
          ca_file: "/etc/csar/upstream-ca.pem"
          cert_file: "/etc/csar/client-cert.pem"
          key_file: "/etc/csar/client-key.pem"
`
	path := writeTemp(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.TLS == nil {
		t.Fatal("TLS is nil, want non-nil")
	}
	if cfg.TLS.CertFile != "/etc/csar/tls/cert.pem" {
		t.Errorf("TLS.CertFile = %q", cfg.TLS.CertFile)
	}
	if cfg.TLS.KeyFile != "/etc/csar/tls/key.pem" {
		t.Errorf("TLS.KeyFile = %q", cfg.TLS.KeyFile)
	}
	if cfg.TLS.ClientCAFile != "/etc/csar/tls/ca.pem" {
		t.Errorf("TLS.ClientCAFile = %q", cfg.TLS.ClientCAFile)
	}
	if cfg.TLS.MinVersion != "1.3" {
		t.Errorf("TLS.MinVersion = %q, want 1.3", cfg.TLS.MinVersion)
	}

	// Check backend TLS
	route := cfg.Paths["/api"]["get"]
	if route.Backend.TLS == nil {
		t.Fatal("Backend.TLS is nil")
	}
	if !route.Backend.TLS.InsecureSkipVerify {
		t.Error("InsecureSkipVerify = false, want true")
	}
	if route.Backend.TLS.CAFile != "/etc/csar/upstream-ca.pem" {
		t.Errorf("Backend.TLS.CAFile = %q", route.Backend.TLS.CAFile)
	}
	if route.Backend.TLS.CertFile != "/etc/csar/client-cert.pem" {
		t.Errorf("Backend.TLS.CertFile = %q", route.Backend.TLS.CertFile)
	}
}

func TestLoad_PathMode_FromYAML(t *testing.T) {
	yamlStr := `
listen_addr: ":8080"
paths:
  /api/v1/products:
    get:
      x-csar-backend:
        target_url: "https://api.example.com/v1/products"
        path_mode: "replace"
  /api/proxy:
    get:
      x-csar-backend:
        target_url: "https://internal-api.local/v2"
        path_mode: "append"
`
	path := writeTemp(t, yamlStr)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	replaceRoute := cfg.Paths["/api/v1/products"]["get"]
	if replaceRoute.Backend.PathMode != "replace" {
		t.Errorf("PathMode = %q, want %q", replaceRoute.Backend.PathMode, "replace")
	}

	appendRoute := cfg.Paths["/api/proxy"]["get"]
	if appendRoute.Backend.PathMode != "append" {
		t.Errorf("PathMode = %q, want %q", appendRoute.Backend.PathMode, "append")
	}
}

// --- helpers ---

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}
