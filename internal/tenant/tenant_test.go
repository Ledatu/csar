package tenant

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestRouter_Resolve_ByCustomHeader(t *testing.T) {
	tr := NewRouter(newTestLogger())
	cfg := Config{
		Header: "X-Tenant-ID",
		Backends: map[string]string{
			"acme":   "https://api-acme.example.com",
			"globex": "https://api-globex.example.com",
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/products", nil)
	req.Header.Set("X-Tenant-ID", "acme")

	target, tenant, err := tr.Resolve(cfg, req)
	if err != nil {
		t.Fatalf("Resolve() error: %v", err)
	}
	if tenant != "acme" {
		t.Errorf("tenant = %q, want %q", tenant, "acme")
	}
	if target != "https://api-acme.example.com" {
		t.Errorf("target = %q, want %q", target, "https://api-acme.example.com")
	}
}

func TestRouter_Resolve_ByHost(t *testing.T) {
	tr := NewRouter(newTestLogger())
	cfg := Config{
		Header: "Host",
		Backends: map[string]string{
			"acme.example.com":   "https://api-acme.internal",
			"globex.example.com": "https://api-globex.internal",
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.Host = "acme.example.com"

	target, tenant, err := tr.Resolve(cfg, req)
	if err != nil {
		t.Fatalf("Resolve() error: %v", err)
	}
	if tenant != "acme.example.com" {
		t.Errorf("tenant = %q, want %q", tenant, "acme.example.com")
	}
	if target != "https://api-acme.internal" {
		t.Errorf("target = %q, want %q", target, "https://api-acme.internal")
	}
}

func TestRouter_Resolve_HostWithPort(t *testing.T) {
	tr := NewRouter(newTestLogger())
	cfg := Config{
		Header: "Host",
		Backends: map[string]string{
			"acme.example.com": "https://api-acme.internal",
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.Host = "acme.example.com:8080"

	target, tenant, err := tr.Resolve(cfg, req)
	if err != nil {
		t.Fatalf("Resolve() error: %v", err)
	}
	if tenant != "acme.example.com" {
		t.Errorf("tenant = %q, want %q", tenant, "acme.example.com")
	}
	if target != "https://api-acme.internal" {
		t.Errorf("target = %q, want %q", target, "https://api-acme.internal")
	}
}

func TestRouter_Resolve_Default(t *testing.T) {
	tr := NewRouter(newTestLogger())
	cfg := Config{
		Header: "X-Tenant-ID",
		Backends: map[string]string{
			"acme": "https://api-acme.example.com",
		},
		Default: "https://api-default.example.com",
	}

	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.Header.Set("X-Tenant-ID", "unknown-tenant")

	target, _, err := tr.Resolve(cfg, req)
	if err != nil {
		t.Fatalf("Resolve() error: %v", err)
	}
	if target != "https://api-default.example.com" {
		t.Errorf("target = %q, want default", target)
	}
}

func TestRouter_Resolve_NoMatch_NoDefault(t *testing.T) {
	tr := NewRouter(newTestLogger())
	cfg := Config{
		Header: "X-Tenant-ID",
		Backends: map[string]string{
			"acme": "https://api-acme.example.com",
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.Header.Set("X-Tenant-ID", "unknown")

	_, _, err := tr.Resolve(cfg, req)
	if err == nil {
		t.Fatal("expected error for unmatched tenant with no default")
	}
}

func TestRouter_Resolve_CaseInsensitiveHost(t *testing.T) {
	tr := NewRouter(newTestLogger())
	cfg := Config{
		Header: "Host",
		Backends: map[string]string{
			"acme.example.com": "https://api-acme.internal",
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.Host = "ACME.EXAMPLE.COM"

	target, _, err := tr.Resolve(cfg, req)
	if err != nil {
		t.Fatalf("Resolve() error: %v", err)
	}
	if target != "https://api-acme.internal" {
		t.Errorf("target = %q, want case-insensitive match", target)
	}
}

func TestRouter_Proxy_Routes(t *testing.T) {
	// Create upstream servers
	acmeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"tenant":"acme"}`))
	}))
	defer acmeServer.Close()

	globexServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"tenant":"globex"}`))
	}))
	defer globexServer.Close()

	tr := NewRouter(newTestLogger())
	cfg := Config{
		Header: "X-Tenant-ID",
		Backends: map[string]string{
			"acme":   acmeServer.URL,
			"globex": globexServer.URL,
		},
	}

	handler := tr.Proxy(cfg, nil)

	// Test acme
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.Header.Set("X-Tenant-ID", "acme")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("acme: status = %d, want 200", rec.Code)
	}
	var result map[string]string
	json.NewDecoder(rec.Result().Body).Decode(&result)
	if result["tenant"] != "acme" {
		t.Errorf("acme: body tenant = %q, want %q", result["tenant"], "acme")
	}

	// Test globex
	req = httptest.NewRequest(http.MethodGet, "/api", nil)
	req.Header.Set("X-Tenant-ID", "globex")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("globex: status = %d, want 200", rec.Code)
	}
	json.NewDecoder(rec.Result().Body).Decode(&result)
	if result["tenant"] != "globex" {
		t.Errorf("globex: body tenant = %q, want %q", result["tenant"], "globex")
	}
}

func TestRouter_Proxy_UnmatchedTenant_Returns404(t *testing.T) {
	tr := NewRouter(newTestLogger())
	cfg := Config{
		Header: "X-Tenant-ID",
		Backends: map[string]string{
			"acme": "http://unused:9999",
		},
	}

	handler := tr.Proxy(cfg, nil)

	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.Header.Set("X-Tenant-ID", "nonexistent")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestRouter_ProxyCaching(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	tr := NewRouter(newTestLogger())

	// Call getOrCreateProxy twice — should reuse the same proxy
	p1, err := tr.getOrCreateProxy(server.URL, http.DefaultTransport, "test-transport")
	if err != nil {
		t.Fatal(err)
	}
	p2, err := tr.getOrCreateProxy(server.URL, http.DefaultTransport, "test-transport")
	if err != nil {
		t.Fatal(err)
	}

	if p1 != p2 {
		t.Error("expected same proxy instance for same URL")
	}
}

func TestRouter_ProxyCaching_IsolatesTransportKeys(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	tr := NewRouter(newTestLogger())
	p1, err := tr.getOrCreateProxy(server.URL, http.DefaultTransport, "identity")
	if err != nil {
		t.Fatal(err)
	}
	p2, err := tr.getOrCreateProxy(server.URL, http.DefaultTransport, "external")
	if err != nil {
		t.Fatal(err)
	}
	if p1 == p2 {
		t.Fatal("expected different proxy instances for different transport keys")
	}
}
