package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNew_ValidURL(t *testing.T) {
	rp, err := New("http://localhost:3000")
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if rp.Target().Host != "localhost:3000" {
		t.Errorf("Target().Host = %q, want %q", rp.Target().Host, "localhost:3000")
	}
	if rp.Target().Scheme != "http" {
		t.Errorf("Target().Scheme = %q, want %q", rp.Target().Scheme, "http")
	}
}

func TestNew_InvalidURL(t *testing.T) {
	// url.Parse is very lenient, so use a scheme that causes issues
	_, err := New("://missing-scheme")
	if err == nil {
		t.Fatal("New() should fail for invalid URL")
	}
}

func TestReverseProxy_ForwardsToUpstream(t *testing.T) {
	// Create a test upstream server
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream", "true")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message":"hello from upstream"}`))
	}))
	defer upstream.Close()

	rp, err := New(upstream.URL)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	// Make a request through the proxy
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	rp.ServeHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != `{"message":"hello from upstream"}` {
		t.Errorf("body = %q, want upstream response", string(body))
	}
}

func TestReverseProxy_PreservesQueryParams(t *testing.T) {
	var receivedQuery string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	rp, err := New(upstream.URL)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/test?foo=bar&baz=qux", nil)
	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)

	if receivedQuery != "foo=bar&baz=qux" {
		t.Errorf("query = %q, want %q", receivedQuery, "foo=bar&baz=qux")
	}
}

func TestReverseProxy_UpstreamHeaders(t *testing.T) {
	var receivedHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHost = r.Host
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	rp, err := New(upstream.URL)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Host = "original-host.com"
	rec := httptest.NewRecorder()

	rp.ServeHTTP(rec, req)

	// Director should rewrite Host to the target
	if receivedHost != rp.Target().Host {
		t.Errorf("upstream received Host = %q, want %q", receivedHost, rp.Target().Host)
	}
}

func TestReverseProxy_ErrorHandler_BadUpstream(t *testing.T) {
	// Point to a closed server
	rp, err := New("http://127.0.0.1:1") // port 1 is almost certainly closed
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	rp.ServeHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want %d (bad gateway)", resp.StatusCode, http.StatusBadGateway)
	}

	body, _ := io.ReadAll(resp.Body)
	if len(body) == 0 {
		t.Error("expected error body, got empty")
	}
}

func TestReverseProxy_UpstreamStatusCodes(t *testing.T) {
	codes := []int{200, 201, 400, 404, 500}

	for _, code := range codes {
		t.Run(http.StatusText(code), func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(code)
			}))
			defer upstream.Close()

			rp, err := New(upstream.URL)
			if err != nil {
				t.Fatalf("New() error: %v", err)
			}

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			rec := httptest.NewRecorder()
			rp.ServeHTTP(rec, req)

			if rec.Code != code {
				t.Errorf("status = %d, want %d", rec.Code, code)
			}
		})
	}
}

func TestNew_WithInsecureSkipVerify(t *testing.T) {
	// Start a TLS server with a self-signed cert
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"tls":"ok"}`))
	}))
	defer upstream.Close()

	// Without skip-verify, this should fail (self-signed)
	rp, err := New(upstream.URL)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Errorf("without skip-verify: status = %d, want 502 (cert error)", rec.Code)
	}

	// With skip-verify, it should succeed
	rp2, err := New(upstream.URL, WithTLS(&TLSConfig{InsecureSkipVerify: true}))
	if err != nil {
		t.Fatalf("New() with TLS error: %v", err)
	}
	req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec2 := httptest.NewRecorder()
	rp2.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Errorf("with skip-verify: status = %d, want 200", rec2.Code)
	}
}

func TestNew_WithCustomCA(t *testing.T) {
	// Start a TLS server
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ca":"ok"}`))
	}))
	defer upstream.Close()

	// Get the server's certificate pool
	pool := x509.NewCertPool()
	for _, cert := range upstream.TLS.Certificates {
		for _, raw := range cert.Certificate {
			c, err := x509.ParseCertificate(raw)
			if err == nil {
				pool.AddCert(c)
			}
		}
	}

	// Build a proxy with a custom transport that trusts the test server's cert
	rp, err := New(upstream.URL, WithTransport(&http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: pool,
		},
	}))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("with custom CA: status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if body != `{"ca":"ok"}` {
		t.Errorf("body = %q, want TLS response", body)
	}
}

func TestNew_WithTransportOption(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	rp, err := New(upstream.URL, WithTransport(http.DefaultTransport))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestBuildTLSTransport_InvalidCA(t *testing.T) {
	_, err := buildTLSTransport(&TLSConfig{CAFile: "/nonexistent/ca.pem"}, nil)
	if err == nil {
		t.Fatal("buildTLSTransport should fail for nonexistent CA file")
	}
}

func TestBuildTLSTransport_InvalidCert(t *testing.T) {
	_, err := buildTLSTransport(&TLSConfig{CertFile: "/nonexistent/cert.pem", KeyFile: "/nonexistent/key.pem"}, nil)
	if err == nil {
		t.Fatal("buildTLSTransport should fail for nonexistent cert files")
	}
}

// ==========================================================================
// Path Mode tests (Feature C)
// ==========================================================================

func TestDirector_ReplaceMode_Default(t *testing.T) {
	// Default path_mode is "replace": target path replaces request path entirely.
	var receivedPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	rp, err := New(upstream.URL + "/adv/v1/balance")
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/balance", nil)
	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)

	// In replace mode, upstream should receive the target path, NOT the request path.
	if receivedPath != "/adv/v1/balance" {
		t.Errorf("upstream received path = %q, want %q (replace mode)", receivedPath, "/adv/v1/balance")
	}
}

func TestDirector_ReplaceMode_Explicit(t *testing.T) {
	// Explicitly setting path_mode="replace" should behave like the default.
	var receivedPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	rp, err := New(upstream.URL+"/api/data", WithPathMode("replace"))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/gateway/api/data", nil)
	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)

	if receivedPath != "/api/data" {
		t.Errorf("upstream received path = %q, want %q", receivedPath, "/api/data")
	}
}

func TestDirector_AppendMode(t *testing.T) {
	// With path_mode="append", request path is appended to target base path.
	var receivedPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	rp, err := New(upstream.URL+"/v2", WithPathMode("append"))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/users/42", nil)
	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)

	// In append mode: /v2 + /api/users/42 = /v2/api/users/42
	if receivedPath != "/v2/api/users/42" {
		t.Errorf("upstream received path = %q, want %q (append mode)", receivedPath, "/v2/api/users/42")
	}
}

func TestDirector_ReplaceMode_QueryPreserved(t *testing.T) {
	// In replace mode, query parameters from the request should still be forwarded.
	var receivedPath, receivedQuery string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		receivedQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	rp, err := New(upstream.URL + "/adv/v1/balance")
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/balance?seller_id=42&page=1", nil)
	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)

	if receivedPath != "/adv/v1/balance" {
		t.Errorf("path = %q, want %q", receivedPath, "/adv/v1/balance")
	}
	if receivedQuery != "seller_id=42&page=1" {
		t.Errorf("query = %q, want %q", receivedQuery, "seller_id=42&page=1")
	}
}

func TestDirector_AppendMode_EmptyBasePath(t *testing.T) {
	// Append mode with no target base path should just use request path.
	var receivedPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	rp, err := New(upstream.URL, WithPathMode("append"))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/foo/bar", nil)
	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)

	if receivedPath != "/foo/bar" {
		t.Errorf("path = %q, want %q", receivedPath, "/foo/bar")
	}
}

func TestDirector_ReplaceMode_NoTargetPath(t *testing.T) {
	// Replace mode with no target path — upstream gets empty path
	// (which httputil normalizes to "/").
	var receivedPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	rp, err := New(upstream.URL)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/some/path", nil)
	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)

	// target has no path, so in replace mode we get "" which httputil normalizes to "/"
	if receivedPath != "" && receivedPath != "/" {
		t.Errorf("path = %q, want empty or /", receivedPath)
	}
}
