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
