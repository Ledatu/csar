package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

// TLSConfig configures outbound TLS for the reverse proxy.
type TLSConfig struct {
	// InsecureSkipVerify disables certificate verification (dev only!).
	InsecureSkipVerify bool

	// CAFile is the path to a custom CA bundle PEM.
	CAFile string

	// CertFile + KeyFile enable mTLS to the upstream.
	CertFile string
	KeyFile  string
}

// ReverseProxy handles forwarding requests to a single upstream service.
type ReverseProxy struct {
	target *url.URL
	proxy  *httputil.ReverseProxy
}

// Option configures the ReverseProxy.
type Option func(*options)

type options struct {
	tls            *TLSConfig
	transport      http.RoundTripper
	ssrfProtection *SSRFProtection
}

// WithTLS configures outbound TLS for this proxy.
func WithTLS(cfg *TLSConfig) Option {
	return func(o *options) { o.tls = cfg }
}

// WithTransport overrides the HTTP transport (mainly for testing).
func WithTransport(rt http.RoundTripper) Option {
	return func(o *options) { o.transport = rt }
}

// WithSSRFProtection enables SSRF protection on the proxy's outbound connections.
func WithSSRFProtection(p *SSRFProtection) Option {
	return func(o *options) { o.ssrfProtection = p }
}

// New creates a new ReverseProxy for the given target URL.
func New(targetURL string, opts ...Option) (*ReverseProxy, error) {
	target, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL %q: %w", targetURL, err)
	}

	o := &options{}
	for _, opt := range opts {
		opt(o)
	}

	rp := &ReverseProxy{
		target: target,
	}

	proxy := &httputil.ReverseProxy{
		Director:       rp.director,
		ModifyResponse: rp.modifyResponse,
		ErrorHandler:   rp.errorHandler,
	}

	// Configure transport
	if o.transport != nil {
		proxy.Transport = o.transport
	} else if o.tls != nil {
		transport, err := buildTLSTransport(o.tls, o.ssrfProtection)
		if err != nil {
			return nil, fmt.Errorf("building TLS transport for %q: %w", targetURL, err)
		}
		proxy.Transport = transport
	} else if o.ssrfProtection != nil {
		// No TLS, but SSRF protection is enabled — use a plain transport with safe dialer.
		proxy.Transport = &http.Transport{
			DialContext:         safeDialContext(o.ssrfProtection),
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 20,
			IdleConnTimeout:     90 * time.Second,
		}
	}

	rp.proxy = proxy
	return rp, nil
}

// ServeHTTP forwards the request to the upstream target.
func (rp *ReverseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rp.proxy.ServeHTTP(w, r)
}

// director rewrites the request to point to the upstream target.
//
// Path policy (audit §5): if the target URL has a base path (e.g. "/v2"),
// it is prepended to the original request path. Otherwise the original
// request path is preserved unchanged. This behavior is consistent with
// the load balancer director.
func (rp *ReverseProxy) director(req *http.Request) {
	req.URL.Scheme = rp.target.Scheme
	req.URL.Host = rp.target.Host
	req.Host = rp.target.Host

	// Join target base path + original request path.
	req.URL.Path = joinPaths(rp.target.Path, req.URL.Path)
	req.URL.RawPath = "" // reset encoded path after join

	// Merge query parameters.
	if rp.target.RawQuery == "" || req.URL.RawQuery == "" {
		req.URL.RawQuery = rp.target.RawQuery + req.URL.RawQuery
	} else {
		req.URL.RawQuery = rp.target.RawQuery + "&" + req.URL.RawQuery
	}

	// Remove hop-by-hop headers
	if _, ok := req.Header["User-Agent"]; !ok {
		req.Header.Set("User-Agent", "")
	}
}

// joinPaths joins a base path and a request path with a single slash separator.
// Ensures no double slashes and handles empty base gracefully.
func joinPaths(base, reqPath string) string {
	if base == "" || base == "/" {
		return reqPath
	}
	if reqPath == "" || reqPath == "/" {
		return base
	}
	return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(reqPath, "/")
}

// modifyResponse is a hook for future logging/metrics on responses.
func (rp *ReverseProxy) modifyResponse(resp *http.Response) error {
	// Hook for future metrics: record upstream response status, latency, etc.
	return nil
}

// errorHandler handles errors from the upstream.
func (rp *ReverseProxy) errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadGateway)
	fmt.Fprintf(w, `{"error":"upstream error","detail":%q}`, err.Error())
}

// Target returns the upstream target URL.
func (rp *ReverseProxy) Target() *url.URL {
	return rp.target
}

// buildTLSTransport creates an http.Transport with custom TLS configuration.
func buildTLSTransport(cfg *TLSConfig, ssrf *SSRFProtection) (*http.Transport, error) {
	tlsCfg := &tls.Config{
		InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec // configurable per-backend
	}

	// Custom CA bundle
	if cfg.CAFile != "" {
		caCert, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("reading CA file %q: %w", cfg.CAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("CA file %q contains no valid certificates", cfg.CAFile)
		}
		tlsCfg.RootCAs = pool
	}

	// Client certificate for mTLS
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("loading client cert %q / key %q: %w", cfg.CertFile, cfg.KeyFile, err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	transport := &http.Transport{
		TLSClientConfig:     tlsCfg,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
	}
	if ssrf != nil {
		transport.DialContext = safeDialContext(ssrf)
	}
	return transport, nil
}
