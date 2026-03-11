package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ledatu/csar/internal/apierror"
)

// ── Context-based header passthrough ─────────────────────────────────
// httputil.ReverseProxy replaces the ResponseWriter's header map with the
// upstream's response headers. To ensure CSAR backpressure headers survive
// the proxy, the router injects them into the request context and
// modifyResponse copies them back onto the final response.

// csarCtxKey is an unexported type for CSAR header context keys.
type csarCtxKey struct{ name string }

var (
	ctxKeyWaitMS    = csarCtxKey{"X-CSAR-Wait-MS"}
	ctxKeyStatus    = csarCtxKey{"X-CSAR-Status"}
	ctxKeyRetryAftr = csarCtxKey{"Retry-After"}
	ctxKeyProtoVer  = csarCtxKey{"X-CSAR-Protocol-Version"}
)

// WithCSARHeaders stores X-CSAR-Wait-MS, X-CSAR-Status, Retry-After, and
// X-CSAR-Protocol-Version values in the request context so they survive
// the ReverseProxy round-trip. Empty values are ignored.
func WithCSARHeaders(ctx context.Context, waitMS, status, retryAfter string) context.Context {
	if waitMS != "" {
		ctx = context.WithValue(ctx, ctxKeyWaitMS, waitMS)
	}
	if status != "" {
		ctx = context.WithValue(ctx, ctxKeyStatus, status)
	}
	if retryAfter != "" {
		ctx = context.WithValue(ctx, ctxKeyRetryAftr, retryAfter)
	}
	return ctx
}

// WithProtocolVersion stores the protocol version in context for proxy passthrough.
func WithProtocolVersion(ctx context.Context, version string) context.Context {
	if version != "" {
		ctx = context.WithValue(ctx, ctxKeyProtoVer, version)
	}
	return ctx
}

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
	target   *url.URL
	proxy    *httputil.ReverseProxy
	pathMode string // "replace" (default) or "append"
}

// Option configures the ReverseProxy.
type Option func(*options)

type options struct {
	tls            *TLSConfig
	transport      http.RoundTripper
	ssrfProtection *SSRFProtection
	pathMode       string
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

// WithPathMode sets the path handling mode for the proxy director.
// "replace" (default): target_url path replaces the incoming request path entirely.
// "append": incoming request path is appended to target_url path.
func WithPathMode(mode string) Option {
	return func(o *options) { o.pathMode = mode }
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
		target:   target,
		pathMode: o.pathMode,
	}

	proxy := &httputil.ReverseProxy{
		Director:       rp.director,
		ModifyResponse: rp.modifyResponse,
		ErrorHandler:   rp.errorHandler,
	}

	// Configure transport
	switch {
	case o.transport != nil:
		proxy.Transport = o.transport
	case o.tls != nil:
		transport, err := buildTLSTransport(o.tls, o.ssrfProtection)
		if err != nil {
			return nil, fmt.Errorf("building TLS transport for %q: %w", targetURL, err)
		}
		proxy.Transport = transport
	case o.ssrfProtection != nil:
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
// Path modes:
//   - "replace" (default): target_url path replaces the incoming request path
//     entirely. Use when target_url contains the full upstream API path.
//   - "append": incoming request path is appended to the target base path.
//     Use when target_url is a base prefix (e.g. "https://api.example.com/v2").
func (rp *ReverseProxy) director(req *http.Request) {
	req.URL.Scheme = rp.target.Scheme
	req.URL.Host = rp.target.Host
	req.Host = rp.target.Host

	if rp.pathMode == "append" {
		// Append mode: join target base path + incoming request path.
		req.URL.Path = joinPaths(rp.target.Path, req.URL.Path)
	} else {
		// Replace mode (default): target path IS the upstream path.
		req.URL.Path = rp.target.Path
	}
	req.URL.RawPath = "" // reset encoded path

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

// modifyResponse re-injects CSAR backpressure headers into the upstream
// response. The values were stashed in the request context by the router
// (via WithCSARHeaders) before the proxy ran, and would otherwise be lost
// because httputil.ReverseProxy replaces the ResponseWriter's header map.
func (rp *ReverseProxy) modifyResponse(resp *http.Response) error {
	ctx := resp.Request.Context()
	if v, ok := ctx.Value(ctxKeyWaitMS).(string); ok && v != "" {
		resp.Header.Set("X-CSAR-Wait-MS", v)
	}
	if v, ok := ctx.Value(ctxKeyStatus).(string); ok && v != "" {
		resp.Header.Set("X-CSAR-Status", v)
	}
	if v, ok := ctx.Value(ctxKeyRetryAftr).(string); ok && v != "" {
		resp.Header.Set("Retry-After", v)
	}
	if v, ok := ctx.Value(ctxKeyProtoVer).(string); ok && v != "" {
		resp.Header.Set("X-CSAR-Protocol-Version", v)
	}
	return nil
}

// errorHandler handles errors from the upstream.
func (rp *ReverseProxy) errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	requestID := r.Header.Get("X-Request-ID")
	apierror.New(apierror.CodeUpstreamError, http.StatusBadGateway,
		"upstream error").WithDetail(err.Error()).
		WithRequestID(requestID).Write(w)
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
