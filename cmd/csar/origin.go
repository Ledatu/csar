package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/ledatu/csar-core/jwtx"
	"github.com/ledatu/csar-core/origincontext"
	"github.com/ledatu/csar-core/tlsx"
	"github.com/ledatu/csar/internal/config"
)

// buildRootIssuer owns two transports: root requests use Core's private clone,
// JWKS uses the original. Both are closed at process shutdown, not route reload.
func buildRootIssuer(cfg *config.OriginIssuerConfig, logger *slog.Logger) (*origincontext.RootClient, func(), error) {
	if cfg == nil {
		return nil, func() {}, nil
	}
	if err := cfg.Validate(); err != nil {
		return nil, nil, err
	}
	transport, err := tlsx.NewHTTPTransport(tlsx.ClientConfig{
		CAFile: cfg.TLS.CAFile, CertFile: cfg.TLS.CertFile, KeyFile: cfg.TLS.KeyFile,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("origin issuer TLS: %w", err)
	}
	transport.Proxy = nil // dedicated trusted ingress; do not inherit ambient proxies
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	keys := jwtx.NewRemoteJWKS(cfg.JWKSURL, jwtx.WithHTTPClient(client), jwtx.WithLogger(logger))
	issuer, err := origincontext.NewRootClient(origincontext.RootClientConfig{
		Endpoint: cfg.Endpoint, Issuer: cfg.Issuer, HTTPClient: client, KeyFuncContext: keys.KeyFuncContext,
	})
	if err != nil {
		transport.CloseIdleConnections()
		return nil, nil, fmt.Errorf("origin issuer configuration: %w", err)
	}
	return issuer, func() { issuer.Close(); transport.CloseIdleConnections() }, nil
}
