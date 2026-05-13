package router

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/ledatu/csar/internal/config"
	"github.com/ledatu/csar/internal/proxy"
)

type transportRegistry struct {
	pools      map[string]config.BackendPoolConfig
	ssrf       *proxy.SSRFProtection
	transports map[string]http.RoundTripper
}

func newTransportRegistry(pools map[string]config.BackendPoolConfig, ssrf *proxy.SSRFProtection) *transportRegistry {
	return &transportRegistry{
		pools:      pools,
		ssrf:       ssrf,
		transports: make(map[string]http.RoundTripper),
	}
}

func (r *transportRegistry) forBackend(backend config.BackendConfig) (http.RoundTripper, string, error) {
	poolName := strings.TrimSpace(backend.Pool)
	poolCfg, ok := r.pools[poolName]
	if poolName != "" && !ok {
		return nil, "", fmt.Errorf("backend pool %q not found", poolName)
	}

	tlsCfg := proxyTLSConfig(backend.TLS)
	key := transportKey(poolName, poolCfg, tlsCfg, r.ssrf != nil)
	if rt, ok := r.transports[key]; ok {
		return rt, key, nil
	}

	rt, err := proxy.BuildTransportWithConfig(tlsCfg, r.ssrf, proxy.TransportConfig{
		MaxIdleConns:          poolCfg.MaxIdleConns,
		MaxIdleConnsPerHost:   poolCfg.MaxIdleConnsPerHost,
		MaxConnsPerHost:       poolCfg.MaxConnsPerHost,
		DialTimeout:           poolCfg.DialTimeout.Duration,
		TLSHandshakeTimeout:   poolCfg.TLSHandshakeTimeout.Duration,
		ResponseHeaderTimeout: poolCfg.ResponseHeaderTimeout.Duration,
		IdleConnTimeout:       poolCfg.IdleConnTimeout.Duration,
		ExpectContinueTimeout: poolCfg.ExpectContinueTimeout.Duration,
	})
	if err != nil {
		return nil, "", err
	}
	r.transports[key] = rt
	return rt, key, nil
}

func proxyTLSConfig(bt *config.BackendTLSConfig) *proxy.TLSConfig {
	if bt == nil {
		return nil
	}
	return &proxy.TLSConfig{
		InsecureSkipVerify: bt.InsecureSkipVerify,
		CAFile:             bt.CAFile,
		CertFile:           bt.CertFile,
		KeyFile:            bt.KeyFile,
	}
}

func transportKey(poolName string, poolCfg config.BackendPoolConfig, tlsCfg *proxy.TLSConfig, ssrfEnabled bool) string {
	tlsKey := "tls:<nil>"
	if tlsCfg != nil {
		tlsKey = fmt.Sprintf("tls:%t:%s:%s:%s",
			tlsCfg.InsecureSkipVerify,
			tlsCfg.CAFile,
			tlsCfg.CertFile,
			tlsCfg.KeyFile,
		)
	}
	return fmt.Sprintf(
		"pool:%s|ssrf:%t|%s|idle:%d|idle_host:%d|max_host:%d|dial:%s|tls_hs:%s|resp_hdr:%s|idle_timeout:%s|expect:%s",
		poolName,
		ssrfEnabled,
		tlsKey,
		poolCfg.MaxIdleConns,
		poolCfg.MaxIdleConnsPerHost,
		poolCfg.MaxConnsPerHost,
		poolCfg.DialTimeout.Duration,
		poolCfg.TLSHandshakeTimeout.Duration,
		poolCfg.ResponseHeaderTimeout.Duration,
		poolCfg.IdleConnTimeout.Duration,
		poolCfg.ExpectContinueTimeout.Duration,
	)
}
