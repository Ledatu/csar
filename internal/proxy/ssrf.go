// Package proxy — SSRF protection via custom DialContext.
//
// This file implements a dialer that inspects resolved IP addresses and
// rejects connections to private, loopback, link-local, and metadata
// subnets (RFC 1918, RFC 3927, RFC 4291) unless explicitly allowlisted.
//
// Recommended by security audit §2.3.2.
package proxy

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/ledatu/csar-core/httpx/clientx"
)

// SSRFProtection configures outbound connection restrictions to prevent
// Server-Side Request Forgery attacks.
type SSRFProtection struct {
	// BlockPrivate blocks connections to RFC 1918 private subnets.
	BlockPrivate bool

	// BlockLoopback blocks connections to loopback addresses.
	BlockLoopback bool

	// BlockLinkLocal blocks connections to link-local addresses (169.254.x.x, fe80::/10).
	BlockLinkLocal bool

	// BlockMetadata blocks connections to cloud metadata endpoints (169.254.169.254).
	BlockMetadata bool

	// AllowedHosts is an explicit allowlist of hosts that bypass SSRF checks.
	AllowedHosts map[string]bool
}

// DefaultSSRFProtection returns a protection config that blocks all dangerous subnets.
func DefaultSSRFProtection() *SSRFProtection {
	return &SSRFProtection{
		BlockPrivate:   true,
		BlockLoopback:  true,
		BlockLinkLocal: true,
		BlockMetadata:  true,
		AllowedHosts:   make(map[string]bool),
	}
}

// safeDialContextWithTimeout returns a DialContext function with the supplied
// TCP dial timeout while preserving the SSRF validation behavior.
func safeDialContextWithTimeout(protection *SSRFProtection, timeout time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
	}

	if protection == nil {
		return dialer.DialContext
	}

	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("ssrf: invalid address %q: %w", addr, err)
		}

		// Check allowlist first — if the host is explicitly allowed, skip checks.
		if protection.AllowedHosts[host] {
			return dialer.DialContext(ctx, network, addr)
		}

		// Resolve the hostname to IPs.
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("ssrf: DNS resolution failed for %q: %w", host, err)
		}

		// Validate each resolved IP.
		for _, ipAddr := range ips {
			ip := ipAddr.IP
			if err := validateIP(ip, protection); err != nil {
				return nil, fmt.Errorf("ssrf: blocked connection to %s (%s): %w", host, ip.String(), err)
			}
		}

		// All IPs are safe — connect using the resolved address.
		// We connect to the first valid IP to avoid re-resolution.
		if len(ips) > 0 {
			resolved := net.JoinHostPort(ips[0].IP.String(), port)
			return dialer.DialContext(ctx, network, resolved)
		}

		return dialer.DialContext(ctx, network, addr)
	}
}

// validateIP checks a single IP address against SSRF protection rules.
//
// The subnet classification itself lives in csar-core so that outbound clients
// which dial an operator allowlist (e.g. the coordinator's token minter) share
// exactly one definition of "internal address". Policy — which classes to
// block, and which hosts bypass checks entirely — stays here.
func validateIP(ip net.IP, p *SSRFProtection) error {
	return clientx.CheckInternalIP(ip, clientx.InternalIPClasses{
		Private:   p.BlockPrivate,
		Loopback:  p.BlockLoopback,
		LinkLocal: p.BlockLinkLocal,
		Metadata:  p.BlockMetadata,
	})
}
