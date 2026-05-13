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

// Well-known private/reserved subnets.
var (
	// RFC 1918 — Private IPv4
	private10  = mustParseCIDR("10.0.0.0/8")
	private172 = mustParseCIDR("172.16.0.0/12")
	private192 = mustParseCIDR("192.168.0.0/16")
	// RFC 3927 — Link-Local IPv4
	linkLocal4 = mustParseCIDR("169.254.0.0/16")
	// RFC 4291 — Link-Local IPv6
	linkLocal6 = mustParseCIDR("fe80::/10")
	// Cloud metadata endpoint
	metadataAddr = net.ParseIP("169.254.169.254")
)

func mustParseCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
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
func validateIP(ip net.IP, p *SSRFProtection) error {
	// Metadata check (most specific — check first).
	if p.BlockMetadata && ip.Equal(metadataAddr) {
		return fmt.Errorf("cloud metadata endpoint (169.254.169.254) is blocked")
	}

	// Loopback check.
	if p.BlockLoopback && ip.IsLoopback() {
		return fmt.Errorf("loopback address is blocked")
	}

	// Link-local check.
	if p.BlockLinkLocal {
		if linkLocal4.Contains(ip) || linkLocal6.Contains(ip) {
			return fmt.Errorf("link-local address is blocked")
		}
	}

	// Private subnet check.
	if p.BlockPrivate {
		if private10.Contains(ip) || private172.Contains(ip) || private192.Contains(ip) {
			return fmt.Errorf("private network address is blocked")
		}
	}

	// IPv6 private (unique local addresses fc00::/7).
	if p.BlockPrivate && len(ip) == net.IPv6len && ip[0]&0xfe == 0xfc {
		return fmt.Errorf("IPv6 unique local address is blocked")
	}

	return nil
}
