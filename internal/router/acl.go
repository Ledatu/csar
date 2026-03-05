package router

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// checkIPAccess returns true if the request is allowed by IP access control.
// Per-route ACL overrides global. If neither is configured, all IPs are allowed.
// trust_proxy is always route-scoped — no global side effects.
func (r *Router) checkIPAccess(rt *route, req *http.Request) bool {
	var cidrs []*net.IPNet
	if rt.hasRouteACL {
		cidrs = rt.allowCIDRs
	} else if r.hasGlobalACL {
		cidrs = r.globalCIDRs
	} else {
		return true // no ACL configured
	}

	clientIP := extractClientIP(req, rt.trustProxy)
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false // unparseable IP is denied
	}

	for _, cidr := range cidrs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// extractClientIP gets the client IP from the request.
// If trustProxy is true, X-Forwarded-For and X-Real-IP are checked first.
//
// SECURITY: We take the RIGHTMOST IP in X-Forwarded-For, because the last
// proxy in the chain appends the real client IP. Taking the leftmost is
// trivially spoofable: an attacker sends "X-Forwarded-For: spoofed, real"
// and the proxy appends the actual IP, making leftmost the spoofed one.
//
// This is a package-level function (not a method) since trust is route-scoped.
func extractClientIP(req *http.Request, trustProxy bool) string {
	if trustProxy {
		// X-Forwarded-For: client, proxy1, proxy2
		// The rightmost IP is the one appended by the last (trusted) proxy.
		if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			// Walk from right to left, take the first non-empty entry.
			for i := len(parts) - 1; i >= 0; i-- {
				ip := strings.TrimSpace(parts[i])
				if ip != "" {
					return ip
				}
			}
		}
		if xri := req.Header.Get("X-Real-IP"); xri != "" {
			return strings.TrimSpace(xri)
		}
	}

	// Fall back to RemoteAddr (host:port)
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr // best effort
	}
	return host
}

// parseCIDRList parses a list of IP addresses and CIDR ranges into []*net.IPNet.
// Plain IPs are converted to /32 (IPv4) or /128 (IPv6).
func parseCIDRList(entries []string) ([]*net.IPNet, error) {
	var nets []*net.IPNet
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		if strings.Contains(entry, "/") {
			_, ipNet, err := net.ParseCIDR(entry)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q: %w", entry, err)
			}
			nets = append(nets, ipNet)
		} else {
			ip := net.ParseIP(entry)
			if ip == nil {
				return nil, fmt.Errorf("invalid IP address %q", entry)
			}
			// Convert plain IP to /32 or /128
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			nets = append(nets, &net.IPNet{
				IP:   ip,
				Mask: net.CIDRMask(bits, bits),
			})
		}
	}
	return nets, nil
}
