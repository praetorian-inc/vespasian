// Copyright 2026 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package probe

import (
	"context"
	"fmt"
	"net"
	"net/url"
)

// privateNetworks defines CIDR ranges that are considered private or internal.
var privateNetworks []*net.IPNet

func init() {
	cidrs := []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC 1918
		"172.16.0.0/12",  // RFC 1918
		"192.168.0.0/16", // RFC 1918
		"169.254.0.0/16", // link-local
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 ULA
	}
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			panic("invalid CIDR in privateNetworks: " + cidr)
		}
		privateNetworks = append(privateNetworks, network)
	}
}

// isPrivateIP reports whether ip falls within a private or internal network range.
func isPrivateIP(ip net.IP) bool {
	if ip.IsUnspecified() {
		return true
	}
	for _, network := range privateNetworks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// validateProbeURL checks that rawURL is safe to probe. It rejects non-HTTP(S)
// schemes and URLs that resolve to private/internal IP addresses (SSRF protection).
func validateProbeURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("unsupported scheme %q: only http and https are allowed", u.Scheme)
	}

	hostname := u.Hostname()

	// Check if the hostname is already a raw IP address to avoid unnecessary DNS lookups.
	if ip := net.ParseIP(hostname); ip != nil {
		if isPrivateIP(ip) {
			return fmt.Errorf("blocked private/internal IP %s", ip)
		}
		return nil
	}

	// Resolve hostname via DNS and check all returned addresses.
	addrs, err := net.LookupHost(hostname)
	if err != nil {
		return fmt.Errorf("DNS lookup failed for %q: %w", hostname, err)
	}

	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip != nil && isPrivateIP(ip) {
			return fmt.Errorf("hostname %q resolves to blocked private/internal IP %s", hostname, ip)
		}
	}

	return nil
}

// ssrfSafeDialContext is a net.Dialer DialContext replacement that re-checks
// resolved IPs against the SSRF blocklist at connect time, preventing TOCTOU
// DNS rebinding attacks.
func ssrfSafeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address %q: %w", addr, err)
	}

	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("DNS lookup failed for %q: %w", host, err)
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("DNS lookup for %q returned no addresses", host)
	}

	for _, ip := range ips {
		if isPrivateIP(ip.IP) {
			return nil, fmt.Errorf("blocked: %s resolves to private IP %s", host, ip.IP)
		}
	}

	// Dial the first resolved address.
	dialer := &net.Dialer{}
	return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
}
