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

// Package ssrf provides URL validation and SSRF-safe dialing primitives that
// reject private/loopback/link-local destinations. It exists as a leaf
// package so any package that needs to make outbound HTTP requests
// (pkg/probe, pkg/crawl) can depend on it without creating an import cycle.
package ssrf

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"time"
)

// privateNetworks defines CIDR ranges that are considered private or internal.
// Includes RFC 1918, loopback, link-local, CGNAT, multicast, broadcast, and
// IETF-reserved ranges so a single check covers everything an attacker could
// reasonably use to reach inside the operator's network from a hostile JS bundle.
var privateNetworks []*net.IPNet

// dnsLookupTimeout caps the DNS lookup performed by ValidateURL when no caller
// context is provided. ValidateURLContext lets callers supply their own ctx.
const dnsLookupTimeout = 5 * time.Second

func init() {
	cidrs := []string{
		// IPv4 reserved
		"0.0.0.0/8",       // RFC 1122 "this network"
		"10.0.0.0/8",      // RFC 1918
		"100.64.0.0/10",   // RFC 6598 CGNAT
		"127.0.0.0/8",     // loopback
		"169.254.0.0/16",  // link-local (incl. AWS/GCP metadata)
		"172.16.0.0/12",   // RFC 1918
		"192.0.0.0/24",    // IETF protocol assignments
		"192.0.2.0/24",    // TEST-NET-1
		"192.168.0.0/16",  // RFC 1918
		"198.18.0.0/15",   // RFC 2544 benchmarking
		"198.51.100.0/24", // TEST-NET-2
		"203.0.113.0/24",  // TEST-NET-3
		"224.0.0.0/4",     // multicast
		"240.0.0.0/4",     // Class E reserved (also covers 255.255.255.255)
		// IPv6 reserved
		"::1/128",      // loopback
		"fe80::/10",    // link-local
		"fc00::/7",     // ULA (covers fd00:ec2::/32 AWS IPv6 IMDS)
		"2002::/16",    // 6to4 (can wrap embedded IPv4)
		"64:ff9b::/96", // well-known NAT64
	}
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			panic("invalid CIDR in privateNetworks: " + cidr)
		}
		privateNetworks = append(privateNetworks, network)
	}
}

// IsPrivateIP reports whether ip falls within a private or internal network range.
// A nil or zero-length IP is treated as private (fail-closed) so callers cannot
// accidentally treat unparsed addresses as public.
func IsPrivateIP(ip net.IP) bool {
	if len(ip) == 0 {
		return true
	}
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

// ValidateURL checks that rawURL is safe to probe. It rejects non-HTTP(S)
// schemes and URLs that resolve to private/internal IP addresses. DNS lookups
// are bounded by dnsLookupTimeout. Use ValidateURLContext to bind the lookup
// to a caller-supplied deadline.
func ValidateURL(rawURL string) error {
	ctx, cancel := context.WithTimeout(context.Background(), dnsLookupTimeout)
	defer cancel()
	return ValidateURLContext(ctx, rawURL)
}

// ValidateURLContext is like ValidateURL but uses the caller's context for the
// DNS lookup. Pass the loop-level context so a JS bundle full of slow/black-holed
// hostnames cannot stall the whole replay step.
func ValidateURLContext(ctx context.Context, rawURL string) error {
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
		if IsPrivateIP(ip) {
			return fmt.Errorf("blocked private/internal IP %s", ip)
		}
		return nil
	}

	// Resolve hostname via DNS and check all returned addresses.
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, hostname)
	if err != nil {
		return fmt.Errorf("DNS lookup failed for %q: %w", hostname, err)
	}

	for _, addr := range addrs {
		if IsPrivateIP(addr.IP) {
			return fmt.Errorf("hostname %q resolves to blocked private/internal IP %s", hostname, addr.IP)
		}
	}

	return nil
}

// SafeDialContext is a net.Dialer DialContext replacement that re-checks
// resolved IPs against the SSRF blocklist at connect time, preventing TOCTOU
// DNS rebinding attacks. It dials the resolved IPs in order and returns the
// first successful connection, mirroring net.Dialer's standard fallback
// behavior on dual-stack hosts.
//
// Note: HTTPS clients using this DialContext keep TLS SNI bound to the URL's
// hostname (Go's http.Transport derives SNI from the request URL, not the
// dialed address) so certificate verification continues to work.
func SafeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
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
		if IsPrivateIP(ip.IP) {
			return nil, fmt.Errorf("blocked: %s resolves to private IP %s", host, ip.IP)
		}
	}

	// Dial each resolved address in order; return the first success.
	dialer := &net.Dialer{}
	var lastErr error
	for _, ip := range ips {
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.IP.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}
