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

// Package netutil provides shared network utilities for SSRF protection used
// across vespasian's crawl and probe stages. It is the single source of truth
// for the private-network CIDR list and the dial-time SSRF guard.
package netutil

import (
	"context"
	"fmt"
	"net"
)

// privateNetworks defines CIDR ranges considered private or internal.
// This is the canonical list shared by pkg/crawl and pkg/probe; both packages
// delegate to IsPrivateIP and SSRFSafeDialContext so the list only lives here.
var privateNetworks []*net.IPNet

func init() {
	cidrs := []string{
		"0.0.0.0/8",      // RFC 1122 "this host on this network" (0.x can address localhost on Linux)
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC 1918
		"100.64.0.0/10",  // RFC 6598 CGNAT / shared address space (carrier & cloud internal)
		"172.16.0.0/12",  // RFC 1918
		"192.168.0.0/16", // RFC 1918
		"169.254.0.0/16", // link-local (includes cloud metadata 169.254.169.254)
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

// IsPrivateIP reports whether ip falls within a private or internal network.
func IsPrivateIP(ip net.IP) bool {
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

// SSRFSafeDialContext is a net.Dialer DialContext replacement that re-resolves
// the target host and rejects the connection if any resolved IP is private or
// internal (SSRF protection). By performing the IP check at dial time — not
// only in the upfront scope/SSRF check — it closes the DNS-rebinding TOCTOU
// window: a short-TTL domain that resolves to a public IP during the scope
// check can be re-resolved to 127.0.0.1 or another private address by the
// time the dialer actually connects.
//
// It tries each validated IP in order, preserving Go's normal multi-IP fallback
// so a single dead A/AAAA record does not fail the dial when another validated
// address would connect.
func SSRFSafeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
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

	// Dial validated addresses directly (by IP, never re-resolving the host) to
	// prevent a TOCTOU re-resolve. Try each validated IP in order, preserving
	// Go's normal multi-IP fallback so a single dead A/AAAA record does not fail
	// the dial when another validated address would connect.
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
