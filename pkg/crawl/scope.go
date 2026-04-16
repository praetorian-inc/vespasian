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

package crawl

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// privateNetworks defines CIDR ranges considered private or internal.
// This mirrors the list in pkg/probe/validate.go to provide consistent
// SSRF protection across both the crawl and probe stages.
var privateNetworks []*net.IPNet

func init() {
	cidrs := []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC 1918
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

// isPrivateIP reports whether ip falls within a private or internal network.
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

// isPrivateHost resolves a hostname via DNS and returns true if any of the
// resolved IPs are private/internal. Also returns true for raw IP addresses
// in private ranges. This prevents the browser from navigating to internal
// network endpoints (SSRF protection).
func isPrivateHost(hostname string) bool {
	// Check if it's already a raw IP address.
	if ip := net.ParseIP(hostname); ip != nil {
		return isPrivateIP(ip)
	}

	// Resolve and check all addresses.
	addrs, err := net.LookupHost(hostname)
	if err != nil {
		// DNS failure — reject to be safe.
		return true
	}
	for _, addr := range addrs {
		if ip := net.ParseIP(addr); ip != nil && isPrivateIP(ip) {
			return true
		}
	}
	return false
}

// scopeChecker returns a function that checks whether a URL is in scope
// relative to the seed URL, based on the scope policy. Unless allowPrivate
// is true, URLs that resolve to private/internal IP addresses are rejected
// to prevent SSRF attacks when the crawl engine runs as a service component.
//
// Scope policies:
//   - "same-origin": exact scheme + host + port match (equivalent to Katana's fqdn)
//   - "same-domain": registered domain match, allowing subdomains (equivalent to Katana's rdn)
func scopeChecker(seedURL string, scope string, allowPrivate bool) (func(string) bool, error) {
	seed, err := url.Parse(seedURL)
	if err != nil {
		return nil, fmt.Errorf("parse seed URL: %w", err)
	}
	if seed.Host == "" {
		return nil, fmt.Errorf("seed URL has no host: %q", seedURL)
	}

	// ssrfCheck returns false (reject) if the URL resolves to a private IP.
	ssrfCheck := func(u *url.URL) bool {
		if allowPrivate {
			return true
		}
		return !isPrivateHost(u.Hostname())
	}

	switch scope {
	case "same-domain":
		seedDomain, err := registeredDomain(seed.Hostname())
		if err != nil {
			return nil, fmt.Errorf("extract registered domain: %w", err)
		}
		return func(rawURL string) bool {
			u := parseHTTPURL(rawURL)
			if u == nil {
				return false
			}
			d, err := registeredDomain(u.Hostname())
			if err != nil {
				return false
			}
			return strings.EqualFold(d, seedDomain) && ssrfCheck(u)
		}, nil

	default: // "same-origin" and any unknown value
		seedOrigin := seed.Scheme + "://" + seed.Host
		return func(rawURL string) bool {
			u := parseHTTPURL(rawURL)
			if u == nil {
				return false
			}
			return (u.Scheme+"://"+u.Host) == seedOrigin && ssrfCheck(u)
		}, nil
	}
}

// parseHTTPURL parses a URL and returns nil if it is invalid or not HTTP(S).
func parseHTTPURL(rawURL string) *url.URL {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return nil
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil
	}
	return u
}

// registeredDomain extracts the eTLD+1 (registered domain) from a hostname.
// For example, "api.example.com" returns "example.com".
func registeredDomain(host string) (string, error) {
	domain, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return "", err
	}
	return domain, nil
}

// normalizeURL normalizes a URL for deduplication by lowercasing the scheme
// and host, stripping fragments, and removing default ports.
// It returns the empty string for unparseable URLs.
func normalizeURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	u.Fragment = ""
	u.Host = strings.ToLower(u.Host)
	u.Scheme = strings.ToLower(u.Scheme)

	// Remove default ports to avoid treating example.com and example.com:443 as different.
	hostname := u.Hostname()
	port := u.Port()
	if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
		u.Host = hostname
	}

	return u.String()
}
