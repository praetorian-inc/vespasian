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
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"

	"golang.org/x/net/publicsuffix"

	"github.com/praetorian-inc/vespasian/pkg/ssrf"
)

// isPrivateIP delegates to pkg/ssrf.IsPrivateIP, the single source for the CIDR
// list shared with the probe stage.
func isPrivateIP(ip net.IP) bool {
	return ssrf.IsPrivateIP(ip)
}

// isPrivateHost resolves the host and reports true if any address is private,
// keeping the browser off internal endpoints.
func isPrivateHost(hostname string) bool {
	if ip := net.ParseIP(hostname); ip != nil {
		return isPrivateIP(ip)
	}

	addrs, err := net.LookupHost(hostname) //nolint:gosec // G704: intentional SSRF protection — taint flows to isPrivateHost check below
	if err != nil {
		// Fail closed.
		return true
	}
	for _, addr := range addrs {
		if ip := net.ParseIP(addr); ip != nil && isPrivateIP(ip) {
			return true
		}
	}
	return false
}

// scopeChecker returns an in-scope predicate. Unless allowPrivate, URLs resolving
// to private addresses are rejected, which matters when the engine runs as a
// service component.
//
//   - "same-origin": exact scheme, host and port
//   - "same-domain": registered domain, subdomains allowed
func scopeChecker(seedURL string, scope string, allowPrivate bool) (func(string) bool, error) {
	seed, err := url.Parse(seedURL)
	if err != nil {
		return nil, fmt.Errorf("parse seed URL: %w", err)
	}
	if seed.Host == "" {
		return nil, fmt.Errorf("seed URL has no host: %q", seedURL)
	}

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

// parseHTTPURL returns nil for invalid or non-HTTP(S) URLs.
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

// registeredDomain returns the eTLD+1: "api.example.com" -> "example.com".
func registeredDomain(host string) (string, error) {
	domain, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return "", err
	}
	return domain, nil
}

// ssrfSafeDialContext re-resolves at dial time, closing the DNS-rebinding TOCTOU
// window: a short-TTL domain can pass the upfront scope check as a public IP and
// resolve to 127.0.0.1 by the time client.Do dials. Delegates to
// pkg/ssrf.SafeDialContext, shared with pkg/probe.
func ssrfSafeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return ssrf.SafeDialContext(ctx, network, addr)
}

// normalizeURL lowercases scheme and host, strips the fragment and drops default
// ports, for dedup. "" if unparseable.
func normalizeURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	u.Fragment = ""
	u.Host = strings.ToLower(u.Host)
	u.Scheme = strings.ToLower(u.Scheme)

	// Or example.com and example.com:443 dedup as different URLs.
	hostname := u.Hostname()
	port := u.Port()
	if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
		u.Host = hostname
	}

	return u.String()
}
