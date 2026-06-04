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

	"github.com/praetorian-inc/vespasian/internal/netutil"
)

// isPrivateIP reports whether ip falls within a private or internal network range.
// It delegates to internal/netutil.IsPrivateIP, which is the single source of
// truth for the CIDR list shared by the crawl and probe stages.
func isPrivateIP(ip net.IP) bool {
	return netutil.IsPrivateIP(ip)
}

// ValidateProbeURL checks that rawURL is safe to probe. It rejects non-HTTP(S)
// schemes and URLs that resolve to private/internal IP addresses (SSRF protection).
func ValidateProbeURL(rawURL string) error {
	return validateProbeURL(rawURL)
}

// validateProbeURL is the internal implementation of ValidateProbeURL.
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

// SSRFSafeDialContext is a net.Dialer DialContext replacement that re-checks
// resolved IPs against the SSRF blocklist at connect time, preventing TOCTOU
// DNS rebinding attacks.
func SSRFSafeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return ssrfSafeDialContext(ctx, network, addr)
}

// ssrfSafeDialContext is the internal implementation of SSRFSafeDialContext.
// It delegates to internal/netutil.SSRFSafeDialContext, which uses the multi-IP
// fallback version (tries each validated IP in order) so a single dead A/AAAA
// record does not fail the dial when another validated address would connect.
func ssrfSafeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return netutil.SSRFSafeDialContext(ctx, network, addr)
}
