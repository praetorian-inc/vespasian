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
	"net"
	"strings"
	"testing"
)

func TestScopeChecker_SameOrigin(t *testing.T) {
	check, err := scopeChecker("https://example.com", "same-origin", true)
	if err != nil {
		t.Fatalf("scopeChecker error: %v", err)
	}

	tests := []struct {
		name string
		url  string
		want bool
	}{
		{"exact match", "https://example.com/api/users", true},
		{"with path and query", "https://example.com/page?q=1", true},
		{"root", "https://example.com/", true},
		{"different scheme", "http://example.com/api", false},
		{"different host", "https://other.com/api", false},
		{"subdomain", "https://api.example.com/data", false},
		{"with port vs no port", "https://example.com:8443/api", false},
		{"empty string", "", false},
		{"javascript url", "javascript:void(0)", false},
		{"mailto", "mailto:test@example.com", false},
		{"data url", "data:text/html,<h1>hi</h1>", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := check(tt.url)
			if got != tt.want {
				t.Errorf("scopeCheck(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

func TestScopeChecker_SameOriginWithPort(t *testing.T) {
	check, err := scopeChecker("https://example.com:8443", "same-origin", true)
	if err != nil {
		t.Fatalf("scopeChecker error: %v", err)
	}

	tests := []struct {
		name string
		url  string
		want bool
	}{
		{"same port", "https://example.com:8443/api", true},
		{"different port", "https://example.com:9443/api", false},
		{"no port", "https://example.com/api", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := check(tt.url)
			if got != tt.want {
				t.Errorf("scopeCheck(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

func TestScopeChecker_SameDomain(t *testing.T) {
	check, err := scopeChecker("https://www.example.com", "same-domain", true)
	if err != nil {
		t.Fatalf("scopeChecker error: %v", err)
	}

	tests := []struct {
		name string
		url  string
		want bool
	}{
		{"exact match", "https://www.example.com/api", true},
		{"subdomain", "https://api.example.com/data", true},
		{"different subdomain", "https://cdn.example.com/asset.js", true},
		{"bare domain", "https://example.com/", true},
		{"http scheme allowed", "http://example.com/api", true},
		{"different domain", "https://other.com/api", false},
		{"similar suffix", "https://notexample.com/api", false},
		{"empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := check(tt.url)
			if got != tt.want {
				t.Errorf("scopeCheck(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

func TestScopeChecker_InvalidSeedURL(t *testing.T) {
	_, err := scopeChecker("://bad", "same-origin", true)
	if err == nil {
		t.Error("expected error for invalid seed URL")
	}
}

func TestScopeChecker_EmptySeedHost(t *testing.T) {
	_, err := scopeChecker("not-a-url", "same-origin", true)
	if err == nil {
		t.Error("expected error for seed URL without host")
	}
}

func TestScopeChecker_UnknownScopeDefaultsToSameOrigin(t *testing.T) {
	check, err := scopeChecker("https://example.com", "unknown-scope", true)
	if err != nil {
		t.Fatalf("scopeChecker error: %v", err)
	}

	// Same-origin behavior: subdomain should be rejected
	if check("https://api.example.com/data") {
		t.Error("unknown scope should default to same-origin (reject subdomains)")
	}
	if !check("https://example.com/api") {
		t.Error("unknown scope should default to same-origin (accept same host)")
	}
}

func TestNormalizeURL(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"strips fragment", "https://example.com/page#section", "https://example.com/page"},
		{"no fragment unchanged", "https://example.com/page", "https://example.com/page"},
		{"preserves query", "https://example.com/page?q=1#frag", "https://example.com/page?q=1"},
		{"empty string", "", ""},
		{"root path", "https://example.com/", "https://example.com/"},
		{"lowercases host", "https://Example.COM/Page", "https://example.com/Page"},
		{"lowercases scheme", "HTTP://example.com/page", "http://example.com/page"},
		{"removes default https port", "https://example.com:443/page", "https://example.com/page"},
		{"removes default http port", "http://example.com:80/page", "http://example.com/page"},
		{"preserves non-default port", "https://example.com:8443/page", "https://example.com:8443/page"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeURL(tt.input)
			if got != tt.want {
				t.Errorf("normalizeURL(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestRegisteredDomain(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		want    string
		wantErr bool
	}{
		{"simple domain", "example.com", "example.com", false},
		{"subdomain", "api.example.com", "example.com", false},
		{"deep subdomain", "a.b.c.example.com", "example.com", false},
		{"co.uk domain", "www.example.co.uk", "example.co.uk", false},
		{"bare TLD", "com", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := registeredDomain(tt.host)
			if tt.wantErr {
				if err == nil {
					t.Errorf("registeredDomain(%q) expected error, got %q", tt.host, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("registeredDomain(%q) unexpected error: %v", tt.host, err)
			}
			if got != tt.want {
				t.Errorf("registeredDomain(%q) = %q, want %q", tt.host, got, tt.want)
			}
		})
	}
}

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{"loopback v4", "127.0.0.1", true},
		{"loopback v4 other", "127.0.0.2", true},
		{"RFC1918 10.x", "10.0.0.1", true},
		{"RFC1918 172.16.x", "172.16.0.1", true},
		{"RFC1918 192.168.x", "192.168.1.1", true},
		{"link-local", "169.254.169.254", true},
		{"loopback v6", "::1", true},
		{"public IP", "93.184.215.14", false},
		{"public IP 2", "8.8.8.8", false},
		{"unspecified v4", "0.0.0.0", true},
		{"this-network 0.x", "0.1.2.3", true},
		{"CGNAT 100.64.x", "100.64.0.1", true},
		{"CGNAT 100.127.x", "100.127.255.254", true},
		{"public near-CGNAT 100.63.x", "100.63.255.255", false},
		{"public near-CGNAT 100.128.x", "100.128.0.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("failed to parse IP %q", tt.ip)
			}
			got := isPrivateIP(ip)
			if got != tt.want {
				t.Errorf("isPrivateIP(%q) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestIsPrivateHost_RawIPs(t *testing.T) {
	tests := []struct {
		name string
		host string
		want bool
	}{
		{"loopback", "127.0.0.1", true},
		{"cloud metadata", "169.254.169.254", true},
		{"RFC1918", "10.0.0.1", true},
		{"public", "93.184.215.14", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isPrivateHost(tt.host)
			if got != tt.want {
				t.Errorf("isPrivateHost(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}

func TestScopeChecker_SSRFProtection_RejectsPrivateIPs(t *testing.T) {
	check, err := scopeChecker("http://127.0.0.1:8080", "same-origin", false)
	if err != nil {
		t.Fatalf("scopeChecker error: %v", err)
	}

	if check("http://127.0.0.1:8080/api/users") {
		t.Error("expected SSRF protection to reject loopback URL")
	}
}

func TestScopeChecker_SSRFProtection_AllowPrivateBypass(t *testing.T) {
	check, err := scopeChecker("http://127.0.0.1:8080", "same-origin", true)
	if err != nil {
		t.Fatalf("scopeChecker error: %v", err)
	}

	if !check("http://127.0.0.1:8080/api/users") {
		t.Error("expected allowPrivate=true to permit loopback URL")
	}
}

func TestScopeChecker_SSRFProtection_RejectsMetadataIP(t *testing.T) {
	check, err := scopeChecker("http://169.254.169.254", "same-origin", false)
	if err != nil {
		t.Fatalf("scopeChecker error: %v", err)
	}

	if check("http://169.254.169.254/latest/meta-data/") {
		t.Error("expected SSRF protection to reject cloud metadata IP")
	}
}

// TestSSRFSafeDialContext_NoPort exercises the SplitHostPort error branch when
// the address has no port component (TEST-004).
func TestSSRFSafeDialContext_NoPort(t *testing.T) {
	ctx := context.Background()
	_, err := ssrfSafeDialContext(ctx, "tcp", "nohost")
	if err == nil {
		t.Fatal("expected error for address with no port, got nil")
	}
	if !strings.Contains(err.Error(), "invalid address") {
		t.Errorf("expected 'invalid address' in error, got: %v", err)
	}
}

// TestSSRFSafeDialContext_PrivateIPRejected exercises the private-IP rejection
// branch using a loopback address (TEST-004).
func TestSSRFSafeDialContext_PrivateIPRejected(t *testing.T) {
	ctx := context.Background()
	_, err := ssrfSafeDialContext(ctx, "tcp", "127.0.0.1:80")
	if err == nil {
		t.Fatal("expected error for private IP 127.0.0.1, got nil")
	}
	if !strings.Contains(err.Error(), "resolves to private IP") {
		t.Errorf("expected 'resolves to private IP' in error, got: %v", err)
	}
}

// TestSSRFSafeDialContext_DNSFailure exercises the DNS-failure branch using a
// guaranteed-NXDOMAIN hostname (.invalid is reserved by RFC 2606) (TEST-004).
func TestSSRFSafeDialContext_DNSFailure(t *testing.T) {
	ctx := context.Background()
	_, err := ssrfSafeDialContext(ctx, "tcp", "no-such-host.invalid:80")
	if err == nil {
		t.Fatal("expected error for NXDOMAIN host, got nil")
	}
	if !strings.Contains(err.Error(), "DNS lookup failed") {
		t.Errorf("expected 'DNS lookup failed' in error, got: %v", err)
	}
}

// Note: the dial-success path (public IP that actually connects) and the
// multi-IP fallback path require a reachable public endpoint and are therefore
// not unit-testable here — loopback is blocked by the SSRF guard itself.
// Those paths are covered by live/integration tests.

// TestFrontierKey verifies the frontier dedup key strips the query (and
// fragment) while keeping scheme/host/path canonicalization, so query-only
// variants share a key but distinct paths do not (LAB-4678 Phase 1).
func TestFrontierKey(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"https://example.com/p?id=1", "https://example.com/p"},
		{"https://example.com/p?id=2&ref=x", "https://example.com/p"},
		{"https://EXAMPLE.com:443/p?id=1#frag", "https://example.com/p"},
		{"https://example.com/other?id=1", "https://example.com/other"},
	}
	got := map[string]string{}
	for _, tc := range cases {
		k := frontierKey(tc.in)
		if k != tc.want {
			t.Errorf("frontierKey(%q) = %q, want %q", tc.in, k, tc.want)
		}
		got[tc.in] = k
	}
	// The two /p query variants must share a key; /other must differ.
	if got["https://example.com/p?id=1"] != got["https://example.com/p?id=2&ref=x"] {
		t.Errorf("query variants of /p produced different keys")
	}
	if got["https://example.com/p?id=1"] == got["https://example.com/other?id=1"] {
		t.Errorf("distinct paths collapsed to the same key")
	}
}
