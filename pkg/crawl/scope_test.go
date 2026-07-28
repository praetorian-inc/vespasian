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
	"bytes"
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

// TestCanonicalizeURL_KeepQuery covers canonicalizeURL in its query-preserving
// mode. It used to test the normalizeURL wrapper, which was removed once
// urlFrontier.Push switched to frontierKey and left it with no production caller.
func TestCanonicalizeURL_KeepQuery(t *testing.T) {
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
			got := canonicalizeURL(tt.input, false)
			if got != tt.want {
				t.Errorf("canonicalizeURL(%q, false) = %q, want %q", tt.input, got, tt.want)
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

// TestSeedScope_LearnsEffectiveOrigin is the unit-level pin for the
// cross-origin-seed-redirect fix. With a same-origin policy, a URL on the origin
// the seed actually resolved to must be in scope once that origin is learned, and
// out of scope before — otherwise every request Chrome captures after following
// the seed's redirect is discarded and the crawl yields an empty capture.
func TestSeedScope_LearnsEffectiveOrigin(t *testing.T) {
	var stderr bytes.Buffer
	s, err := newSeedScope("http://example.com", "same-origin", true, &stderr)
	if err != nil {
		t.Fatalf("newSeedScope: %v", err)
	}

	const post = "https://www.example.com/api/users"
	if s.Check(post) {
		t.Fatal("post-redirect origin in scope before the redirect was observed")
	}
	if !s.Check("http://example.com/api/users") {
		t.Fatal("seed origin not in scope")
	}

	s.LearnEffectiveOrigin("https://www.example.com/")

	if !s.Check(post) {
		t.Error("post-redirect origin still out of scope after LearnEffectiveOrigin")
	}
	// Widening is bounded to that one origin: nothing else is admitted.
	for _, u := range []string{
		"https://attacker.test/x",
		"https://other.example.com/x", // a sibling host is NOT implied
		"https://www.example.com:8443/x",
	} {
		if s.Check(u) {
			t.Errorf("Check(%q) = true, want false (widening must add exactly one origin)", u)
		}
	}
	// And it is announced, not silent.
	if !strings.Contains(stderr.String(), "https://www.example.com") {
		t.Errorf("scope widening not reported on stderr; got %q", stderr.String())
	}
}

// TestSeedScope_LearnIsOneShot pins the containment bound: only the seed's FIRST
// navigation may widen scope. A later call — a resumed depth-0 entry, a retry, or
// any future caller — must not be able to add a second origin.
func TestSeedScope_LearnIsOneShot(t *testing.T) {
	s, err := newSeedScope("http://example.com", "same-origin", true, nil)
	if err != nil {
		t.Fatalf("newSeedScope: %v", err)
	}
	s.LearnEffectiveOrigin("https://www.example.com/")
	s.LearnEffectiveOrigin("https://attacker.test/")
	if s.Check("https://attacker.test/x") {
		t.Error("a second LearnEffectiveOrigin call widened scope again")
	}
	if !s.Check("https://www.example.com/x") {
		t.Error("the first learned origin was lost")
	}
}

// TestSeedScope_LearnNoopOnSameOrigin verifies the common case adds nothing: a
// seed that redirects within its own origin (or not at all) leaves the accepted
// set exactly as configured, and says nothing on stderr.
func TestSeedScope_LearnNoopOnSameOrigin(t *testing.T) {
	var stderr bytes.Buffer
	s, err := newSeedScope("https://example.com/start", "same-origin", true, &stderr)
	if err != nil {
		t.Fatalf("newSeedScope: %v", err)
	}
	// Same origin in explicit-port form: must be recognized as unchanged.
	s.LearnEffectiveOrigin("https://example.com:443/app/")
	if s.effOrigin != "" {
		t.Errorf("effOrigin = %q, want empty (no widening for a same-origin redirect)", s.effOrigin)
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty", stderr.String())
	}
}

// TestSeedScope_RefusesPrivateEffectiveOrigin verifies the gates still hold over
// the widened origin: a seed that redirects to a private host on a DIFFERENT
// domain must not pull that host into scope. Since the Codex review of PR #189
// the domain constraint is checked first, so this is refused as a foreign domain
// rather than as a private origin — either way it stays out of scope, and it is
// now refused even with --dangerous-allow-private, because a cross-domain
// redirect is not what the seed widening exists for.
func TestSeedScope_RefusesPrivateEffectiveOrigin(t *testing.T) {
	var stderr bytes.Buffer
	s, err := newSeedScope("https://example.com", "same-origin", false, &stderr)
	if err != nil {
		t.Fatalf("newSeedScope: %v", err)
	}
	s.LearnEffectiveOrigin("http://127.0.0.1:8080/")
	if s.Check("http://127.0.0.1:8080/admin") {
		t.Error("private effective origin was admitted without --dangerous-allow-private")
	}
	if !strings.Contains(stderr.String(), "different domain") {
		t.Errorf("cross-domain refusal not reported; stderr = %q", stderr.String())
	}
}

// TestSeedScope_RefusesPrivateSameDomainOrigin exercises the SSRF gate on the
// path that now reaches it: the redirect target shares the seed's registrable
// domain, so the domain constraint passes and the private-host check is what
// refuses it. This is the case where the --dangerous-allow-private hint is the
// useful diagnostic.
func TestSeedScope_RefusesPrivateSameDomainOrigin(t *testing.T) {
	var stderr bytes.Buffer
	s, err := newSeedScope("https://intranet.example.com", "same-origin", false, &stderr)
	if err != nil {
		t.Fatalf("newSeedScope: %v", err)
	}
	// Same registrable domain (example.com), but the host resolves privately.
	s.LearnEffectiveOrigin("https://localhost.example.com/")
	if !strings.Contains(stderr.String(), "private origin") {
		t.Skipf("host does not resolve privately in this environment; stderr = %q", stderr.String())
	}
	if s.Check("https://localhost.example.com/admin") {
		t.Error("private same-domain origin was admitted without --dangerous-allow-private")
	}
}

// TestSeedScope_RefusesForeignDomainRedirect is the containment case from the
// Codex review: an IdP hand-off or an open redirect on the seed must not become
// crawl scope. Before the fix the foreign origin was admitted after only the
// private-host check, so any external redirect target joined the crawl.
func TestSeedScope_RefusesForeignDomainRedirect(t *testing.T) {
	var stderr bytes.Buffer
	s, err := newSeedScope("https://target.example.com", "same-origin", false, &stderr)
	if err != nil {
		t.Fatalf("newSeedScope: %v", err)
	}
	s.LearnEffectiveOrigin("https://idp.attacker.test/authorize")
	if s.Check("https://idp.attacker.test/anything") {
		t.Error("a seed redirect to a foreign registrable domain widened the crawl scope")
	}
	if !strings.Contains(stderr.String(), "different domain") {
		t.Errorf("cross-domain refusal not reported; stderr = %q", stderr.String())
	}
}

// TestSeedScope_AllowsIntendedWidenings pins that the constraint does not break
// the two deployments the widening exists for: http -> https on the same host,
// and apex -> www on the same registrable domain.
func TestSeedScope_AllowsIntendedWidenings(t *testing.T) {
	t.Run("http to https", func(t *testing.T) {
		s, err := newSeedScope("http://example.com", "same-origin", false, nil)
		if err != nil {
			t.Fatalf("newSeedScope: %v", err)
		}
		s.LearnEffectiveOrigin("https://example.com/")
		if !s.Check("https://example.com/dashboard") {
			t.Error("http -> https seed redirect must stay crawlable")
		}
	})

	t.Run("apex to www", func(t *testing.T) {
		s, err := newSeedScope("https://example.com", "same-origin", false, nil)
		if err != nil {
			t.Fatalf("newSeedScope: %v", err)
		}
		s.LearnEffectiveOrigin("https://www.example.com/")
		if !s.Check("https://www.example.com/dashboard") {
			t.Error("apex -> www seed redirect must stay crawlable")
		}
	})
}
