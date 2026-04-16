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

import "testing"

func TestScopeChecker_SameOrigin(t *testing.T) {
	check, err := scopeChecker("https://example.com", "same-origin")
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
	check, err := scopeChecker("https://example.com:8443", "same-origin")
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
	check, err := scopeChecker("https://www.example.com", "same-domain")
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
	_, err := scopeChecker("://bad", "same-origin")
	if err == nil {
		t.Error("expected error for invalid seed URL")
	}
}

func TestScopeChecker_EmptySeedHost(t *testing.T) {
	_, err := scopeChecker("not-a-url", "same-origin")
	if err == nil {
		t.Error("expected error for seed URL without host")
	}
}

func TestScopeChecker_UnknownScopeDefaultsToSameOrigin(t *testing.T) {
	check, err := scopeChecker("https://example.com", "unknown-scope")
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
