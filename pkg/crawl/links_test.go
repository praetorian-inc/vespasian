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

func TestResolveURL_Absolute(t *testing.T) {
	got, err := resolveURL("https://example.com/page", "https://example.com/other")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "https://example.com/other" {
		t.Errorf("got %q, want %q", got, "https://example.com/other")
	}
}

func TestResolveURL_Relative(t *testing.T) {
	got, err := resolveURL("https://example.com/dir/page", "other")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "https://example.com/dir/other" {
		t.Errorf("got %q, want %q", got, "https://example.com/dir/other")
	}
}

func TestResolveURL_RootRelative(t *testing.T) {
	got, err := resolveURL("https://example.com/dir/page", "/api/users")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "https://example.com/api/users" {
		t.Errorf("got %q, want %q", got, "https://example.com/api/users")
	}
}

func TestResolveURL_ProtocolRelative(t *testing.T) {
	got, err := resolveURL("https://example.com/page", "//cdn.example.com/asset.js")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "https://cdn.example.com/asset.js" {
		t.Errorf("got %q, want %q", got, "https://cdn.example.com/asset.js")
	}
}

func TestResolveURL_StripsFragment(t *testing.T) {
	got, err := resolveURL("https://example.com/page", "/other#section")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "https://example.com/other" {
		t.Errorf("got %q, want %q", got, "https://example.com/other")
	}
}

func TestResolveURL_JavascriptScheme(t *testing.T) {
	_, err := resolveURL("https://example.com/page", "javascript:void(0)")
	if err == nil {
		t.Error("expected error for javascript: URL")
	}
}

func TestResolveURL_MailtoScheme(t *testing.T) {
	_, err := resolveURL("https://example.com/page", "mailto:test@example.com")
	if err == nil {
		t.Error("expected error for mailto: URL")
	}
}

func TestResolveURL_DataScheme(t *testing.T) {
	_, err := resolveURL("https://example.com/page", "data:text/html,<h1>hi</h1>")
	if err == nil {
		t.Error("expected error for data: URL")
	}
}

func TestResolveURL_Empty(t *testing.T) {
	_, err := resolveURL("https://example.com/page", "")
	if err == nil {
		t.Error("expected error for empty reference")
	}
}

func TestResolveURL_WhitespaceRef(t *testing.T) {
	_, err := resolveURL("https://example.com/page", "   ")
	if err == nil {
		t.Error("expected error for whitespace-only reference")
	}
}

func TestResolveURL_FTPScheme(t *testing.T) {
	_, err := resolveURL("https://example.com/page", "ftp://files.example.com/data")
	if err == nil {
		t.Error("expected error for ftp: URL")
	}
}

func TestResolveURL_PreservesQuery(t *testing.T) {
	got, err := resolveURL("https://example.com/page", "/search?q=test&page=1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "https://example.com/search?q=test&page=1" {
		t.Errorf("got %q, want %q", got, "https://example.com/search?q=test&page=1")
	}
}

func TestResolveURL_TelScheme(t *testing.T) {
	_, err := resolveURL("https://example.com/page", "tel:+1234567890")
	if err == nil {
		t.Error("expected error for tel: URL")
	}
}

// --- Base-href awareness (LAB-2221 Issue A) -----------------------------

// Regression: when an SPA page is served under a deep path but declares
// <base href="/">, relative script/link paths must resolve against the
// base (producing /main.js) instead of the page URL (which would produce
// /walletExploitAddress/socket.io/main.js).
func TestResolveURL_BaseHrefRoot(t *testing.T) {
	got, err := resolveURL("https://example.com/", "main.js")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "https://example.com/main.js" {
		t.Errorf("got %q, want %q", got, "https://example.com/main.js")
	}
}

// --- isLikelyPage asset filter (LAB-2221) -------------------------------

func TestIsLikelyPage_AcceptsHTMLPaths(t *testing.T) {
	cases := []string{
		"https://example.com/",
		"https://example.com/login",
		"https://example.com/api/users",
		"https://example.com/path/with.dots/resource",
		"https://example.com/#/product/1",
		"https://example.com/search?q=test",
	}
	for _, c := range cases {
		if !isLikelyPage(c) {
			t.Errorf("isLikelyPage(%q) = false, want true", c)
		}
	}
}

func TestIsLikelyPage_RejectsAssetExtensions(t *testing.T) {
	cases := []string{
		"https://example.com/main.js",
		"https://example.com/polyfills.mjs",
		"https://example.com/chunk-ABCDE.js",
		"https://example.com/styles.css",
		"https://example.com/main.js.map",
		"https://example.com/assets/public/favicon_js.ico",
		"https://example.com/assets/public/images/JuiceShop_Logo.png",
		"https://example.com/assets/font.woff2",
		"https://example.com/doc.pdf",
		"https://example.com/archive.zip",
	}
	for _, c := range cases {
		if isLikelyPage(c) {
			t.Errorf("isLikelyPage(%q) = true, want false", c)
		}
	}
}

func TestIsLikelyPage_RejectsStreamingEndpoints(t *testing.T) {
	// These endpoints return the SPA catch-all HTML on Juice Shop when
	// hit via GET without the right protocol handshake; navigating to
	// them would trigger recursive path nesting through relative asset
	// references.
	cases := []string{
		"http://localhost:3000/socket.io/",
		"http://localhost:3000/socket.io/?EIO=4&transport=polling&t=abc",
		"http://localhost:3000/engine.io/socket.io/",
	}
	for _, c := range cases {
		if isLikelyPage(c) {
			t.Errorf("isLikelyPage(%q) = true, want false", c)
		}
	}
}

func TestIsLikelyPage_IsCaseInsensitive(t *testing.T) {
	if isLikelyPage("https://example.com/BUNDLE.JS") {
		t.Error("isLikelyPage should be case-insensitive on extensions")
	}
	if isLikelyPage("https://example.com/IMAGE.PNG") {
		t.Error("isLikelyPage should be case-insensitive on extensions")
	}
}

func TestIsLikelyPage_UnparseableInputIsPermissive(t *testing.T) {
	// Weird/unparseable URLs are passed through — the frontier and scope
	// checker are authoritative; isLikelyPage only filters obvious assets.
	// net/url.Parse is extremely lenient, so just verify the default.
	if !isLikelyPage("") {
		t.Error("isLikelyPage(\"\") = false, want true (permissive default)")
	}
}
