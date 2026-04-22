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

// effectiveBaseURLFrom is the pure URL-resolution core of effectiveBaseURL.
// These tests cover the behavior that makes the LAB-2221 fix a red-green
// regression against the pre-fix code: pre-fix, extractLinks never read
// <base href> at all and always resolved against the page URL, so a <base
// href="/"> on a deep page URL had no effect. The happy-path case below
// would have returned "https://ex.com/deep/page/here" before the fix.
func TestEffectiveBaseURLFrom_HappyPath(t *testing.T) {
	got := effectiveBaseURLFrom("/", "https://ex.com/deep/page/here")
	if got != "https://ex.com/" {
		t.Errorf("got %q, want %q", got, "https://ex.com/")
	}
}

// Cross-host absolute base is rejected — the SEC-BE-001 cross-host guard.
// Previously this returned the CDN URL; now it must return pageURL because
// cdn.example.com differs from ex.com.
func TestEffectiveBaseURLFrom_RejectsCrossHostAbsoluteBase(t *testing.T) {
	got := effectiveBaseURLFrom("https://cdn.example.com/app/", "https://ex.com/page")
	if got != "https://ex.com/page" {
		t.Errorf("got %q, want %q", got, "https://ex.com/page")
	}
}

func TestEffectiveBaseURLFrom_RelativeBase(t *testing.T) {
	got := effectiveBaseURLFrom("../api/", "https://ex.com/deep/page/")
	if got != "https://ex.com/deep/api/" {
		t.Errorf("got %q, want %q", got, "https://ex.com/deep/api/")
	}
}

// Empty/whitespace/nil href all fall back to the page URL.
func TestEffectiveBaseURLFrom_EmptyHref(t *testing.T) {
	for _, in := range []string{"", "   ", "\t\n "} {
		got := effectiveBaseURLFrom(in, "https://ex.com/page")
		if got != "https://ex.com/page" {
			t.Errorf("effectiveBaseURLFrom(%q, ...) = %q, want page URL", in, got)
		}
	}
}

// Non-http(s) base schemes are rejected — attacker-controlled <base
// href="javascript:..."> or <base href="data:..."> must not become the
// resolution anchor for relative refs.
func TestEffectiveBaseURLFrom_DisallowedSchemes(t *testing.T) {
	cases := []string{
		"javascript:void(0)",
		"data:text/html,x",
		"file:///etc/passwd",
		"ftp://files.example.com/",
	}
	for _, in := range cases {
		got := effectiveBaseURLFrom(in, "https://ex.com/page")
		if got != "https://ex.com/page" {
			t.Errorf("effectiveBaseURLFrom(%q, ...) = %q, want page URL", in, got)
		}
	}
}

// SEC-BE-001 regression: a page served over HTTPS must not accept an
// http:// <base href> — that would downgrade every relative reference on
// the page to plaintext and leak any operator-supplied auth headers or
// session cookies. The reverse (https base on http page) is safe.
func TestEffectiveBaseURLFrom_RejectsSchemeDowngrade(t *testing.T) {
	got := effectiveBaseURLFrom("http://target.com/", "https://target.com/page")
	if got != "https://target.com/page" {
		t.Errorf("downgrade not rejected: got %q, want %q", got, "https://target.com/page")
	}
}

func TestEffectiveBaseURLFrom_AllowsUpgrade(t *testing.T) {
	got := effectiveBaseURLFrom("https://target.com/", "http://target.com/page")
	if got != "https://target.com/" {
		t.Errorf("scheme upgrade wrongly rejected: got %q, want %q", got, "https://target.com/")
	}
}

// Same-host absolute base is accepted — a page at target.com declaring
// <base href="https://target.com/app/"> must still honor the deeper base,
// this is only disallowed when the host differs.
func TestEffectiveBaseURLFrom_AcceptsSameHostAbsoluteBase(t *testing.T) {
	got := effectiveBaseURLFrom("https://ex.com/app/", "https://ex.com/page")
	if got != "https://ex.com/app/" {
		t.Errorf("got %q, want %q", got, "https://ex.com/app/")
	}
}

// SEC-BE-001 regression: an in-scope page that declares a <base href> on
// a different host (e.g., <base href="https://attacker.com/"> on a
// target.com page, via stored XSS or attacker-owned subdomain) must not
// re-anchor relative references to attacker.com. Doing so would poison
// capture.json / the produced spec with attacker-host endpoints, since
// synthetic form ObservedRequests are appended without a scope filter at
// this stage. Pin the behaviour so this guard is not silently removed.
func TestEffectiveBaseURLFrom_RejectsCrossHostBase(t *testing.T) {
	got := effectiveBaseURLFrom("https://attacker.com/", "https://target.com/login")
	if got != "https://target.com/login" {
		t.Errorf("cross-host base not rejected: got %q, want %q", got, "https://target.com/login")
	}
}

func TestEffectiveBaseURLFrom_HostCompareIsCaseInsensitive(t *testing.T) {
	got := effectiveBaseURLFrom("https://EX.COM/app/", "https://ex.com/page")
	if got != "https://EX.COM/app/" {
		t.Errorf("case-only host mismatch wrongly rejected: got %q, want %q", got, "https://EX.COM/app/")
	}
}

// Port-different same-hostname is treated as cross-host because url.Host
// includes the port. A <base href="https://ex.com:8443/"> on a page
// served from https://ex.com/page is rejected. This is conservative —
// a well-intentioned refactor to compare hostname-only (stripping the
// port) would silently accept port-different bases, which we do not
// want for our threat model. Pin the behaviour.
func TestEffectiveBaseURLFrom_PortDifferentIsCrossHost(t *testing.T) {
	got := effectiveBaseURLFrom("https://ex.com:8443/", "https://ex.com/page")
	if got != "https://ex.com/page" {
		t.Errorf("port-different base not rejected: got %q, want %q", got, "https://ex.com/page")
	}
}

// Cross-host protocol-relative base is rejected — the SEC-BE-001 cross-host
// guard applies to protocol-relative forms too. Previously this returned the
// CDN URL; now it must return pageURL because cdn.ex.com differs from ex.com.
func TestEffectiveBaseURLFrom_RejectsCrossHostProtocolRelativeBase(t *testing.T) {
	got := effectiveBaseURLFrom("//cdn.ex.com/app/", "https://ex.com/page")
	if got != "https://ex.com/page" {
		t.Errorf("got %q, want %q", got, "https://ex.com/page")
	}
}

// Malformed page URL falls back cleanly — we return the malformed input
// as-is so the caller can still emit it for diagnostic logs.
func TestEffectiveBaseURLFrom_MalformedPageURL(t *testing.T) {
	bad := "http://[::1:" // unterminated IPv6
	got := effectiveBaseURLFrom("/", bad)
	if got != bad {
		t.Errorf("got %q, want unchanged input %q", got, bad)
	}
}

// Malformed base href falls back to the page URL.
func TestEffectiveBaseURLFrom_MalformedHref(t *testing.T) {
	got := effectiveBaseURLFrom("http://[::1:", "https://ex.com/page")
	if got != "https://ex.com/page" {
		t.Errorf("got %q, want %q", got, "https://ex.com/page")
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
		// Query-only URL with no path — e.g., /?q=term or bare
		// https://host?q=1 — must still be treated as a page.
		"https://example.com?q=1",
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
	// references. Covers both trailing-slash and bare forms since the
	// socket.io client uses both depending on transport state.
	cases := []string{
		"http://localhost:3000/socket.io/",
		"http://localhost:3000/socket.io",
		"http://localhost:3000/socket.io?EIO=4&transport=polling&t=abc",
		"http://localhost:3000/socket.io/?EIO=4&transport=polling&t=abc",
		"http://localhost:3000/engine.io",
		"http://localhost:3000/engine.io/socket.io/",
	}
	for _, c := range cases {
		if isLikelyPage(c) {
			t.Errorf("isLikelyPage(%q) = true, want false", c)
		}
	}
}

// Guard against over-eager segment matching: a path whose segment merely
// contains "socket.io" as a substring (e.g., /my-socket.io-wrapper) must
// not be rejected.
func TestIsLikelyPage_SegmentMatchIsExact(t *testing.T) {
	cases := []string{
		"http://localhost:3000/my-socket.io-wrapper",
		"http://localhost:3000/docs/socket.io-guide",
	}
	for _, c := range cases {
		if !isLikelyPage(c) {
			t.Errorf("isLikelyPage(%q) = false, want true (substring, not segment)", c)
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

// Parse-failure path: this intentionally uses an input net/url.Parse
// actually rejects (unterminated IPv6 literal). When parsing fails,
// isLikelyPage is permissive — the frontier and scope stages are
// authoritative for rejecting bad URLs. Also covers the empty-string
// default. (A previous iteration tested only "" and admitted in its
// own comment that the err path was unreachable — this input actually
// drives it.)
func TestIsLikelyPage_UnparseableInputIsPermissive(t *testing.T) {
	cases := []string{"", "http://[::1:"}
	for _, c := range cases {
		if !isLikelyPage(c) {
			t.Errorf("isLikelyPage(%q) = false, want true (permissive default)", c)
		}
	}
}
