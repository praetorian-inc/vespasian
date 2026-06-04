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
	"strings"
	"testing"
)

func TestExtractFromHTML_UsesLinkSelectors(t *testing.T) {
	body := []byte(`<html><body>
      <a href="/page1">x</a>
      <form action="/submit"></form>
      <iframe src="/frame"></iframe>
      <a href="/bundle.js">js</a>
      <a href="https://other.example/x">off</a>
    </body></html>`)
	got, _, _ := extractHTMLAndInlineScripts(body, "https://e.com/")
	want := map[string]bool{
		"https://e.com/page1":     true,
		"https://e.com/submit":    true,
		"https://e.com/frame":     true,
		"https://other.example/x": true, // scope is enforced by frontier, not here
	}
	for _, u := range got {
		if !want[u] {
			t.Errorf("unexpected/duplicate link: %s", u)
		}
		delete(want, u)
	}
	if len(want) != 0 {
		t.Errorf("missing links: %v", want)
	}
	for _, u := range got {
		if strings.HasSuffix(u, ".js") {
			t.Errorf(".js bundle not filtered: %s", u)
		}
	}
}

func TestExtractInlineScripts_RunsJsluice(t *testing.T) {
	body := []byte(`<html><script>fetch("/api/inline")</script><script src="/x.js"></script></html>`)
	_, _, got := extractHTMLAndInlineScripts(body, "https://example.com/")
	found := false
	for _, e := range got {
		if strings.Contains(e.URL, "/api/inline") {
			found = true
		}
	}
	if !found {
		t.Errorf("inline jsluice URL not found in %v", got)
	}
}

func TestExtractFromHTML_EmptyBody(t *testing.T) {
	// Empty body should return nil/empty without panicking.
	got, _, _ := extractHTMLAndInlineScripts([]byte{}, "https://example.com/")
	if len(got) != 0 {
		t.Errorf("empty body: got %v, want []", got)
	}
}

func TestExtractFromHTML_NoLinks(t *testing.T) {
	body := []byte(`<html><body><p>no links here</p></body></html>`)
	got, _, _ := extractHTMLAndInlineScripts(body, "https://example.com/")
	if len(got) != 0 {
		t.Errorf("no-link page: got %v, want []", got)
	}
}

func TestExtractInlineScripts_NoInlineScripts(t *testing.T) {
	// Only external scripts — nothing to extract from inline.
	body := []byte(`<html><script src="/external.js"></script></html>`)
	_, _, got := extractHTMLAndInlineScripts(body, "https://example.com/")
	if len(got) != 0 {
		t.Errorf("external-only scripts: got %v, want []", got)
	}
}

func TestExtractInlineScripts_EmptyBody(t *testing.T) {
	_, _, got := extractHTMLAndInlineScripts([]byte{}, "https://example.com/")
	if len(got) != 0 {
		t.Errorf("empty body: got %v, want []", got)
	}
}

// TestExtractFromHTML_BaseReturnedNoBaseTag verifies extractHTMLAndInlineScripts
// returns pageURL as the base when the HTML contains no <base href> element.
func TestExtractFromHTML_BaseReturnedNoBaseTag(t *testing.T) {
	body := []byte(`<html><body><a href="/x">x</a></body></html>`)
	_, base, _ := extractHTMLAndInlineScripts(body, "https://example.com/page")
	if base != "https://example.com/page" {
		t.Errorf("base (no base tag) = %q, want %q", base, "https://example.com/page")
	}
}

// TestExtractFromHTML_BaseReturnedWithBaseTag verifies extractHTMLAndInlineScripts
// returns the resolved base URL when a valid <base href> element is present.
func TestExtractFromHTML_BaseReturnedWithBaseTag(t *testing.T) {
	body := []byte(`<html><head><base href="/app/"></head><body></body></html>`)
	_, base, _ := extractHTMLAndInlineScripts(body, "https://example.com/page")
	want := "https://example.com/app/"
	if base != want {
		t.Errorf("base = %q, want %q", base, want)
	}
}

// TestExtractFromHTML_BaseHref verifies that a <base href="/app/"> tag causes
// relative links to resolve against the base, not the raw pageURL.
func TestExtractFromHTML_BaseHref(t *testing.T) {
	// <base href="/app/"> is an absolute-path reference: resolves to https://host/app/.
	// The relative <a href="x"> should therefore resolve to https://host/app/x.
	body := []byte(`<html><head><base href="/app/"></head><body><a href="x">page</a></body></html>`)
	got, _, _ := extractHTMLAndInlineScripts(body, "https://host/other/page")
	want := "https://host/app/x"
	found := false
	for _, u := range got {
		if u == want {
			found = true
		}
		// Must NOT resolve relative to original pageURL (/other/page).
		if u == "https://host/other/x" {
			t.Errorf("relative link resolved against pageURL instead of <base href>: got %s", u)
		}
	}
	if !found {
		t.Errorf("expected %q in results %v", want, got)
	}
}

// TestExtractFromHTML_BaseHrefCrossHostRejected verifies that a cross-host
// <base href> is rejected and pageURL is used as fallback (cross-host guard).
func TestExtractFromHTML_BaseHrefCrossHostRejected(t *testing.T) {
	// attacker.com base must be rejected; relative link resolves against pageURL.
	body := []byte(`<html><head><base href="https://attacker.com/evil/"></head><body><a href="x">page</a></body></html>`)
	got, _, _ := extractHTMLAndInlineScripts(body, "https://target.com/app/")
	for _, u := range got {
		if strings.Contains(u, "attacker.com") {
			t.Errorf("cross-host <base href> was NOT rejected; got %s", u)
		}
	}
	// The relative "x" should resolve against pageURL → https://target.com/app/x
	want := "https://target.com/app/x"
	found := false
	for _, u := range got {
		if u == want {
			found = true
		}
	}
	if !found {
		t.Errorf("expected fallback resolution %q in results %v", want, got)
	}
}
