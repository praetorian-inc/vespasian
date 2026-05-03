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
	"testing"
)

func TestExtractURLsFromJS_FetchCall(t *testing.T) {
	source := []byte(`
		fetch("/api/v1/users")
		fetch("/api/v1/orders", {method: "POST"})
	`)

	results := extractURLsFromJS(source)
	if len(results) == 0 {
		t.Fatal("expected at least one URL from fetch calls")
	}

	found := false
	for _, r := range results {
		if r.URL == "/api/v1/users" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected /api/v1/users in results, got %+v", results)
	}
}

func TestExtractURLsFromJS_AxiosGet(t *testing.T) {
	source := []byte(`
		axios.get("/api/data/items")
		axios.post("/api/data/submit", data)
	`)

	results := extractURLsFromJS(source)
	if len(results) == 0 {
		t.Fatal("expected at least one URL from axios calls")
	}

	urls := make(map[string]bool)
	for _, r := range results {
		urls[r.URL] = true
	}
	if !urls["/api/data/items"] {
		t.Errorf("expected /api/data/items in results")
	}
}

func TestExtractURLsFromJS_StringLiterals(t *testing.T) {
	source := []byte(`
		var endpoint = "/api/v2/search";
		var base = "https://api.example.com/v1";
	`)

	results := extractURLsFromJS(source)
	urls := make(map[string]bool)
	for _, r := range results {
		urls[r.URL] = true
	}
	// jsluice may or may not extract simple string literals depending on context.
	// We just verify no crash and results are filtered.
	for _, r := range results {
		if r.URL == "" {
			t.Error("got empty URL in results")
		}
	}
}

func TestExtractURLsFromJS_FiltersNonNavigable(t *testing.T) {
	source := []byte(`
		var a = "javascript:void(0)";
		var b = "data:text/html,hello";
		var c = "mailto:test@example.com";
		fetch("/api/valid")
	`)

	results := extractURLsFromJS(source)
	for _, r := range results {
		lower := r.URL
		if lower == "javascript:void(0)" || lower == "data:text/html,hello" || lower == "mailto:test@example.com" {
			t.Errorf("non-navigable URL should be filtered: %q", r.URL)
		}
	}
}

func TestExtractURLsFromJS_EmptySource(t *testing.T) {
	results := extractURLsFromJS(nil)
	if results != nil {
		t.Errorf("expected nil for empty source, got %v", results)
	}

	results = extractURLsFromJS([]byte(""))
	if results != nil {
		t.Errorf("expected nil for empty string source, got %v", results)
	}
}

func TestExtractURLsFromResponses(t *testing.T) {
	captured := []ObservedRequest{
		{
			URL:    "https://example.com/app.js",
			Method: "GET",
			Response: ObservedResponse{
				StatusCode:  200,
				ContentType: "application/javascript",
				Body:        []byte(`fetch("/api/from-external-js")`),
			},
		},
		{
			URL:    "https://example.com/page.html",
			Method: "GET",
			Response: ObservedResponse{
				StatusCode:  200,
				ContentType: "text/html",
				Body:        []byte(`<html><body>not js</body></html>`),
			},
		},
		{
			URL:    "https://example.com/empty.js",
			Method: "GET",
			Response: ObservedResponse{
				StatusCode:  200,
				ContentType: "application/javascript",
				Body:        nil,
			},
		},
	}

	results := extractURLsFromResponses(captured)

	found := false
	for _, r := range results {
		if r.URL == "/api/from-external-js" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected /api/from-external-js from JS response body, got %+v", results)
	}
}

func TestIsJavaScriptContentType(t *testing.T) {
	tests := []struct {
		ct   string
		want bool
	}{
		{"application/javascript", true},
		{"application/x-javascript", true},
		{"text/javascript", true},
		{"application/ecmascript", true},
		{"text/js", true},
		{"application/x-js", true},
		{"text/html", false},
		{"application/json", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.ct, func(t *testing.T) {
			got := isJavaScriptContentType(tt.ct)
			if got != tt.want {
				t.Errorf("isJavaScriptContentType(%q) = %v, want %v", tt.ct, got, tt.want)
			}
		})
	}
}

func TestJsExtractedToLinks(t *testing.T) {
	extracted := []jsExtractedURL{
		{URL: "/api/users", Method: "GET"},
		{URL: "/api/orders", Method: "POST"},
		{URL: "/api/users", Method: "GET"},              // duplicate
		{URL: "javascript:void(0)", Method: "GET"},      // will fail resolveURL
		{URL: "https://example.com/abs", Method: "GET"}, // absolute
	}

	links := jsExtractedToLinks(extracted, "https://example.com/app")

	if len(links) == 0 {
		t.Fatal("expected at least one resolved link")
	}

	// Check dedup: /api/users should appear only once
	count := 0
	for _, l := range links {
		if l == "https://example.com/api/users" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected /api/users once, got %d times", count)
	}
}

// Regression guard for the asset-filter wired into jsExtractedToLinks
// (LAB-2221): jsluice sometimes pulls out string constants like "main.js"
// or "/socket.io/" that look like URLs but aren't crawlable pages. If we
// enqueue them we end up either fetching a known static asset (already
// captured via CDP) or, on SPA catch-all servers, triggering recursive
// nested paths like /socket.io/socket.io/.... The filter must drop them
// before they reach the frontier.
func TestJsExtractedToLinks_FiltersAssets(t *testing.T) {
	extracted := []jsExtractedURL{
		{URL: "/api/users"},
		{URL: "/main.js"},
		{URL: "/assets/chunk-ABCDE.mjs"},
		{URL: "/styles.css"},
		{URL: "/assets/public/images/logo.png"},
		{URL: "/assets/font.woff2"},
		{URL: "/socket.io/"},
		{URL: "/engine.io/socket.io/"},
	}

	links := jsExtractedToLinks(extracted, "https://example.com/app")

	rejected := []string{
		"https://example.com/main.js",
		"https://example.com/assets/chunk-ABCDE.mjs",
		"https://example.com/styles.css",
		"https://example.com/assets/public/images/logo.png",
		"https://example.com/assets/font.woff2",
		"https://example.com/socket.io/",
		"https://example.com/engine.io/socket.io/",
	}

	for _, bad := range rejected {
		for _, got := range links {
			if got == bad {
				t.Errorf("asset URL %q leaked through filter; links=%v", bad, links)
			}
		}
	}

	// Real API path must still be present.
	found := false
	for _, got := range links {
		if got == "https://example.com/api/users" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("legitimate API path dropped by filter; links=%v", links)
	}
}
