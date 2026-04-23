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
	"slices"
	"testing"
)

// mergeEnrichedLinks is the pure, DOM-free portion of enrichFromPage. These
// tests cover the branches that aren't exercised by TestRodEngine_*
// integration tests (which are gated behind //go:build integration and
// excluded from the default coverage run).

func TestMergeEnrichedLinks_CombinesAllSources(t *testing.T) {
	captured := []ObservedRequest{{Method: "GET", URL: "https://ex.com/"}}
	domLinks := []string{"https://ex.com/login", "https://ex.com/about"}
	jsFromResponses := []jsExtractedURL{{URL: "/api/products", Method: "GET"}}
	jsFromInline := []jsExtractedURL{{URL: "/rest/users", Method: "GET"}}
	forms := []discoveredForm{{
		Action:      "https://ex.com/submit",
		Method:      "POST",
		ContentType: "application/x-www-form-urlencoded",
		Fields:      map[string]string{"name": "alice"},
	}}

	captured, links := mergeEnrichedLinks(
		captured, domLinks, jsFromResponses, jsFromInline, forms,
		"https://ex.com/", "https://ex.com/",
	)

	want := []string{
		"https://ex.com/login",
		"https://ex.com/about",
		"https://ex.com/api/products",
		"https://ex.com/rest/users",
		"https://ex.com/submit",
	}
	for _, w := range want {
		if !slices.Contains(links, w) {
			t.Errorf("links missing %q; got %v", w, links)
		}
	}

	// Form produces a synthetic POST ObservedRequest in captured.
	foundForm := false
	for _, c := range captured {
		if c.Method == "POST" && c.URL == "https://ex.com/submit" && c.Source == "form" {
			foundForm = true
			break
		}
	}
	if !foundForm {
		t.Errorf("expected synthetic form request in captured; got %v", captured)
	}
}

// jsluice-extracted URLs that point at assets or streaming transports must
// be dropped before entering the frontier — this is the LAB-2221 fix that
// prevents /socket.io/socket.io/... mangled paths on SPA catch-all servers.
func TestMergeEnrichedLinks_FiltersAssetsFromJSLuice(t *testing.T) {
	extracted := []jsExtractedURL{
		{URL: "/api/orders"},
		{URL: "/main.js"},
		{URL: "/socket.io/"},
	}
	_, links := mergeEnrichedLinks(nil, nil, extracted, nil, nil, "https://ex.com/", "https://ex.com/")

	if !slices.Contains(links, "https://ex.com/api/orders") {
		t.Errorf("expected /api/orders in links; got %v", links)
	}
	if slices.Contains(links, "https://ex.com/main.js") {
		t.Errorf("main.js leaked through filter; got %v", links)
	}
	if slices.Contains(links, "https://ex.com/socket.io/") {
		t.Errorf("socket.io leaked through filter; got %v", links)
	}
}

// TestMergeEnrichedLinks_InlineOnly covers the jsFromInline branch
// (engine.go:355-357) independently — previously only tested in
// combination with jsFromResponses via TestMergeEnrichedLinks_CombinesAllSources.
// Asset filtering must apply to inline-discovered URLs the same way it
// applies to response-discovered ones.
func TestMergeEnrichedLinks_InlineOnly(t *testing.T) {
	inline := []jsExtractedURL{
		{URL: "/rest/customers"},
		{URL: "/vendor.js"},
	}
	_, links := mergeEnrichedLinks(nil, nil, nil, inline, nil, "https://ex.com/", "https://ex.com/")

	if !slices.Contains(links, "https://ex.com/rest/customers") {
		t.Errorf("expected /rest/customers in links; got %v", links)
	}
	if slices.Contains(links, "https://ex.com/vendor.js") {
		t.Errorf("inline-only vendor.js leaked through filter; got %v", links)
	}
}

// TestMergeEnrichedLinks_JSLuiceResolvedAgainstBaseNotPage pins the
// primary LAB-2221 pre-fix defect: mergeEnrichedLinks must route
// jsFromResponses and jsFromInline through baseURL (not pageURL) when
// they differ. Without this test, a refactor that reverted engine.go:365
// or :368 from baseURL to pageURL would reintroduce the SPA deep-path
// bug and the default suite would still pass (the integration-tagged
// TestRodEngine_BaseHrefResolution is the only other catch).
func TestMergeEnrichedLinks_JSLuiceResolvedAgainstBaseNotPage(t *testing.T) {
	const pageURL = "https://ex.com/deep/page/here"
	const baseURL = "https://ex.com/"

	fromResponses := []jsExtractedURL{{URL: "/api/users"}}
	fromInline := []jsExtractedURL{{URL: "orders"}}

	_, links := mergeEnrichedLinks(nil, nil, fromResponses, fromInline, nil, pageURL, baseURL)

	// Root-relative jsluice URL resolves against base root.
	if !slices.Contains(links, "https://ex.com/api/users") {
		t.Errorf("expected /api/users resolved against base root; got %v", links)
	}
	// Bare-relative jsluice URL resolves against base root, not deep page.
	if !slices.Contains(links, "https://ex.com/orders") {
		t.Errorf("expected orders resolved against base root; got %v", links)
	}
	// Pre-fix behavior: the two strings below must NOT appear. A regression
	// that swapped baseURL→pageURL at engine.go:365/368 would produce them.
	if slices.Contains(links, "https://ex.com/deep/page/here/api/users") {
		t.Errorf("regression: jsFromResponses resolved against pageURL; got %v", links)
	}
	if slices.Contains(links, "https://ex.com/deep/page/orders") {
		t.Errorf("regression: jsFromInline resolved against pageURL; got %v", links)
	}
}

// Form actions arrive pre-resolved from extractForms (see resolveFormAction
// for the resolution semantics and TestResolveFormAction_* for its
// per-branch coverage). mergeEnrichedLinks only applies the asset/streaming
// filter so that asset-shaped actions (action="/app.js") are not queued.
func TestMergeEnrichedLinks_FormActionFiltering(t *testing.T) {
	forms := []discoveredForm{
		{Action: "https://ex.com/api/login", Method: "POST"},
		{Action: "https://ex.com/main.js", Method: "POST"}, // asset-shaped — filtered
		{Action: "", Method: "GET"},                        // empty — skipped without error
	}
	_, links := mergeEnrichedLinks(nil, nil, nil, nil, forms, "https://ex.com/login", "https://ex.com/")

	if !slices.Contains(links, "https://ex.com/api/login") {
		t.Errorf("expected form action in links; got %v", links)
	}
	if slices.Contains(links, "https://ex.com/main.js") {
		t.Errorf("asset form action wrongly queued; got %v", links)
	}
}

// No-action forms get Action=pageURL (HTML §4.10.21.3). This test pins
// what happens in mergeEnrichedLinks once extractForms / resolveFormAction
// has already set Action — the per-branch coverage of resolveFormAction
// itself lives in TestResolveFormAction_NoActionUsesPageURL.
func TestMergeEnrichedLinks_NoActionFormUsesPageURL(t *testing.T) {
	// Simulate what extractForms emits when there's no action attribute:
	// Action is set to pageURL, not baseURL.
	forms := []discoveredForm{{Action: "https://ex.com/login", Method: "POST"}}
	captured, _ := mergeEnrichedLinks(nil, nil, nil, nil, forms, "https://ex.com/login", "https://ex.com/")

	found := false
	for _, c := range captured {
		if c.URL == "https://ex.com/login" && c.Method == "POST" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected synthetic POST on /login; got %v", captured)
	}
}

func TestMergeEnrichedLinks_EmptyInputs(t *testing.T) {
	captured, links := mergeEnrichedLinks(nil, nil, nil, nil, nil, "https://ex.com/", "https://ex.com/")
	if len(captured) != 0 {
		t.Errorf("captured = %v, want empty", captured)
	}
	if len(links) != 0 {
		t.Errorf("links = %v, want empty", links)
	}
}
