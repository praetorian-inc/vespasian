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
	"reflect"
	"slices"
	"strings"
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
		"https://ex.com/", "https://ex.com/", nil,
	)

	want := []string{
		"https://ex.com/login",
		"https://ex.com/about",
		"https://ex.com/api/products",
		"https://ex.com/rest/users",
		"https://ex.com/submit",
	}
	// Pin the contract from mergeEnrichedLinks's doc comment: DOM links,
	// then js-from-responses, then js-from-inline, then form actions.
	// A refactor that shuffles source order (e.g. forms before DOM links)
	// would slip past a membership-only check.
	if !slices.Equal(links, want) {
		t.Errorf("links order mismatch\n got:  %v\n want: %v", links, want)
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
	_, links := mergeEnrichedLinks(nil, nil, extracted, nil, nil, "https://ex.com/", "https://ex.com/", nil)

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
	_, links := mergeEnrichedLinks(nil, nil, nil, inline, nil, "https://ex.com/", "https://ex.com/", nil)

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

	_, links := mergeEnrichedLinks(nil, nil, fromResponses, fromInline, nil, pageURL, baseURL, nil)

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
	_, links := mergeEnrichedLinks(nil, nil, nil, nil, forms, "https://ex.com/login", "https://ex.com/", nil)

	if !slices.Contains(links, "https://ex.com/api/login") {
		t.Errorf("expected form action in links; got %v", links)
	}
	if slices.Contains(links, "https://ex.com/main.js") {
		t.Errorf("asset form action wrongly queued; got %v", links)
	}
}

// TestMergeEnrichedLinks_PreResolvedFormActionIsCaptured pins the
// contract at the mergeEnrichedLinks boundary: forms arrive with Action
// already resolved (extractForms / resolveFormAction handle the
// resolution, including the HTML §4.10.21.3 no-action -> pageURL rule).
// mergeEnrichedLinks's job is to emit a synthetic ObservedRequest for
// whatever absolute Action it sees. resolveFormAction's own per-branch
// coverage lives in TestResolveFormAction_NoActionUsesPageURL.
func TestMergeEnrichedLinks_PreResolvedFormActionIsCaptured(t *testing.T) {
	// Simulate what extractForms emits when there's no action attribute:
	// Action is set to pageURL, not baseURL.
	forms := []discoveredForm{{Action: "https://ex.com/login", Method: "POST"}}
	captured, _ := mergeEnrichedLinks(nil, nil, nil, nil, forms, "https://ex.com/login", "https://ex.com/", nil)

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
	captured, links := mergeEnrichedLinks(nil, nil, nil, nil, nil, "https://ex.com/", "https://ex.com/", nil)
	if len(captured) != 0 {
		t.Errorf("captured = %v, want empty", captured)
	}
	if len(links) != 0 {
		t.Errorf("links = %v, want empty", links)
	}
}

// SEC-BE-001 regression (PR #88 review 4165223270): a <form action="https://attacker/">
// on an in-scope page must not produce a synthetic ObservedRequest in captured.
// Without scope enforcement in mergeEnrichedLinks, the attacker-host URL would
// flow to capture.json and be re-requested by downstream probes carrying any
// operator-supplied --header values (Authorization, cookies, CSRF tokens).
//
// Note: the "attacker URL absent from links" assertion below is load-bearing,
// not belt-and-suspenders. The scope filter's scopedForms slice feeds BOTH
// the captured-append path AND the links-append loop in mergeEnrichedLinks
// — a future refactor that split them must still catch cross-host URLs at
// both sinks. Do not remove the links check if this test is later split.
func TestMergeEnrichedLinks_FormActionCrossHostIsNotCaptured(t *testing.T) {
	forms := []discoveredForm{
		{Action: "https://attacker.example/evil", Method: "GET"},
		{Action: "https://in-scope.example/login", Method: "POST"},
	}
	scope := func(u string) bool { return strings.Contains(u, "in-scope.example") }

	captured, links := mergeEnrichedLinks(
		nil, nil, nil, nil, forms,
		"https://in-scope.example/login", "https://in-scope.example/", scope,
	)

	// The attacker-host URL must NOT appear anywhere in captured or links.
	for _, r := range captured {
		if strings.Contains(r.URL, "attacker.example") {
			t.Fatalf("cross-host form URL leaked into captured: %q", r.URL)
		}
	}
	for _, u := range links {
		if strings.Contains(u, "attacker.example") {
			t.Fatalf("cross-host form URL leaked into links: %q", u)
		}
	}

	// Positive links-side assertion: the in-scope form action DOES land
	// in links. Without this, a bug that drops ALL forms from the links-
	// append loop (early return, accidental break, wrong variable) would
	// not be caught.
	if !slices.Contains(links, "https://in-scope.example/login") {
		t.Errorf("expected in-scope form action in links; got %v", links)
	}

	// The in-scope form action IS captured (no false negative).
	foundInScope := false
	for _, r := range captured {
		if r.URL == "https://in-scope.example/login" && r.Source == "form" {
			foundInScope = true
			break
		}
	}
	if !foundInScope {
		t.Errorf("expected in-scope form in captured; got %v", captured)
	}
}

// Nil scopeFn preserves pre-fix behavior: no filtering applied.
// Pins the nil-contract so a future refactor that makes scopeFn required
// without updating all call sites is caught.
func TestMergeEnrichedLinks_NilScopeFnDoesNotFilter(t *testing.T) {
	forms := []discoveredForm{
		{Action: "https://anywhere.example/x", Method: "POST"},
	}
	captured, _ := mergeEnrichedLinks(
		nil, nil, nil, nil, forms,
		"https://in-scope.example/", "https://in-scope.example/", nil,
	)
	found := false
	for _, r := range captured {
		if r.URL == "https://anywhere.example/x" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("nil scopeFn should pass all forms through; got %v", captured)
	}
}

// TEST-002 (PR #88 review round 11): the scope filter has an early-accept
// branch — f.Action == "" is kept regardless of scopeFn. Existing tests
// cover nil scopeFn and non-empty Action with non-nil scopeFn; the combo
// empty Action + reject-all scopeFn is not pinned. A refactor that
// dropped the `f.Action == ""` branch would silently change behavior
// here (the form would be dropped instead of kept). The empty-Action
// invariant comes from resolveFormAction (which always maps empty raw
// action to pageURL, same-origin) and is the reason the early-accept
// is safe.
func TestMergeEnrichedLinks_EmptyActionPassesThroughWhenScopeFnWouldReject(t *testing.T) {
	forms := []discoveredForm{{Action: "", Method: "GET"}}
	scope := func(string) bool { return false }
	captured, _ := mergeEnrichedLinks(nil, nil, nil, nil, forms,
		"https://ex.com/login", "https://ex.com/", scope)
	if len(captured) != 1 {
		t.Fatalf("expected empty-Action form to pass through scope filter; got %d captured", len(captured))
	}
	// formsToObservedRequests emits URL="" for empty Action.
	if captured[0].URL != "" {
		t.Errorf("expected captured URL to be empty (Action=\"\"); got %q", captured[0].URL)
	}
}

// TEST-004 (PR #88 review round 11): realistic pages mix forms with
// empty action, in-scope absolute action, and out-of-scope absolute
// action. Each branch is covered in isolation; this pins their
// interaction (ordering, partial-filtering bugs, one-off off-by-one
// skips).
func TestMergeEnrichedLinks_MixedFormsWithScope(t *testing.T) {
	forms := []discoveredForm{
		{Action: "", Method: "GET"},                              // empty → pageURL, always kept
		{Action: "https://in-scope.example/api", Method: "POST"}, // in-scope, kept
		{Action: "https://attacker.example/evil", Method: "GET"}, // out-of-scope, dropped
	}
	scope := func(u string) bool { return strings.Contains(u, "in-scope.example") }
	captured, links := mergeEnrichedLinks(nil, nil, nil, nil, forms,
		"https://in-scope.example/login", "https://in-scope.example/", scope)

	// captured must contain exactly the two kept forms — empty Action
	// produces URL="" and the in-scope form produces the /api URL.
	if len(captured) != 2 {
		t.Fatalf("expected 2 captured ObservedRequests, got %d: %v", len(captured), captured)
	}
	urls := []string{captured[0].URL, captured[1].URL}
	if !slices.Contains(urls, "") {
		t.Errorf("expected empty-Action form in captured (URL=\"\"); got %v", urls)
	}
	if !slices.Contains(urls, "https://in-scope.example/api") {
		t.Errorf("expected in-scope form in captured; got %v", urls)
	}
	for _, r := range captured {
		if strings.Contains(r.URL, "attacker.example") {
			t.Fatalf("attacker URL leaked into captured: %q", r.URL)
		}
	}

	// links must contain /api and NOT /evil. (Empty Action doesn't feed
	// the links loop — the `if f.Action == ""` continue skips it.)
	if !slices.Contains(links, "https://in-scope.example/api") {
		t.Errorf("expected in-scope form action in links; got %v", links)
	}
	for _, u := range links {
		if strings.Contains(u, "attacker.example") {
			t.Fatalf("attacker URL leaked into links: %q", u)
		}
	}
}

// Round-11 TEST-001 regression: enrichFromPage threads scopeFn (from
// e.opts.ScopeCheck) through to mergeEnrichedLinks in a single one-line
// call. Integration test TestRodEngine_ScopeFiltering covers this in a
// full browser environment, but default-suite coverage was absent — a
// refactor that dropped scopeFn at the enrichFromPage -> mergeEnrichedLinks
// call site would not fail any default-suite test.
//
// These tests install a spy merger via the package-level mergeEnrichedLinksFn
// var (exposed for exactly this purpose), then call enrichFromPage with a
// nil *rod.Page (routed straight to the merger by the nil-page guard) and
// verify the spy observed the same scopeFn function pointer the caller passed.

func TestEnrichFromPage_ThreadsScopeFnToMergeEnrichedLinks(t *testing.T) {
	var captured struct {
		scopeFn func(string) bool
		pageURL string
		baseURL string
	}
	orig := mergeEnrichedLinksFn
	mergeEnrichedLinksFn = func(c []ObservedRequest, domLinks []string, jsFromResponses, jsFromInline []jsExtractedURL, forms []discoveredForm, pageURL, baseURL string, scopeFn func(string) bool) ([]ObservedRequest, []string) {
		captured.scopeFn = scopeFn
		captured.pageURL = pageURL
		captured.baseURL = baseURL
		return c, nil
	}
	t.Cleanup(func() { mergeEnrichedLinksFn = orig })

	myScope := func(string) bool { return false }
	_, _ = enrichFromPage(nil, nil, "https://ex.com/login", nil, myScope)

	if captured.scopeFn == nil {
		t.Fatal("scopeFn was not passed to mergeEnrichedLinks")
	}
	// Compare function pointers: the spy must have received the SAME
	// scopeFn the caller passed, not nil and not some wrapper.
	//
	// reflect.Value.Pointer is used instead of `==` because Go forbids
	// equality on function values other than against nil (spec §Comparison
	// operators). Two distinct func literals with identical bodies produce
	// different pointers here, which is the property we want to test: any
	// refactor that replaces the caller's scopeFn with a wrapper before
	// reaching the merger would flip this comparison.
	if reflect.ValueOf(captured.scopeFn).Pointer() != reflect.ValueOf(myScope).Pointer() {
		t.Errorf("scopeFn identity differs: enrichFromPage passed a different function to mergeEnrichedLinks")
	}
	if captured.pageURL != "https://ex.com/login" {
		t.Errorf("pageURL = %q, want %q", captured.pageURL, "https://ex.com/login")
	}
	// The nil-page guard uses pageURL for both pageURL AND baseURL since
	// there's no DOM to read a <base href> from.
	if captured.baseURL != "https://ex.com/login" {
		t.Errorf("baseURL = %q, want %q (nil-page guard uses pageURL)", captured.baseURL, "https://ex.com/login")
	}
}

// Companion: enrichFromPage with nil scopeFn must forward nil (not a
// wrapper). Protects against a refactor that silently defaults scopeFn
// to an accept-all function before the merger call.
func TestEnrichFromPage_ThreadsNilScopeFn(t *testing.T) {
	var got func(string) bool
	orig := mergeEnrichedLinksFn
	mergeEnrichedLinksFn = func(c []ObservedRequest, _ []string, _, _ []jsExtractedURL, _ []discoveredForm, _, _ string, scopeFn func(string) bool) ([]ObservedRequest, []string) {
		got = scopeFn
		return c, nil
	}
	t.Cleanup(func() { mergeEnrichedLinksFn = orig })

	_, _ = enrichFromPage(nil, nil, "https://ex.com/", nil, nil)

	if got != nil {
		t.Errorf("nil scopeFn was wrapped into non-nil by enrichFromPage; got non-nil function — mergeEnrichedLinks would apply filtering")
	}
}
