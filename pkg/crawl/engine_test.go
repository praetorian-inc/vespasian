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
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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

// TestRodEngine_Crawl_SeedRejectedByFrontierReturnsError covers LAB-2438.
//
// Before this fix, when the frontier rejected the seed (e.g., the seed host
// was private and allowPrivate=false), engine.Crawl pushed zero entries and
// then blocked in wg.Wait() until all workers saw an empty frontier, returning
// nil with no captures — the operator got `captured 0 requests` with no error
// and no way to diagnose. The fix makes this condition a hard error that
// names the seed and points at `--dangerous-allow-private`.
//
// This test constructs a frontier with a scope predicate that rejects every
// URL, calls Crawl, and asserts a non-nil error is returned without the
// engine ever touching the (nil) browser.
func TestRodEngine_Crawl_SeedRejectedByFrontierReturnsError(t *testing.T) {
	// rejectAll mirrors the private-seed + SSRF rejection case without
	// requiring the real scopeChecker wiring — Push just asks for a
	// func(string) bool, and we control its answer.
	rejectAll := func(string) bool { return false }

	e := &rodEngine{
		// AC #3: nil browser is deliberate — see LAB-2438. The error path must
		// return before any CDP call happens. If a future refactor accidentally
		// advances past Push before the guard, this test will panic on a
		// nil-browser deref (at e.browser.Page() in visitPage, engine.go) rather
		// than silently passing.
		browser: nil,
		opts: engineOptions{
			Concurrency: 1,
			MaxPages:    10,
			MaxDepth:    2,
			ScopeCheck:  rejectAll,
		},
		frontier: newURLFrontier(2, rejectAll),
	}

	err := e.Crawl(context.Background(), "http://localhost:9000", func(ObservedRequest) {
		t.Fatal("onResult must not be called when the seed is rejected")
	})
	if err == nil {
		t.Fatal("Crawl returned nil error on rejected seed; expected a descriptive error")
	}
	if !strings.Contains(err.Error(), "rejected") {
		t.Errorf("Crawl error %q should mention 'rejected'; prior bug was a silent empty-frontier exit", err)
	}
	if !strings.Contains(err.Error(), "http://localhost:9000") {
		t.Errorf("Crawl error %q should echo the seed URL for operator diagnosis", err)
	}
	if !strings.Contains(err.Error(), flagDangerousAllowPrivate) {
		t.Errorf("Crawl error %q should name the remediation flag (%s) so operators know what to do", err, flagDangerousAllowPrivate)
	}
	// Pin the load-bearing operator-facing clauses so a refactor that drops
	// either the diagnostic breakdown or the private-host enumeration fails
	// the test instead of silently degrading the error message.
	if !strings.Contains(err.Error(), "scope, SSRF, or parse") {
		t.Errorf("Crawl error %q should include the '(scope, SSRF, or parse)' diagnostic breakdown so operators know why the seed was rejected", err)
	}
	if !strings.Contains(err.Error(), "private host") {
		t.Errorf("Crawl error %q should include the 'private host' enumeration so operators recognize the common-case cause", err)
	}
}

// TestRodEngine_Crawl_SeedAcceptedDoesNotReturnRejectionError covers LAB-2438
// AC #2: with --dangerous-allow-private (modeled here as an accept-all scope
// predicate) the Crawl entry-point must NOT emit the
// "seed URL rejected by frontier" error. Without this test the happy path is
// only pinned by the live-test harness / integration-tagged tests; the default
// suite had no tripwire for a regression that starts rejecting valid seeds.
//
// We cannot run the full crawl in a unit test (there is no browser), so we
// invoke Crawl with Concurrency=0 — newRodEngine normally bumps that to
// DefaultConcurrency, but we bypass newRodEngine here and construct rodEngine
// directly. With Concurrency=0 no worker goroutines launch, wg.Wait() returns
// immediately, and Crawl returns ctx.Err() (nil for context.Background()).
// The only way to hit the rejection error is for Push to return 0; with an
// accept-all predicate Push returns 1, so the rejection error is not emitted.
func TestRodEngine_Crawl_SeedAcceptedDoesNotReturnRejectionError(t *testing.T) {
	acceptAll := func(string) bool { return true }

	e := &rodEngine{
		// Same nil-browser rationale as the rejection test above, and it is
		// load-bearing here: Concurrency=0 means no workers launch, so we
		// never reach visitPage's e.browser.Page() call. If someone changes
		// Crawl to launch a worker regardless of Concurrency, this test will
		// panic on nil-browser deref instead of silently hanging.
		browser: nil,
		opts: engineOptions{
			Concurrency: 0,
			MaxPages:    10,
			MaxDepth:    2,
			ScopeCheck:  acceptAll,
		},
		frontier: newURLFrontier(2, acceptAll),
	}

	// With Concurrency=0 and context.Background(), Crawl's control flow is
	// deterministically: Push succeeds → range over 0 launches no workers →
	// wg.Wait returns immediately → return ctx.Err() == nil. Any non-nil error
	// at all is a regression of AC #2 (happy path must not fail). Asserting
	// err == nil (rather than only inspecting for the rejection substring)
	// keeps the tripwire broad so an unrelated regression does not slip past.
	err := e.Crawl(context.Background(), "http://example.com", func(ObservedRequest) {})
	if err != nil {
		t.Fatalf("Crawl returned unexpected error %q on accept-all predicate; AC #2 happy path must return nil", err)
	}
}

// TestRodEngine_Crawl_SeedRejectionRedactsUserinfo covers the follow-up to
// LAB-2438: an operator may paste a credentialed seed URL (e.g.
// http://user:pass@internal.corp) and forget flagDangerousAllowPrivate. The
// rejection error is written to stderr by kong's FatalIfErrorf and can land in
// shell history, terminal scrollback, or CI logs. The error message therefore
// must not echo the password (or username) back to the operator.
func TestRodEngine_Crawl_SeedRejectionRedactsUserinfo(t *testing.T) {
	rejectAll := func(string) bool { return false }

	e := &rodEngine{
		browser: nil,
		opts: engineOptions{
			Concurrency: 1, MaxPages: 10, MaxDepth: 2, ScopeCheck: rejectAll,
		},
		frontier: newURLFrontier(2, rejectAll),
	}

	seed := "http://admin:s3cret@10.0.0.5:8080/path" //nolint:gosec // G101: intentional test credential used to verify redactSeedURL strips userinfo from error messages
	err := e.Crawl(context.Background(), seed, func(ObservedRequest) {
		t.Fatal("onResult must not be called when the seed is rejected")
	})
	if err == nil {
		t.Fatal("Crawl returned nil error on rejected credentialed seed; expected a descriptive error")
	}
	if strings.Contains(err.Error(), "s3cret") {
		t.Errorf("Crawl error %q MUST NOT echo the seed password; it could land in shell history or CI logs", err)
	}
	if strings.Contains(err.Error(), "admin") {
		t.Errorf("Crawl error %q MUST NOT echo the seed username; redactSeedURL is expected to strip the full userinfo block", err)
	}
	// The rest of the URL (host, port, path) is operator-supplied context and
	// must still be present so the operator can identify which seed failed.
	if !strings.Contains(err.Error(), "10.0.0.5:8080") {
		t.Errorf("Crawl error %q should still echo the host:port after redaction", err)
	}
	if !strings.Contains(err.Error(), "/path") {
		t.Errorf("Crawl error %q should still echo the path after redaction", err)
	}
}

// TestRedactSeedURL table-drives the redaction helper directly so regressions
// in url.Parse handling (empty URLs, malformed, no userinfo) are caught
// independently of the Crawl integration above.
func TestRedactSeedURL(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"no userinfo", "http://example.com/x", "http://example.com/x"},
		{"user+password", "http://u:p@example.com:443/x?q=1", "http://example.com:443/x?q=1"},
		{"user only", "http://u@example.com/x", "http://example.com/x"},
		{"empty password", "http://u:@example.com/x", "http://example.com/x"},
		// IPv6 literal uses bracket notation in the authority; url.Parse
		// round-trips the brackets so the host:port form is preserved.
		{"ipv6 with userinfo", "http://u:p@[::1]:8080/x", "http://[::1]:8080/x"}, //nolint:gosec // G101: intentional test credential used to verify IPv6 userinfo redaction
		{"empty string", "", ""},
		// url.Parse fails on unknown scheme syntax, but the string has no
		// "@" so we fall through to the raw-return path. Operators still
		// get an actionable message without risking credential leak.
		{"malformed no userinfo returned as-is", "://not a url", "://not a url"},
		// url.Parse fails (invalid percent-escape in userinfo) AND the raw
		// string contains "@", so we fail closed: the placeholder is emitted
		// instead of echoing "admin:se%zz@host/path" with credentials.
		{"malformed with userinfo redacts to placeholder", "http://admin:se%zz@host/path", redactedURLPlaceholder}, //nolint:gosec // G101: intentional malformed test credential used to verify fail-closed redaction
		// Opaque form: "http:user:pass@host/path" parses as Opaque="user:pass@host/path"
		// with u.User nil. Clearing u.User is a no-op and u.String() would
		// round-trip the credentials — the residual "@" check forces the
		// placeholder. Not reachable via the CLI (main.go:validateURL blocks
		// empty-Host URLs) but pinned here because redactSeedURL lives at a
		// package boundary.
		{"opaque with userinfo redacts to placeholder", "http:admin:pw@host/path", redactedURLPlaceholder}, //nolint:gosec // G101: intentional opaque-form test credential used to verify fail-closed redaction
		// Deliberate false positive: "@" is legal in path/query components
		// (Go preserves it unencoded). The residual-"@" check cannot cheaply
		// distinguish this from opaque-form credential smuggling, so we fail
		// closed. Operators lose host/path context; accepted as the safer
		// default. Pin the behavior so a future refactor that "fixes" the
		// false positive by removing the check does not silently expose the
		// opaque-form credential-leak path.
		{"@ in path falls back to placeholder", "http://example.com/@user", redactedURLPlaceholder},
		{"@ in query falls back to placeholder", "http://example.com/?q=a@b", redactedURLPlaceholder},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := redactSeedURL(tc.in)
			if got != tc.want {
				t.Errorf("redactSeedURL(%q) = %q; want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestMergeEnrichedLinks_ScopeFiltersCapturedRequests verifies that passively
// captured network requests to out-of-scope hosts are dropped (LAB-4678 Phase 1),
// so third-party XHR/CDN hosts do not become endpoints or spec servers. In-scope
// captured requests and scoped form actions are retained.
func TestMergeEnrichedLinks_ScopeFiltersCapturedRequests(t *testing.T) {
	scopeFn := func(u string) bool { return strings.Contains(u, "ex.com") }
	captured := []ObservedRequest{
		{Method: "GET", URL: "https://ex.com/"},
		{Method: "GET", URL: "https://ex.com/api/users"},
		{Method: "GET", URL: "https://analytics.thirdparty.com/collect"},
		{Method: "POST", URL: "https://cdn.other.net/beacon"},
	}

	got, _ := mergeEnrichedLinks(captured, nil, nil, nil, nil, "https://ex.com/", "https://ex.com/", scopeFn)

	for _, r := range got {
		if !strings.Contains(r.URL, "ex.com") {
			t.Errorf("out-of-scope captured request survived: %s", r.URL)
		}
	}
	if len(got) != 2 {
		t.Errorf("kept %d captured requests, want 2 (in-scope only): %v", len(got), got)
	}
}

// TestMergeEnrichedLinks_NilScopeKeepsCaptured verifies a nil scopeFn applies no
// filtering to captured requests (matching the form-action convention).
func TestMergeEnrichedLinks_NilScopeKeepsCaptured(t *testing.T) {
	captured := []ObservedRequest{
		{Method: "GET", URL: "https://ex.com/"},
		{Method: "GET", URL: "https://third.party/x"},
	}
	got, _ := mergeEnrichedLinks(captured, nil, nil, nil, nil, "https://ex.com/", "https://ex.com/", nil)
	if len(got) != 2 {
		t.Errorf("nil scopeFn kept %d, want 2 (no filtering)", len(got))
	}
}

// TestBudgetReached covers the two crawl budgets (LAB-4678 Phase 3): a 0 budget
// is unlimited for that dimension, and either dimension hitting its bound stops
// the crawl from starting a new page.
func TestBudgetReached(t *testing.T) {
	cases := []struct {
		name                                   string
		pageCount, maxPages, reqCount, maxReqs int
		want                                   bool
	}{
		{"both unlimited", 100, 0, 100, 0, false},
		{"pages under cap", 1, 5, 0, 0, false},
		{"pages at cap", 5, 5, 0, 0, true},
		{"requests at cap", 1, 0, 50, 50, true},
		{"requests under cap", 1, 0, 49, 50, false},
		{"pages ok, requests over", 2, 100, 500, 200, true},
		{"requests ok, pages over", 100, 50, 10, 1000, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			pages, reqs := tc.pageCount, tc.reqCount
			if got := budgetReached(&mu, &pages, tc.maxPages, &reqs, tc.maxReqs, false); got != tc.want {
				t.Errorf("budgetReached(pages=%d/%d, reqs=%d/%d) = %v, want %v",
					tc.pageCount, tc.maxPages, tc.reqCount, tc.maxReqs, got, tc.want)
			}
			// The pre-Pop early-out must never consume a page slot.
			if pages != tc.pageCount {
				t.Errorf("check-only call changed pageCount: %d -> %d", tc.pageCount, pages)
			}
			if reqs != tc.reqCount {
				t.Errorf("check-only call changed reqCount: %d -> %d", tc.reqCount, reqs)
			}
		})
	}
}

// TestBudgetReached_Reserve pins the reserve semantics that keep the page cap
// exact under concurrency: a reserving call consumes exactly one page slot when
// it admits the page, and consumes none when it reports a budget reached — for
// either dimension. Compare and increment share one critical section, so a
// separate check-then-increment cannot race workers past MaxPages.
func TestBudgetReached_Reserve(t *testing.T) {
	t.Run("admits and consumes one slot", func(t *testing.T) {
		var mu sync.Mutex
		pages, reqs := 3, 0
		if budgetReached(&mu, &pages, 5, &reqs, 0, true) {
			t.Fatal("reported budget reached at 3/5 pages")
		}
		if pages != 4 {
			t.Errorf("reserve did not consume a slot: pageCount = %d, want 4", pages)
		}
	})

	t.Run("page cap reached consumes nothing", func(t *testing.T) {
		var mu sync.Mutex
		pages, reqs := 5, 0
		if !budgetReached(&mu, &pages, 5, &reqs, 0, true) {
			t.Fatal("did not report budget reached at 5/5 pages")
		}
		if pages != 5 {
			t.Errorf("reserve consumed a slot past the page cap: pageCount = %d, want 5", pages)
		}
	})

	t.Run("request cap reached consumes no page slot", func(t *testing.T) {
		var mu sync.Mutex
		pages, reqs := 1, 50
		if !budgetReached(&mu, &pages, 100, &reqs, 50, true) {
			t.Fatal("did not report budget reached at 50/50 requests")
		}
		if pages != 1 {
			t.Errorf("reserve consumed a page slot when the request budget stopped the crawl: pageCount = %d, want 1", pages)
		}
	})

	// The property this function exists for is exactness UNDER CONCURRENCY, and every
	// subtest above is single-goroutine. budgetReached takes a *sync.Mutex precisely
	// because N workers call it, yet nothing in the default suite ever called it from
	// more than one goroutine, and the only end-to-end assertion of the exact-page-cap
	// criterion (TestRodEngine_MaxPages) is behind //go:build integration and does not
	// run in CI. So nothing CI executed verified that concurrent reservation cannot
	// overshoot (LAB-4678 review, TEST-007).
	//
	// budgetReached is a pure function over pointers, so the invariant is directly
	// testable in microseconds under -race with no browser.
	t.Run("concurrent reservation admits exactly maxPages", func(t *testing.T) {
		const (
			goroutines = 200
			maxPages   = 37 // not a divisor of goroutines, so an off-by-one cannot hide
		)
		var (
			mu       sync.Mutex
			pages    int
			reqs     int
			admitted atomic.Int64
			wg       sync.WaitGroup
		)

		start := make(chan struct{})
		for range goroutines {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start // maximize contention on the compare-and-increment
				if !budgetReached(&mu, &pages, maxPages, &reqs, 0, true) {
					admitted.Add(1)
				}
			}()
		}
		close(start)
		wg.Wait()

		if got := admitted.Load(); got != maxPages {
			t.Errorf("admitted %d pages, want exactly %d: concurrent reservation "+
				"overshot or undershot the page cap", got, maxPages)
		}
		if pages != maxPages {
			t.Errorf("pageCount = %d, want exactly %d: reserved slots must equal admissions",
				pages, maxPages)
		}
	})

	// The mirror case for the request dimension: the request budget must also stop
	// admissions exactly, and must never consume a page slot when it is what stopped
	// the crawl.
	t.Run("concurrent calls stop exactly at the request cap", func(t *testing.T) {
		const (
			goroutines  = 200
			maxRequests = 25
		)
		var (
			mu       sync.Mutex
			pages    int
			reqs     = maxRequests // already at the bound
			admitted atomic.Int64
			wg       sync.WaitGroup
		)

		start := make(chan struct{})
		for range goroutines {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				if !budgetReached(&mu, &pages, 0, &reqs, maxRequests, true) {
					admitted.Add(1)
				}
			}()
		}
		close(start)
		wg.Wait()

		if got := admitted.Load(); got != 0 {
			t.Errorf("admitted %d pages with the request budget already exhausted, want 0", got)
		}
		if pages != 0 {
			t.Errorf("pageCount = %d, want 0: no page slot may be consumed when the "+
				"request budget is what stopped the crawl", pages)
		}
	})
}

// TestEnrichTarget_RedactsCredentialsInNavigationNotice pins the redaction on the
// interaction navigation notice. For the depth-0 visit pageURL is the seed exactly
// as the operator typed it, so echoing it raw wrote cleartext credentials to
// stderr, and stderr lands in CI job logs, shell scrollback, and any wrapper that
// captures the capability's output (LAB-4678 review, SEC-BE-005).
//
// navigated=true is the only branch that writes, and it ignores the page argument,
// so this needs no browser.
func TestEnrichTarget_RedactsCredentialsInNavigationNotice(t *testing.T) {
	var stderr bytes.Buffer
	e := &rodEngine{opts: engineOptions{Stderr: &stderr}}

	if got := e.enrichTarget(nil, true, "https://admin:s3cret@target.example.com/app"); got != nil {
		t.Error("enrichTarget must return nil when a click navigated away unrecoverably")
	}

	out := stderr.String()
	if out == "" {
		t.Fatal("no notice written")
	}
	for _, secret := range []string{"s3cret", "admin:"} {
		if strings.Contains(out, secret) {
			t.Errorf("credential %q leaked to stderr: %q", secret, out)
		}
	}
}

// urlEchoIdentifiers are the identifiers in this package that hold a RAW,
// operator-supplied URL, which may carry userinfo credentials. Identifiers holding
// a derived origin (originOf output, which is scheme://host and so cannot contain
// userinfo) are deliberately absent.
var urlEchoIdentifiers = []string{
	"pageURL", "targetURL", "seedURL", "rawURL", "effectiveURL",
	"entry.URL", "target.URL", "req.URL.String()", "info.URL",
}

// TestOperatorFacingURLEchoesAreRedacted is the class-level guard for SEC-BE-005.
// redactSeedURL was applied at nine echo sites and skipped at the one this PR added;
// reviewing the diff found the new line but nothing compared it against the
// established pattern. This scans every non-test file in the package for an
// operator-facing message that interpolates a raw-URL identifier and requires that
// argument to go through redactSeedURL, so the eleventh site cannot regress the way
// the tenth did.
//
// It parses with go/ast and inspects whole CALL EXPRESSIONS, not lines. A
// line-oriented scan silently missed any call whose format string and arguments sit
// on different lines, which is how several echoes in this package are already
// written — so a new unredacted echo wrapped across lines passed the guard, and the
// coverage floor below could not catch it either (CodeRabbit review of the
// SEC-BE-005 fix). Verified by mutation: a multi-line unredacted Fprintf now fails.
//
// It reads source rather than behavior on purpose: the alternative is one behavioral
// test per echo site, several of which need a live browser or a real redirect.
func TestOperatorFacingURLEchoesAreRedacted(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}

	checked := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}

		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !isMessageCall(call.Fun) {
				return true
			}
			for _, arg := range call.Args {
				inner, redacted := redactedArg(arg)
				name := types.ExprString(inner)
				if !slices.Contains(urlEchoIdentifiers, name) {
					continue
				}
				checked++
				if !redacted {
					pos := fset.Position(arg.Pos())
					t.Errorf("%s:%d passes raw URL identifier %q to %s without "+
						"redactSeedURL; an operator-supplied URL can carry userinfo "+
						"credentials and stderr lands in CI logs",
						f, pos.Line, name, types.ExprString(call.Fun))
				}
			}
			return true
		})
	}

	// If the identifier list ever stops matching the code, this guard silently passes
	// over everything. Assert it still finds the known sites.
	if checked < 5 {
		t.Errorf("matched only %d URL echo arguments; urlEchoIdentifiers has probably "+
			"drifted from the code and this guard is no longer checking anything", checked)
	}
}

// isMessageCall reports whether fn is one of the fmt calls that produce an
// operator-facing message. Restricted to these so an ordinary assignment or
// comparison mentioning a URL identifier is not treated as an echo.
func isMessageCall(fn ast.Expr) bool {
	name := types.ExprString(fn)
	return strings.HasPrefix(name, "fmt.Fprint") || name == "fmt.Errorf" || name == "fmt.Sprintf"
}

// redactedArg unwraps a redactSeedURL(x) argument, returning x and true. For any
// other expression it returns the expression unchanged and false. Checking each
// argument expression individually is what makes the guard insensitive to line
// breaks: it never has to see the call and its arguments on one line.
func redactedArg(arg ast.Expr) (inner ast.Expr, redacted bool) {
	call, ok := arg.(*ast.CallExpr)
	if !ok {
		return arg, false
	}
	ident, ok := call.Fun.(*ast.Ident)
	if !ok || ident.Name != "redactSeedURL" || len(call.Args) != 1 {
		return arg, false
	}
	return call.Args[0], true
}

// TestLearnSeedOrigin_OnlyTheSeedWidensScope pins the containment invariant that
// seedScope's whole argument rests on: only the seed's own navigation may widen
// scope. The gate used to be Depth == 0, which was a valid proxy only while the
// seed was the sole depth-0 entry.
//
// Resume broke that. resumeFrontier restores pending entries BEFORE the seed is
// pushed, and urlFrontier.Restore honors whatever Depth the checkpoint claims, so a
// restored entry carrying "Depth": 0 with a different URL is popped ahead of the
// seed and became the page whose post-redirect origin was learned. A checkpoint is
// unauthenticated by design, so anyone who could write to checkpoint storage chose
// which page decided the widening (LAB-4678 review, SEC-BE-004).
//
// The gate is reached before any CDP call, so a nil page exercises it: a rejected
// target returns before touching the page, and an accepted one would nil-panic —
// which is what makes "accepted" observable here without a browser.
func TestLearnSeedOrigin_OnlyTheSeedWidensScope(t *testing.T) {
	const seed = "https://target.example.com/app"

	cases := []struct {
		name         string
		target       urlEntry
		wantConsider bool
	}{
		{"the seed itself is considered", urlEntry{URL: seed, Depth: 0}, true},
		{"the seed at a non-zero depth is still the seed", urlEntry{URL: seed, Depth: 3}, true},
		// The regression: a checkpoint-injected entry claiming depth 0.
		{"a foreign URL claiming depth 0 is refused", urlEntry{URL: "https://attacker.example/x", Depth: 0}, false},
		{"an ordinary deeper page is refused", urlEntry{URL: "https://target.example.com/deep", Depth: 2}, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var learned []string
			e := &rodEngine{
				seedKey: frontierKey(seed),
				opts: engineOptions{
					LearnEffectiveOrigin: func(u string) { learned = append(learned, u) },
				},
			}

			// A considered target proceeds to page.Info() on the nil page and panics;
			// a refused one returns before touching it. Either way the callback must
			// not have fired, since a nil page yields no URL.
			considered := func() (reached bool) {
				defer func() { reached = recover() != nil }()
				e.learnSeedOrigin(nil, c.target)
				return false
			}()

			if considered != c.wantConsider {
				t.Errorf("target %+v: reached the page read = %v, want %v",
					c.target, considered, c.wantConsider)
			}
			if len(learned) != 0 {
				t.Errorf("LearnEffectiveOrigin called with %v from a nil page", learned)
			}
		})
	}
}

// TestLearnSeedOrigin_NoCallbackIsInert covers the nil-callback guard so the
// identity check cannot be reordered ahead of it into a nil dereference.
func TestLearnSeedOrigin_NoCallbackIsInert(t *testing.T) {
	e := &rodEngine{seedKey: frontierKey("https://ex.com/"), opts: engineOptions{}}
	// Must return without touching the nil page even for the seed itself.
	e.learnSeedOrigin(nil, urlEntry{URL: "https://ex.com/", Depth: 0})
}

// newTestEngine builds a rodEngine with no browser, for driving worker's budget and
// requeue logic directly. visit is stubbed, so nothing touches Chrome.
func newTestEngine(opts engineOptions, visit func(context.Context, urlEntry) ([]ObservedRequest, []string, error)) *rodEngine {
	e := &rodEngine{
		opts:     opts,
		frontier: newURLFrontier(opts.MaxDepth, opts.ScopeCheck),
		visit:    visit,
	}
	return e
}

// nRequests builds n distinct captured requests for one page, so a stubbed visit can
// return a realistic multi-request page the way a real SPA visit does.
func nRequests(pageURL string, n int) []ObservedRequest {
	out := make([]ObservedRequest, 0, n)
	for i := range n {
		out = append(out, ObservedRequest{
			Method: "GET",
			URL:    fmt.Sprintf("%s/xhr/%d", pageURL, i),
		})
	}
	return out
}

// TestWorker_MaxRequestsBudget_RodBackend covers --max-requests on the DEFAULT
// (headless) backend, which is the one Guard runs and the one that had no coverage at
// any level. The existing TestCrawl_MaxRequests_HTTPBackend sets Headless: false, so
// it exercises the net/http path where one page is one request and the request budget
// degenerates into a page cap; nothing verified that the rod worker consults the
// request budget at all (LAB-4678 review, TEST-004).
//
// It asserts the three properties the PR claims:
//   - the crawl stops taking new pages once reqCount >= MaxRequests,
//   - the entry dequeued but not visited is REQUEUED, so it survives into resume
//     state rather than being dropped,
//   - the documented bound holds: the final count exceeds MaxRequests by at most one
//     page's requests, and is not unbounded.
func TestWorker_MaxRequestsBudget_RodBackend(t *testing.T) {
	const (
		maxRequests       = 10
		requestsPerPage   = 4
		pagesInFrontier   = 20
		expectedOvershoot = requestsPerPage - 1 // the page that crosses the bound still finishes
	)

	var visited atomic.Int64
	visit := func(_ context.Context, target urlEntry) ([]ObservedRequest, []string, error) {
		visited.Add(1)
		// No links: the frontier is pre-seeded, so the budget is the only thing that
		// can stop the crawl and a failure shows up as a hang or an overshoot.
		return nRequests(target.URL, requestsPerPage), nil, nil
	}

	e := newTestEngine(engineOptions{
		MaxRequests: maxRequests,
		MaxDepth:    -1,
		Concurrency: 1,
	}, visit)

	entries := make([]urlEntry, 0, pagesInFrontier)
	for i := range pagesInFrontier {
		entries = append(entries, urlEntry{URL: fmt.Sprintf("https://ex.com/p%d", i), Depth: 1})
	}
	if got := e.frontier.Push(entries); got != pagesInFrontier {
		t.Fatalf("seeded %d entries, want %d", got, pagesInFrontier)
	}

	var (
		mu        sync.Mutex
		pageCount int
		reqCount  int
		emitted   atomic.Int64
	)

	done := make(chan struct{})
	go func() {
		e.worker(context.Background(), 0, func(ObservedRequest) { emitted.Add(1) }, &mu, &pageCount, &reqCount)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("worker did not terminate: the request budget must stop the loop, not spin")
	}

	got := int(emitted.Load())
	if got < maxRequests {
		t.Errorf("emitted %d requests, want at least the budget of %d", got, maxRequests)
	}
	if got > maxRequests+expectedOvershoot {
		t.Errorf("emitted %d requests, want at most %d (budget %d + one page's %d requests): "+
			"the overshoot must be bounded by one page, not unbounded",
			got, maxRequests+expectedOvershoot, maxRequests, requestsPerPage)
	}

	// The budget must stop the crawl well short of the frontier.
	if v := int(visited.Load()); v >= pagesInFrontier {
		t.Errorf("visited %d of %d pages: the request budget did not stop the crawl", v, pagesInFrontier)
	}

	// Unvisited pages must remain in resume state, including the entry that was
	// dequeued and then returned when the budget check fired.
	cp := e.frontier.Snapshot
	pending, _ := cp()
	if len(pending) == 0 {
		t.Fatal("no pending entries survived: pages the budget prevented from being " +
			"visited must be requeued for resume, not dropped")
	}
	if len(pending)+int(visited.Load()) < pagesInFrontier {
		t.Errorf("pending(%d) + visited(%d) = %d, want at least %d: an entry was dropped "+
			"rather than requeued", len(pending), visited.Load(), len(pending)+int(visited.Load()), pagesInFrontier)
	}
}

// TestWorker_MaxRequestsZeroIsUnlimited pins that the budget is opt-in: with
// MaxRequests unset the worker drains the frontier. A guard that treated 0 as "stop
// immediately" would make the flag's default silently disable the crawl.
func TestWorker_MaxRequestsZeroIsUnlimited(t *testing.T) {
	const pages = 6
	e := newTestEngine(engineOptions{MaxDepth: -1, Concurrency: 1},
		func(_ context.Context, target urlEntry) ([]ObservedRequest, []string, error) {
			return nRequests(target.URL, 3), nil, nil
		})

	entries := make([]urlEntry, 0, pages)
	for i := range pages {
		entries = append(entries, urlEntry{URL: fmt.Sprintf("https://ex.com/p%d", i), Depth: 1})
	}
	e.frontier.Push(entries)

	var (
		mu        sync.Mutex
		pageCount int
		reqCount  int
		emitted   atomic.Int64
	)
	e.worker(context.Background(), 0, func(ObservedRequest) { emitted.Add(1) }, &mu, &pageCount, &reqCount)

	if got := int(emitted.Load()); got != pages*3 {
		t.Errorf("emitted %d requests, want %d: MaxRequests=0 must mean unlimited", got, pages*3)
	}
}

// TestWorker_MaxRequestsOvershoot_ScalesWithConcurrency pins the ACTUAL --max-requests
// bound, which is not the one the docs used to state.
//
// TestWorker_MaxRequestsBudget_RodBackend runs at Concurrency=1, where the overshoot
// really is one page's requests. That made the documented bound ("the final count can
// exceed the bound by up to one page's worth of requests") look verified while the
// default is Concurrency=10. reqCount is incremented only AFTER a visit returns and
// the budget is consulted BEFORE one starts, so every worker can clear the check in
// that window: the bound is MaxRequests + (Concurrency x requests-per-page). Measured
// at the default concurrency, a budget of 10 emits 44 — over 3x the old claim, on a
// control an operator sets precisely because they are being careful with the target.
//
// The assertion is two-sided on purpose. The upper bound stops the overshoot from
// growing further; the lower bound is what fails if someone "fixes" the docs back to
// one page without changing the code, because a Concurrency=1-shaped expectation
// cannot hold here.
func TestWorker_MaxRequestsOvershoot_ScalesWithConcurrency(t *testing.T) {
	const (
		maxRequests     = 10
		requestsPerPage = 4
		pages           = 200
		concurrency     = DefaultConcurrency
	)

	// Every worker parks inside its visit long enough that all of them clear the
	// pre-visit budget check before any increments reqCount. This is the real
	// interleaving under a slow target, made deterministic.
	release := make(chan struct{})
	var arrived sync.WaitGroup
	arrived.Add(concurrency)
	var parked atomic.Bool
	visit := func(_ context.Context, target urlEntry) ([]ObservedRequest, []string, error) {
		if !parked.Load() {
			arrived.Done()
			<-release
		}
		return nRequests(target.URL, requestsPerPage), nil, nil
	}

	e := newTestEngine(engineOptions{
		MaxRequests: maxRequests,
		MaxDepth:    -1,
		Concurrency: concurrency,
	}, visit)

	entries := make([]urlEntry, 0, pages)
	for i := range pages {
		entries = append(entries, urlEntry{URL: fmt.Sprintf("https://ex.com/p%d", i), Depth: 1})
	}
	e.frontier.Push(entries)

	var (
		mu        sync.Mutex
		pageCount int
		reqCount  int
		emitted   atomic.Int64
		wg        sync.WaitGroup
	)
	for i := range concurrency {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			e.worker(context.Background(), id, func(ObservedRequest) { emitted.Add(1) }, &mu, &pageCount, &reqCount)
		}(i)
	}

	// Once all Concurrency workers are inside a visit, stop parking and let them run.
	arrived.Wait()
	parked.Store(true)
	close(release)
	wg.Wait()

	got := int(emitted.Load())
	onePageClaim := maxRequests + (requestsPerPage - 1)
	realBound := maxRequests + concurrency*requestsPerPage

	if got <= onePageClaim {
		t.Errorf("emitted %d requests, which is within the old one-page claim of %d. "+
			"At Concurrency=%d the overshoot MUST be larger; if the code now genuinely "+
			"bounds it this tightly, update the README/CLAUDE.md/engine.go wording that "+
			"this test exists to keep honest", got, onePageClaim, concurrency)
	}
	if got > realBound {
		t.Errorf("emitted %d requests, above the documented bound MaxRequests + "+
			"(Concurrency x requests-per-page) = %d + (%d x %d) = %d",
			got, maxRequests, concurrency, requestsPerPage, realBound)
	}
}
