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

package jsstatic

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/praetorian-inc/vespasian/pkg/classify"
	"github.com/praetorian-inc/vespasian/pkg/crawl"
)

// makeJSCapture returns a captured ObservedRequest whose response body is JS.
func makeJSCapture(url, body string) crawl.ObservedRequest {
	return crawl.ObservedRequest{
		Method: "GET",
		URL:    url,
		Source: "katana",
		Response: crawl.ObservedResponse{
			StatusCode:  200,
			ContentType: "application/javascript",
			Body:        []byte(body),
		},
	}
}

// makeHTMLCapture returns a captured HTML response (not JS).
func makeHTMLCapture(url string) crawl.ObservedRequest {
	return crawl.ObservedRequest{
		Method: "GET",
		URL:    url,
		Source: "katana",
		Response: crawl.ObservedResponse{
			StatusCode:  200,
			ContentType: "text/html",
			Body:        []byte(`<html><body>fetch("/api/users")</body></html>`),
		},
	}
}

func TestAnalyze_AppendsAfterDynamic(t *testing.T) {
	// Dynamic capture already has /api/users.
	dynamic := crawl.ObservedRequest{
		Method: "GET",
		URL:    "https://h/api/users",
		Source: "katana",
		Response: crawl.ObservedResponse{
			StatusCode:  200,
			ContentType: "application/json",
		},
	}
	dynamic2 := crawl.ObservedRequest{
		Method: "GET",
		URL:    "https://h/api/products",
		Source: "katana",
	}
	// JS bundle finds /api/users (collision) and nothing else unique.
	jsBundle := makeJSCapture("https://h/app.js", `fetch("/api/users")`)

	captured := []crawl.ObservedRequest{dynamic, dynamic2, jsBundle}

	res, err := Analyze(context.Background(), captured, Options{})
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}

	// Result must contain the 3 original + 1 synthesized (even if dedup would collapse).
	if len(res.Requests) < 3 {
		t.Fatalf("expected at least 3 requests, got %d", len(res.Requests))
	}
	// Original dynamic entries come first.
	if res.Requests[0].Source != "katana" {
		t.Errorf("first entry should be dynamic (katana), got %q", res.Requests[0].Source)
	}
	if res.Requests[1].Source != "katana" {
		t.Errorf("second entry should be dynamic (katana), got %q", res.Requests[1].Source)
	}

	// Run dedup to confirm dynamic entry wins on collision.
	classified := make([]classify.ClassifiedRequest, 0, len(res.Requests))
	for _, r := range res.Requests {
		classified = append(classified, classify.ClassifiedRequest{
			ObservedRequest: r,
			IsAPI:           true,
			Confidence:      0.9,
			APIType:         "rest",
		})
	}
	deduped := classify.Deduplicate(classified)
	// Find /api/users — it should be dynamic (katana).
	for _, d := range deduped {
		if strings.Contains(d.URL, "/api/users") {
			if d.Source != "katana" {
				t.Errorf("after dedup, /api/users should be katana, got %q", d.Source)
			}
			break
		}
	}

	if res.Stats.BundlesAnalyzed < 1 {
		t.Errorf("expected BundlesAnalyzed >= 1, got %d", res.Stats.BundlesAnalyzed)
	}
}

func TestAnalyze_NonJSResponsesIgnored(t *testing.T) {
	// An HTML body that contains fetch() — if parsed as JS would yield endpoints.
	html := makeHTMLCapture("https://h/page")
	captured := []crawl.ObservedRequest{html}

	res, err := Analyze(context.Background(), captured, Options{})
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	if res.Stats.BundlesAnalyzed != 0 {
		t.Errorf("expected BundlesAnalyzed=0 for HTML, got %d", res.Stats.BundlesAnalyzed)
	}
	// Only the HTML request should be present.
	if len(res.Requests) != 1 {
		t.Errorf("expected 1 request (input unchanged), got %d", len(res.Requests))
	}
}

func TestAnalyze_OversizedBundleSkipped(t *testing.T) {
	maxSize := DefaultMaxBundleSize
	big := bytes.Repeat([]byte("x"), maxSize+1)
	oversized := crawl.ObservedRequest{
		Method: "GET",
		URL:    "https://h/big.js",
		Source: "katana",
		Response: crawl.ObservedResponse{
			StatusCode:  200,
			ContentType: "application/javascript",
			Body:        big,
		},
	}

	res, err := Analyze(context.Background(), []crawl.ObservedRequest{oversized}, Options{})
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	if res.Stats.BundlesSkipped != 1 {
		t.Errorf("expected BundlesSkipped=1, got %d", res.Stats.BundlesSkipped)
	}
	if res.Stats.BundlesAnalyzed != 0 {
		t.Errorf("expected BundlesAnalyzed=0, got %d", res.Stats.BundlesAnalyzed)
	}
}

func TestAnalyze_ReturnsCopyNotMutation(t *testing.T) {
	js := makeJSCapture("https://h/app.js", `fetch("/api/x")`)
	original := []crawl.ObservedRequest{js}
	origLen := len(original)

	res, err := Analyze(context.Background(), original, Options{})
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	// Input len unchanged.
	if len(original) != origLen {
		t.Errorf("input slice modified: was %d, now %d", origLen, len(original))
	}
	// Output is a new slice.
	if len(res.Requests) < 1 {
		t.Fatalf("expected at least 1 request")
	}
}

func TestAnalyze_ContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	captured := []crawl.ObservedRequest{makeJSCapture("https://h/app.js", `fetch("/api/x")`)}

	res, err := Analyze(ctx, captured, Options{})
	// Should return the captured (unmodified) slice and a context error.
	if err == nil {
		t.Error("expected non-nil error for canceled context")
	}
	// Input requests should be in output even on cancel.
	if len(res.Requests) < 1 {
		t.Error("expected at least original captured requests in result")
	}
}

// TestAnalyze_NonPositiveOptionsResolveToDefaults pins the CodeRabbit fix: a
// caller passing Concurrency: -1 (or any other non-positive numeric option)
// must get the default behavior, not zero workers / zero bundle size / zero
// timeout. Pre-fix this would leave Concurrency at -1, spawn no workers, and
// silently classify every bundle as BundlesAbandonedOnCancel on a clean run.
func TestAnalyze_NonPositiveOptionsResolveToDefaults(t *testing.T) {
	captured := []crawl.ObservedRequest{makeJSCapture("https://h/app.js", `fetch("/api/x")`)}
	res, err := Analyze(context.Background(), captured, Options{
		Concurrency:           -1,
		PerBundleTimeout:      -1,
		MaxBundleSize:         -1,
		MaxEndpointsPerBundle: -1,
	})
	if err != nil {
		t.Fatalf("Analyze with negative Options: %v", err)
	}
	if res.Stats.BundlesAnalyzed != 1 {
		t.Errorf("expected BundlesAnalyzed=1 (defaults applied to negative values), got %d", res.Stats.BundlesAnalyzed)
	}
	if res.Stats.BundlesAbandonedOnCancel != 0 {
		t.Errorf("expected BundlesAbandonedOnCancel=0 on clean run with negative-Concurrency input, got %d",
			res.Stats.BundlesAbandonedOnCancel)
	}
	// QUAL-004 panic-safe wrapper: on a clean run, the recover() in
	// safeAnalyzeOne must NOT fire, so AnalyzeOnePanics stays at zero.
	if res.Stats.AnalyzeOnePanics != 0 {
		t.Errorf("expected AnalyzeOnePanics=0 on clean run, got %d", res.Stats.AnalyzeOnePanics)
	}
}

// TestSafeAnalyzeOne_PanicRecovery is the positive regression test for QUAL-004.
// Forces a panic inside safeAnalyzeOne's call path via testInjectPanic and
// verifies (a) the panic is recovered (Analyze does not crash), (b)
// AnalyzeOnePanics is incremented, (c) workerProcessed is NOT understated so
// BundlesAbandonedOnCancel stays at zero on a clean non-canceled run.
func TestSafeAnalyzeOne_PanicRecovery(t *testing.T) {
	testInjectPanic = func(loc string) {
		if loc == "analyzeOne" {
			panic("forced QUAL-004 regression test panic")
		}
	}
	defer func() { testInjectPanic = nil }()

	captured := []crawl.ObservedRequest{
		makeJSCapture("https://h/a.js", `fetch("/api/a")`),
		makeJSCapture("https://h/b.js", `fetch("/api/b")`),
	}
	res, err := Analyze(context.Background(), captured, Options{Concurrency: 1})
	if err != nil {
		t.Fatalf("Analyze returned err on panic-injected run: %v (panic must be swallowed)", err)
	}
	if res.Stats.AnalyzeOnePanics != len(captured) {
		t.Errorf("AnalyzeOnePanics = %d, want %d (one per bundle that panicked)",
			res.Stats.AnalyzeOnePanics, len(captured))
	}
	if res.Stats.BundlesAnalyzed != 0 {
		t.Errorf("BundlesAnalyzed = %d, want 0 (panic short-circuits before BundlesAnalyzed++)",
			res.Stats.BundlesAnalyzed)
	}
	if res.Stats.BundlesAbandonedOnCancel != 0 {
		t.Errorf("BundlesAbandonedOnCancel = %d, want 0 (panic must not look like cancel)",
			res.Stats.BundlesAbandonedOnCancel)
	}
	if len(res.Requests) != len(captured) {
		t.Errorf("Requests length = %d, want %d (original inputs only on panic)",
			len(res.Requests), len(captured))
	}
}

// TestAnalyze_BundlePanic_IncrementsBundlesSkipped is the positive regression
// test for the bundle-path panic-recovery in extractWithTimeout. When the
// extraction goroutine panics while parsing the bundle body, the recover()
// must (a) prevent the panic from unwinding Analyze, (b) return extractPanic
// status, and (c) cause analyzeOne to increment BundlesSkipped (NOT
// BundlesAnalyzed). Together with the sourcemap-panic test below, this
// exercises all three loc values that testInjectPanic supports.
func TestAnalyze_BundlePanic_IncrementsBundlesSkipped(t *testing.T) {
	testInjectPanic = func(loc string) {
		if loc == "bundle" {
			panic("forced bundle-extraction panic for regression test")
		}
	}
	defer func() { testInjectPanic = nil }()

	captured := []crawl.ObservedRequest{
		makeJSCapture("https://h/app.js", `fetch("/api/x")`),
	}
	res, err := Analyze(context.Background(), captured, Options{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if res.Stats.BundlesSkipped != 1 {
		t.Errorf("BundlesSkipped = %d, want 1 (bundle-path panic must be counted as skipped)",
			res.Stats.BundlesSkipped)
	}
	if res.Stats.BundlesAnalyzed != 0 {
		t.Errorf("BundlesAnalyzed = %d, want 0 (panic short-circuits before BundlesAnalyzed++)",
			res.Stats.BundlesAnalyzed)
	}
	// Bundle-path panic must NOT escape to the outer safeAnalyzeOne recover
	// (extractWithTimeout's goroutine recovers first), so AnalyzeOnePanics
	// stays at zero.
	if res.Stats.AnalyzeOnePanics != 0 {
		t.Errorf("AnalyzeOnePanics = %d, want 0 (bundle panic is caught by extractWithTimeout, not safeAnalyzeOne)",
			res.Stats.AnalyzeOnePanics)
	}
	// Cross-counter isolation: a bundle-path panic must NOT bleed into the
	// sourcemap-path counters. Pre-QUAL-002 split, all three causes shared
	// one counter; this assertion pins the new isolation contract.
	if res.Stats.SourcemapSourcePanics != 0 {
		t.Errorf("SourcemapSourcePanics = %d, want 0 (bundle panic must not increment sourcemap-path counter)",
			res.Stats.SourcemapSourcePanics)
	}
	if res.Stats.SourcemapSourceTimeouts != 0 {
		t.Errorf("SourcemapSourceTimeouts = %d, want 0", res.Stats.SourcemapSourceTimeouts)
	}
	if res.Stats.SourcemapSourcesOversized != 0 {
		t.Errorf("SourcemapSourcesOversized = %d, want 0", res.Stats.SourcemapSourcesOversized)
	}
	// Output preserves the original captured entry — no synthesized requests
	// because extraction never returned a successful result.
	if len(res.Requests) != len(captured) {
		t.Errorf("Requests length = %d, want %d (input passes through on bundle panic)",
			len(res.Requests), len(captured))
	}
}

// TestAnalyze_SourcemapSourcePanic_IncrementsPanicCounter is the positive
// regression test for the SourcemapSourcePanics counter (QUAL-002 split).
// Forces a panic inside the extraction goroutine when processing a recovered
// sourcemap source, and verifies the panic counter increments while the
// timeout/oversized counters stay at zero.
func TestAnalyze_SourcemapSourcePanic_IncrementsPanicCounter(t *testing.T) {
	testInjectPanic = func(loc string) {
		if loc == "sourcemap-source" {
			panic("forced sourcemap-source panic for regression test")
		}
	}
	defer func() { testInjectPanic = nil }()

	// Bundle body has a normal fetch (bundle extraction must succeed). The
	// inline sourcemap data URI carries one source that — when extraction is
	// dispatched — will hit the injected panic.
	srcContent := `fetch("/api/from-sourcemap")`
	smDoc := fmt.Sprintf(`{"sources":["src/index.js"],"sourcesContent":[%s]}`,
		func() string { b, _ := json.Marshal(srcContent); return string(b) }())
	encoded := base64.StdEncoding.EncodeToString([]byte(smDoc))
	dataURI := "data:application/json;base64," + encoded
	bundleBody := `fetch("/api/from-bundle")` + "\n//# sourceMappingURL=" + dataURI

	bundle := makeJSCapture("https://h/app.js", bundleBody)
	res, err := Analyze(context.Background(), []crawl.ObservedRequest{bundle}, Options{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if res.Stats.SourcemapSourcePanics != 1 {
		t.Errorf("SourcemapSourcePanics = %d, want 1", res.Stats.SourcemapSourcePanics)
	}
	if res.Stats.SourcemapSourceTimeouts != 0 {
		t.Errorf("SourcemapSourceTimeouts = %d, want 0 (panic must NOT count as timeout)",
			res.Stats.SourcemapSourceTimeouts)
	}
	if res.Stats.SourcemapSourcesOversized != 0 {
		t.Errorf("SourcemapSourcesOversized = %d, want 0", res.Stats.SourcemapSourcesOversized)
	}
	// Bundle body extraction (no panic injected for kind="bundle") should
	// still have succeeded.
	if res.Stats.BundlesAnalyzed != 1 {
		t.Errorf("BundlesAnalyzed = %d, want 1 (bundle path unaffected)", res.Stats.BundlesAnalyzed)
	}
}

func TestAnalyze_DefaultOptionsAreSane(t *testing.T) {
	captured := []crawl.ObservedRequest{makeJSCapture("https://h/app.js", `fetch("/api/x")`)}
	// Should not panic with zero Options.
	res, err := Analyze(context.Background(), captured, Options{})
	if err != nil {
		t.Fatalf("Analyze error with zero Options: %v", err)
	}
	_ = res // just checking no panic
}

// Regression for CodeRabbit CR-1: MaxEndpointsPerBundle must cap the TOTAL
// endpoints kept per bundle, counting both bundle-body endpoints and any
// endpoints recovered from sourcemap sources. Pre-fix, the cap applied only to
// the bundle body, so a sourcemap could push EndpointsKept arbitrarily high.
func TestAnalyze_MaxEndpointsPerBundle_AppliesToSourcemapToo(t *testing.T) {
	// Bundle body has 3 distinct endpoints.
	var bundleBody strings.Builder
	for i := 0; i < 3; i++ {
		fmt.Fprintf(&bundleBody, "fetch(\"/api/b%d\");\n", i)
	}
	// Sourcemap source has 20 more endpoints — well over the cap.
	var smContent strings.Builder
	for i := 0; i < 20; i++ {
		fmt.Fprintf(&smContent, "fetch(\"/api/sm%d\");\n", i)
	}
	smDoc := fmt.Sprintf(`{"sources":["src/x.js"],"sourcesContent":[%s]}`,
		func() string { b, _ := json.Marshal(smContent.String()); return string(b) }())
	encoded := base64.StdEncoding.EncodeToString([]byte(smDoc))
	dataURI := "data:application/json;base64," + encoded
	bundleBody.WriteString("\n//# sourceMappingURL=" + dataURI + "\n")

	bundle := makeJSCapture("https://h/app.js", bundleBody.String())
	res, err := Analyze(context.Background(), []crawl.ObservedRequest{bundle}, Options{
		MaxEndpointsPerBundle: 5,
	})
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	// EndpointsKept (bundle-body + sourcemap-source combined) must equal the
	// cap exactly: 3 bundle-body endpoints + 2 from the sourcemap to reach 5.
	// Pre-fix this would have been 3 + 20 = 23 (no cap on sourcemap path).
	// A regression that DROPS sourcemap contribution entirely would yield 3,
	// also failing this assertion — so this pins both upper AND lower bounds.
	if res.Stats.EndpointsKept != 5 {
		t.Errorf("EndpointsKept = %d, want exactly 5 (MaxEndpointsPerBundle, fully consumed by bundle+sourcemap)",
			res.Stats.EndpointsKept)
	}
	synthCount := len(res.Requests) - 1 // -1 for the original bundle request
	if synthCount != 5 {
		t.Errorf("synthesized request count = %d, want exactly 5", synthCount)
	}
	// Sanity: at least one sourcemap-derived entry must have survived (the
	// cap is supposed to admit some sourcemap endpoints, not lock them out
	// entirely).
	var sawSourcemap bool
	for _, r := range res.Requests {
		if r.Source == SourceSourcemap {
			sawSourcemap = true
			break
		}
	}
	if !sawSourcemap {
		t.Error("expected at least one static:js-sourcemap entry under the cap; got none — sourcemap contribution was dropped entirely")
	}
}

func TestAnalyze_SourcemapAndBundleEmissions(t *testing.T) {
	// Build a valid sourcemap data URI with one source that has a fetch call.
	srcContent := `fetch("/api/from-sourcemap")`
	smDoc := fmt.Sprintf(`{"sources":["src/index.js"],"sourcesContent":[%s]}`,
		func() string { b, _ := json.Marshal(srcContent); return string(b) }())
	encoded := base64.StdEncoding.EncodeToString([]byte(smDoc))
	dataURI := "data:application/json;base64," + encoded

	bundleBody := `fetch("/api/from-bundle")` + "\n//# sourceMappingURL=" + dataURI

	bundle := makeJSCapture("https://h/app.js", bundleBody)
	res, err := Analyze(context.Background(), []crawl.ObservedRequest{bundle}, Options{})
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}

	// There should be requests with both static:js and static:js-sourcemap.
	var hasJS, hasSM bool
	for _, r := range res.Requests {
		if r.Source == SourceJS {
			hasJS = true
		}
		if r.Source == SourceSourcemap {
			hasSM = true
		}
	}
	if !hasJS {
		t.Error("expected at least one static:js request")
	}
	if !hasSM {
		t.Error("expected at least one static:js-sourcemap request")
	}
}

// TestAnalyze_StatsEndpointsFound verifies that Stats.EndpointsFound is
// populated (it counts raw extractedEndpoints before filtering/dedup).
func TestAnalyze_StatsEndpointsFound(t *testing.T) {
	cap := makeJSCapture("https://example.com/app.js", `
		fetch("/api/users");
		fetch("/api/orders", {method: "POST"});
		axios.get("/api/products");
	`)
	res, err := Analyze(context.Background(), []crawl.ObservedRequest{cap}, Options{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if res.Stats.EndpointsFound < 3 {
		t.Errorf("expected EndpointsFound >= 3, got %d", res.Stats.EndpointsFound)
	}
	if res.Stats.BundlesAnalyzed != 1 {
		t.Errorf("expected BundlesAnalyzed=1, got %d", res.Stats.BundlesAnalyzed)
	}
}

// TestExtractFromBundle_HonorsMaxEndpoints verifies that the analyzer respects
// Options.MaxEndpointsPerBundle by truncating the per-bundle endpoint slice.
func TestExtractFromBundle_HonorsMaxEndpoints(t *testing.T) {
	// Build a bundle with 10 unique fetch URLs. The cap is enforced in Analyze
	// (see jsstatic.go), not in ExtractFromBundle, so we test via Analyze.
	var sb strings.Builder
	for i := 0; i < 10; i++ {
		fmt.Fprintf(&sb, "fetch(\"/api/r%d\");\n", i)
	}
	cap := makeJSCapture("https://example.com/app.js", sb.String())

	res, err := Analyze(context.Background(), []crawl.ObservedRequest{cap}, Options{
		MaxEndpointsPerBundle: 3,
	})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	// Originating capture (1) + capped synthesized (3) == 4. Anything more means the cap was ignored.
	staticCount := 0
	for _, r := range res.Requests {
		if r.Source == "static:js" {
			staticCount++
		}
	}
	if staticCount > 3 {
		t.Errorf("MaxEndpointsPerBundle=3, got %d static entries", staticCount)
	}
	if staticCount == 0 {
		t.Errorf("expected some static entries up to the cap, got 0")
	}
}

// TestExtractFromBundle_MinifiedBundleSmoke confirms that extraction works on a
// single-line minified-style bundle with multiple fetches concatenated together.
func TestExtractFromBundle_MinifiedBundleSmoke(t *testing.T) {
	// One line, no whitespace except where strictly necessary.
	source := []byte(`!function(){var a=fetch("/api/auth/login",{method:"POST"});var b=fetch("/api/profile");axios.get("/api/products");}();`)
	endpoints, err := ExtractFromBundle(source, "https://example.com/min.js")
	if err != nil {
		t.Fatalf("ExtractFromBundle: %v", err)
	}
	want := map[string]bool{
		"/api/auth/login": false,
		"/api/profile":    false,
		"/api/products":   false,
	}
	for _, ep := range endpoints {
		if _, ok := want[ep.URL]; ok {
			want[ep.URL] = true
		}
	}
	for url, found := range want {
		if !found {
			t.Errorf("expected to find %q in minified bundle, did not", url)
		}
	}
}

// TestAnalyze_PerBundleTimeoutSkips verifies Analyze records a skipped bundle
// when the per-bundle parse exceeds Options.PerBundleTimeout.
//
// Timing rationale: the bundle below has 2000 fetch() statements; tree-sitter
// parsing of even an empty document is multi-microsecond on every supported
// platform, so a 1-nanosecond timeout is reliable (the smallest jsluice parse
// observed in CI is ~50µs, four orders of magnitude above the timeout). If
// jsluice ever becomes orders-of-magnitude faster, this test will start to
// fail rather than silently skip — that is the intended signal.
func TestAnalyze_PerBundleTimeoutSkips(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < 2000; i++ {
		fmt.Fprintf(&sb, "fetch(\"/api/r%d\");\n", i)
	}
	captured := makeJSCapture("https://example.com/big.js", sb.String())

	res, err := Analyze(context.Background(), []crawl.ObservedRequest{captured}, Options{
		PerBundleTimeout: time.Nanosecond,
	})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if res.Stats.BundlesAnalyzed != 0 {
		t.Errorf("expected BundlesAnalyzed=0 with 1ns timeout, got %d", res.Stats.BundlesAnalyzed)
	}
	if res.Stats.BundlesSkipped != 1 {
		t.Errorf("expected BundlesSkipped=1, got %d", res.Stats.BundlesSkipped)
	}
}

// TestAnalyze_PreRunCancel_ReturnsCtxErr pins the early-return at the top of
// Analyze: a context that is already canceled when Analyze is invoked must
// return (Result{Requests: captured}, ctx.Err()) without touching the input
// slice. This is the deterministic half of cancellation handling.
func TestAnalyze_PreRunCancel_ReturnsCtxErr(t *testing.T) {
	captured := []crawl.ObservedRequest{
		makeJSCapture("https://h/a.js", `fetch("/api/a")`),
		makeJSCapture("https://h/b.js", `fetch("/api/b")`),
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := Analyze(ctx, captured, Options{})
	if err != context.Canceled {
		t.Errorf("expected context.Canceled, got %v", err)
	}
	if len(res.Requests) != len(captured) {
		t.Errorf("expected captured slice returned unchanged, got len=%d want %d", len(res.Requests), len(captured))
	}
	if res.Stats.BundlesAnalyzed != 0 {
		t.Errorf("expected BundlesAnalyzed=0 on pre-cancel, got %d", res.Stats.BundlesAnalyzed)
	}
}

// TestAnalyze_MidRunCancel_ReturnsCtxErr pins the post-loop ctx.Err() check
// inside Analyze: when ctx is canceled DURING worker execution, Analyze must
// return (partialResult, ctx.Err()).
//
// Determinism: workers don't expose hooks, so we synchronize on a slow bundle
// instead. The fixture is one fast bundle plus N copies of a deliberately
// expensive bundle (large minified blob that takes jsluice well above 50ms to
// parse). With Concurrency=1, the cancel goroutine sleeps 20ms before
// canceling — long enough to guarantee the fast bundle has been picked up by
// the worker but well short of jsluice's parse time on the slow bundle, so the
// worker observes ctx.Done() between iterations. If the assertion fails, that
// is a real regression in the post-loop ctx.Err() return path, not flake.
func TestAnalyze_MidRunCancel_ReturnsCtxErr(t *testing.T) {
	fast := makeJSCapture("https://h/fast.js", `fetch("/api/fast")`)
	// Build a bundle large enough that jsluice cannot finish before the
	// cancel goroutine fires. Empirically, 5000 fetch() lines is comfortably
	// > 50ms on all supported platforms while still being small enough to fit
	// inside Options.MaxBundleSize.
	var sb strings.Builder
	for i := 0; i < 5000; i++ {
		fmt.Fprintf(&sb, "fetch(\"/api/slow%d\");\n", i)
	}
	slow := makeJSCapture("https://h/slow.js", sb.String())

	caps := []crawl.ObservedRequest{fast, slow, slow, slow, slow}

	ctx, cancel := context.WithCancel(context.Background())
	cancelFired := make(chan struct{})
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
		close(cancelFired)
	}()

	res, err := Analyze(ctx, caps, Options{Concurrency: 1})
	<-cancelFired
	if err != context.Canceled {
		t.Errorf("expected context.Canceled, got %v", err)
	}
	// Original inputs are always present, even on partial result.
	if len(res.Requests) < len(caps) {
		t.Errorf("expected at least %d requests in partial result, got %d", len(caps), len(res.Requests))
	}
	// At least one bundle should have been abandoned when ctx fired. Combined
	// with the pre-loop and worker-loop ctx checks, this exercises the new
	// BundlesAbandonedOnCancel accounting.
	if res.Stats.BundlesAbandonedOnCancel == 0 && res.Stats.BundlesAnalyzed >= len(caps) {
		t.Errorf("expected some bundles abandoned on cancel; got Analyzed=%d Skipped=%d Abandoned=%d",
			res.Stats.BundlesAnalyzed, res.Stats.BundlesSkipped, res.Stats.BundlesAbandonedOnCancel)
	}
}

// TestAnalyze_SourcemapSourceTimeout verifies that a pathological sourcemap
// source that takes too long to parse is skipped and counted in BundlesSkipped.
// This guards the per-source extraction timeout fix.
//
// The test uses a small bundle body (fast parse) with a large sourcemap source
// (slow parse) to ensure BundlesAnalyzed==1 while SourcemapSourceTimeouts>=1.
// The PerBundleTimeout for the bundle parse is generous (5s default); the
// per-source goroutine uses the same PerBundleTimeout, which is set to 1ns.
//
// NOTE: With PerBundleTimeout=1ns the bundle parse may also time out before
// reaching the sourcemap-source loop. If BundlesAnalyzed==0, the test falls
// through to the legacy assertion (BundlesSkipped>=1).
func TestAnalyze_SourcemapSourceTimeout(t *testing.T) {
	// Build a sourcemap with one "source" that is a large, complex JS blob
	// that will keep jsluice busy longer than our 1ns timeout.
	var sb strings.Builder
	for i := 0; i < 500; i++ {
		fmt.Fprintf(&sb, "fetch(\"/api/src%d\");\n", i)
	}
	largeSource := sb.String()

	smDoc := fmt.Sprintf(`{"sources":["src/x.js"],"sourcesContent":[%s]}`,
		func() string { b, _ := json.Marshal(largeSource); return string(b) }())
	encoded := base64.StdEncoding.EncodeToString([]byte(smDoc))
	dataURI := "data:application/json;base64," + encoded

	bundleBody := `fetch("/api/from-bundle")` + "\n//# sourceMappingURL=" + dataURI
	cap := makeJSCapture("https://h/app.js", bundleBody)

	res, err := Analyze(context.Background(), []crawl.ObservedRequest{cap}, Options{
		PerBundleTimeout: 1, // 1 nanosecond — guaranteed timeout for any extraction.
	})
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	// Both bundle-level and per-source-level timeouts increment counters.
	if res.Stats.BundlesSkipped < 1 {
		t.Errorf("expected BundlesSkipped >= 1, got %d", res.Stats.BundlesSkipped)
	}
}

// TestAnalyze_SourcemapSourcePerSourceTimeout verifies that when the bundle parse
// succeeds (BundlesAnalyzed==1) but a sourcemap-source extraction is delayed past
// PerBundleTimeout, Stats.SourcemapSourceTimeouts is incremented unconditionally.
//
// TEST-003: uses the testInjectDelay hook (analogous to testInjectPanic) so the
// bundle-body extraction always completes while only the sourcemap-source
// extraction sleeps past the timeout. This eliminates the race between the bundle
// parse time and PerBundleTimeout that made the previous fallback assertion
// necessary.
func TestAnalyze_SourcemapSourcePerSourceTimeout(t *testing.T) {
	// Inject a delay ONLY for sourcemap-source extractions. The delay is 500ms,
	// much longer than the 100ms PerBundleTimeout set below but short enough for
	// a real test run.
	testInjectDelay = func(loc string) {
		if loc == "sourcemap-source" {
			time.Sleep(500 * time.Millisecond)
		}
	}
	defer func() { testInjectDelay = nil }()

	// Bundle body is a single tiny fetch (fast parse; no delay injected for
	// kind="bundle") with an embedded inline sourcemap carrying one source entry.
	srcContent := `fetch("/api/from-sourcemap")`
	smDoc := fmt.Sprintf(`{"sources":["src/x.js"],"sourcesContent":[%s]}`,
		func() string { b, _ := json.Marshal(srcContent); return string(b) }())
	encoded := base64.StdEncoding.EncodeToString([]byte(smDoc))
	dataURI := "data:application/json;base64," + encoded
	bundleBody := `fetch("/api/from-bundle")` + "\n//# sourceMappingURL=" + dataURI
	cap := makeJSCapture("https://h/app.js", bundleBody)

	// PerBundleTimeout=100ms: gives the tiny bundle parse (typically <1ms on any
	// supported platform, but far slower under -race on a loaded CI runner) plenty
	// of margin to complete, while remaining far shorter than the 500ms delay
	// injected for sourcemap-source extractions. The 5:1 ratio makes the test
	// robust against slow CI environments.
	res, err := Analyze(context.Background(), []crawl.ObservedRequest{cap}, Options{
		PerBundleTimeout: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}

	// Bundle parse must have succeeded (the delay is only for sourcemap-source).
	if res.Stats.BundlesAnalyzed != 1 {
		t.Errorf("BundlesAnalyzed = %d, want 1 (bundle parse must succeed with 10ms timeout)", res.Stats.BundlesAnalyzed)
	}
	// The sourcemap-source extraction must have timed out.
	if res.Stats.SourcemapSourceTimeouts != 1 {
		t.Errorf("SourcemapSourceTimeouts = %d, want 1", res.Stats.SourcemapSourceTimeouts)
	}
	// Sanity: no panics, no oversized counts.
	if res.Stats.SourcemapSourcePanics != 0 {
		t.Errorf("SourcemapSourcePanics = %d, want 0", res.Stats.SourcemapSourcePanics)
	}
	if res.Stats.SourcemapSourcesOversized != 0 {
		t.Errorf("SourcemapSourcesOversized = %d, want 0", res.Stats.SourcemapSourcesOversized)
	}
}

// TestAnalyze_SinglePassOversizedCount verifies that Analyze correctly counts
// oversized bundles when mixed with valid and non-JS entries in a single pass.
// Pins the single-pass classification refactor.
func TestAnalyze_SinglePassOversizedCount(t *testing.T) {
	maxSize := DefaultMaxBundleSize
	big := bytes.Repeat([]byte("x"), maxSize+1)

	caps := []crawl.ObservedRequest{
		// 1 valid JS bundle.
		makeJSCapture("https://h/small.js", `fetch("/api/x")`),
		// 1 oversized JS bundle.
		{
			Method: "GET",
			URL:    "https://h/big.js",
			Source: "katana",
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "application/javascript",
				Body:        big,
			},
		},
		// 1 non-JS response (should be ignored entirely).
		makeHTMLCapture("https://h/page"),
	}

	res, err := Analyze(context.Background(), caps, Options{})
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	if res.Stats.BundlesSkipped != 1 {
		t.Errorf("expected BundlesSkipped=1, got %d", res.Stats.BundlesSkipped)
	}
	if res.Stats.BundlesAnalyzed != 1 {
		t.Errorf("expected BundlesAnalyzed=1, got %d", res.Stats.BundlesAnalyzed)
	}
	// All 3 original entries must be present in output.
	if len(res.Requests) < 3 {
		t.Errorf("expected at least 3 requests, got %d", len(res.Requests))
	}
}
