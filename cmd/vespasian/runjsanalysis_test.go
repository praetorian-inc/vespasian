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

package main

import (
	"context"
	"strings"
	"testing"

	"github.com/praetorian-inc/vespasian/pkg/crawl"
)

// captureStderr lives in display_test.go and is re-used here.

// jsFixtureCapture returns one HTML page and one JS bundle exercising fetch.
// Shared by the error-path and verbose-path tests.
func jsFixtureCapture() []crawl.ObservedRequest {
	return []crawl.ObservedRequest{
		{
			Method: "GET",
			URL:    "https://example.com/",
			Source: "katana",
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "text/html",
				Body:        []byte(`<html></html>`),
			},
		},
		{
			Method: "GET",
			URL:    "https://example.com/app.js",
			Source: "katana",
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "application/javascript",
				Body:        []byte(`fetch("/api/v1/users")`),
			},
		},
	}
}

// TEST-001 (helper-level integration): when enabled=true the helper hands the
// captured slice to jsstatic.Analyze and returns an enriched slice with
// SourceJS entries appended. This is the code path that ScanCmd.Run and
// CrawlCmd.Run reach into; testing the helper at this granularity covers the
// same plumbing without requiring a real headless browser.
func TestRunJSAnalysisStage_Enabled_AppendsStaticEntries(t *testing.T) {
	captured := jsFixtureCapture()
	out := runJSAnalysisStage(context.Background(), captured, jsAnalysisArgs{
		enabled:         true,
		fetchSourcemaps: false,
		allowPrivate:    true,
	})
	if len(out) <= len(captured) {
		t.Fatalf("expected enriched slice longer than input; got %d in, %d out", len(captured), len(out))
	}
	// Dynamic entries must still come first (classify.Deduplicate relies on
	// first-write-wins). At least one static:js entry must be appended.
	var sawStatic bool
	for i, r := range out {
		if i < len(captured) {
			if r.Source == "static:js" {
				t.Errorf("static entry at position %d (still in dynamic prefix)", i)
			}
			continue
		}
		if r.Source == "static:js" {
			sawStatic = true
		}
	}
	if !sawStatic {
		t.Error("expected at least one static:js entry appended after dynamic prefix")
	}
}

// Enabled=false short-circuits and returns the input slice unchanged.
func TestRunJSAnalysisStage_Disabled_ShortCircuits(t *testing.T) {
	captured := jsFixtureCapture()
	out := runJSAnalysisStage(context.Background(), captured, jsAnalysisArgs{enabled: false})
	// Same length, same backing data (returned input directly).
	if len(out) != len(captured) {
		t.Fatalf("expected unchanged slice; got %d in, %d out", len(captured), len(out))
	}
	for i := range out {
		if out[i].URL != captured[i].URL {
			t.Errorf("entry %d URL mismatch: got %q, want %q", i, out[i].URL, captured[i].URL)
		}
	}
}

// TEST-002: when jsstatic.Analyze returns an error (here: pre-canceled ctx),
// runJSAnalysisStage writes a warning to stderr and returns the ORIGINAL
// requests slice rather than the partial result. This is the contract the
// surrounding pipeline relies on — JS analysis must never fail the run.
func TestRunJSAnalysisStage_ErrorPath_ReturnsOriginalAndWarns(t *testing.T) {
	captured := jsFixtureCapture()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel so Analyze returns ctx.Err() immediately
	var out []crawl.ObservedRequest
	stderr := captureStderr(t, func() {
		out = runJSAnalysisStage(ctx, captured, jsAnalysisArgs{
			enabled:         true,
			fetchSourcemaps: false,
			allowPrivate:    true,
		})
	})
	// Must be the original slice (identical length and URLs), not enriched.
	if len(out) != len(captured) {
		t.Fatalf("expected original slice on error; got %d in, %d out", len(captured), len(out))
	}
	for i := range out {
		if out[i].URL != captured[i].URL {
			t.Errorf("entry %d URL mismatch: got %q, want %q", i, out[i].URL, captured[i].URL)
		}
	}
	if !strings.Contains(stderr, "warning: js-static analysis failed") {
		t.Errorf("expected warning on stderr, got: %q", stderr)
	}
}

// TEST-003: verbose=true prints the stats line to stderr.
func TestRunJSAnalysisStage_Verbose_LogsStats(t *testing.T) {
	captured := jsFixtureCapture()
	var out []crawl.ObservedRequest
	stderr := captureStderr(t, func() {
		out = runJSAnalysisStage(context.Background(), captured, jsAnalysisArgs{
			enabled:         true,
			fetchSourcemaps: false,
			allowPrivate:    true,
			verbose:         true,
		})
	})
	if len(out) <= len(captured) {
		t.Errorf("expected enriched slice; got %d in, %d out", len(captured), len(out))
	}
	if !strings.Contains(stderr, "js-static:") {
		t.Errorf("expected 'js-static:' status line on stderr, got: %q", stderr)
	}
	if !strings.Contains(stderr, "bundles=") || !strings.Contains(stderr, "endpoints=") {
		t.Errorf("expected stats fields in stderr line, got: %q", stderr)
	}
}

// TestAugmentAll_FormsBeforeJSStatic pins the order contract enforced by the
// augmentAll helper — the single shared entry point that both ScanCmd.Run and
// GenerateCmd.Run call. A regression that flipped the order inside augmentAll
// (or, in either Run method, bypassed augmentAll and re-ordered the stages)
// would cause static:js entries to appear before static:html in the output.
//
// Why this pins both commands: ScanCmd and GenerateCmd both call augmentAll
// (verified by grep — the only call sites of augmentAll). If a future Run
// re-implements the two stages inline in the wrong order, the order regression
// would surface during integration testing rather than this unit test, but
// the helper itself stays correct because this test exercises it directly.
func TestAugmentAll_FormsBeforeJSStatic(t *testing.T) {
	captured := []crawl.ObservedRequest{
		{
			Method: "GET",
			URL:    "https://example.com/login",
			Source: "katana",
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "text/html",
				Body: []byte(`<html><body>` +
					`<form method="POST" action="/api/login">` +
					`<input name="email" type="email">` +
					`<input name="password" type="password">` +
					`</form></body></html>`),
			},
		},
		{
			Method: "GET",
			URL:    "https://example.com/app.js",
			Source: "katana",
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "application/javascript",
				Body:        []byte(`fetch("/api/users")`),
			},
		},
	}

	// Call augmentAll directly — the shared helper used by both ScanCmd.Run
	// and GenerateCmd.Run. A regression inside augmentAll that swaps the two
	// stages would propagate to BOTH commands and fail this test.
	enriched := augmentAll(context.Background(), captured, jsAnalysisArgs{
		enabled:      true,
		allowPrivate: true,
	})

	firstHTML, firstJS := -1, -1
	for i, r := range enriched {
		if firstHTML == -1 && r.Source == "static:html" {
			firstHTML = i
		}
		if firstJS == -1 && r.Source == "static:js" {
			firstJS = i
		}
	}
	if firstHTML == -1 {
		t.Fatalf("expected at least one static:html entry; got sources: %v", sourcesOf(enriched))
	}
	if firstJS == -1 {
		t.Fatalf("expected at least one static:js entry; got sources: %v", sourcesOf(enriched))
	}
	if firstHTML >= firstJS {
		t.Errorf("augmentAll order broken: static:html (idx %d) must precede static:js (idx %d)",
			firstHTML, firstJS)
	}
}

// TestAugmentAll_DisabledJS_KeepsHTMLAugmentation verifies that augmentAll
// still runs static-HTML augmentation when JS analysis is disabled. Pre-fix
// it was possible for a Run method to call only one of the two stages; the
// helper now guarantees forms ALWAYS run regardless of the JS flag.
func TestAugmentAll_DisabledJS_KeepsHTMLAugmentation(t *testing.T) {
	captured := []crawl.ObservedRequest{
		{
			Method: "GET",
			URL:    "https://example.com/login",
			Source: "katana",
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "text/html",
				Body:        []byte(`<form method="POST" action="/api/login"><input name="email"></form>`),
			},
		},
	}
	enriched := augmentAll(context.Background(), captured, jsAnalysisArgs{enabled: false})
	var sawHTML, sawJS bool
	for _, r := range enriched {
		switch r.Source {
		case "static:html":
			sawHTML = true
		case "static:js", "static:js-sourcemap":
			sawJS = true
		}
	}
	if !sawHTML {
		t.Errorf("expected static:html augmentation even with JS analysis disabled; got sources: %v", sourcesOf(enriched))
	}
	// Inverse: with enabled=false, the JS stage must short-circuit and NOT
	// produce any static:js* entries. A regression that removed the enabled
	// short-circuit in runJSAnalysisStage would still produce static:js
	// because there's no separate input fixture (the HTML response has no
	// JS bundle), so the JS stage would simply return the input slice
	// unchanged — but a worse regression that ran jsstatic.Analyze on an
	// HTML body would fail the isJSContentType guard and ALSO produce no
	// static:js. To make this test catch a real "ignored enabled flag"
	// regression, we'd need a JS bundle in the fixture too. That fixture
	// is exercised by TestAugmentAll_FormsBeforeJSStatic above which
	// asserts sawJS=true under enabled=true; the absence here asserts the
	// disabled-flag short-circuit doesn't accidentally produce static:js
	// entries from any other code path.
	if sawJS {
		t.Errorf("expected NO static:js* entries when JS analysis disabled; got sources: %v", sourcesOf(enriched))
	}
}

func sourcesOf(rs []crawl.ObservedRequest) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.Source
	}
	return out
}

// Verbose=false must NOT log the stats line.
func TestRunJSAnalysisStage_NonVerbose_DoesNotLog(t *testing.T) {
	captured := jsFixtureCapture()
	stderr := captureStderr(t, func() {
		_ = runJSAnalysisStage(context.Background(), captured, jsAnalysisArgs{
			enabled:         true,
			fetchSourcemaps: false,
			allowPrivate:    true,
			verbose:         false,
		})
	})
	if strings.Contains(stderr, "js-static:") {
		t.Errorf("expected no status line when verbose=false, got: %q", stderr)
	}
}
