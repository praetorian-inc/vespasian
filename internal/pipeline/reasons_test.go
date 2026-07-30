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

// This file is package pipeline (internal) so it can exercise the unexported
// logClassificationReasons helper directly. Most pipeline tests live in the
// external pipeline_test package; this one needs internal access.
package pipeline

import (
	"bytes"
	"strings"
	"testing"

	"github.com/praetorian-inc/vespasian/pkg/classify"
	"github.com/praetorian-inc/vespasian/pkg/crawl"
)

func cr(method, url, apiType, reason string, confidence float64) classify.ClassifiedRequest {
	return classify.ClassifiedRequest{
		ObservedRequest: crawl.ObservedRequest{Method: method, URL: url},
		IsAPI:           true,
		Confidence:      confidence,
		Reason:          reason,
		APIType:         apiType,
	}
}

// TestLogClassificationReasons_DeterministicOrder pins the AC1 guarantee that
// the -v explanation is byte-stable for a given input regardless of the order
// the classified requests arrive in (the sort.Strings at the end of
// logClassificationReasons). A regression in that sort would let the output
// vary run-to-run.
func TestLogClassificationReasons_DeterministicOrder(t *testing.T) {
	forward := []classify.ClassifiedRequest{
		cr("GET", "https://example.com/api/items", "rest", "content-type:application/json+path-heuristic", 0.95),
		cr("POST", "https://example.com/api/orders", "rest", "method:POST", 0.7),
		cr("GET", "https://example.com/api/users", "rest", "request-signal:accept:application/json", 0.6),
	}
	reversed := []classify.ClassifiedRequest{forward[2], forward[1], forward[0]}

	var bufFwd, bufRev bytes.Buffer
	logClassificationReasons(&bufFwd, forward)
	logClassificationReasons(&bufRev, reversed)

	if bufFwd.String() != bufRev.String() {
		t.Errorf("output depends on input order:\nforward:\n%s\nreversed:\n%s", bufFwd.String(), bufRev.String())
	}

	// The lines must be sorted (the sorted formatted string begins with the
	// left-padded method, so GET sorts before POST here).
	lines := strings.Split(strings.TrimRight(bufFwd.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d: %q", len(lines), bufFwd.String())
	}
	sorted := append([]string(nil), lines...)
	for i := 1; i < len(sorted); i++ {
		if sorted[i-1] > sorted[i] {
			t.Errorf("lines not sorted:\n%s", bufFwd.String())
		}
	}
}

// TestLogClassificationReasons_EmptyReason verifies an empty Reason renders as
// the "-" placeholder rather than a blank field.
func TestLogClassificationReasons_EmptyReason(t *testing.T) {
	var buf bytes.Buffer
	logClassificationReasons(&buf, []classify.ClassifiedRequest{
		cr("GET", "https://example.com/api/items", "rest", "", 0.6),
	})
	out := buf.String()
	if !strings.Contains(out, "reason=-") {
		t.Errorf("empty reason should render as %q, got: %q", "reason=-", out)
	}
}

// TestLogClassificationReasons_UnparseablePathFallback verifies that a URL with
// no parseable path falls back to printing the full URL instead of an empty
// path field.
func TestLogClassificationReasons_UnparseablePathFallback(t *testing.T) {
	// A URL with no path component (Path == "") triggers the fallback to the
	// full URL string.
	const rawURL = "https://api.example.com"
	var buf bytes.Buffer
	logClassificationReasons(&buf, []classify.ClassifiedRequest{
		cr("GET", rawURL, "rest", "path-heuristic", 0.6),
	})
	if !strings.Contains(buf.String(), rawURL) {
		t.Errorf("expected fallback to full URL %q, got: %q", rawURL, buf.String())
	}
}

// TestLogClassificationReasons_SanitizesTerminalEscapes verifies that control
// and escape bytes in the untrusted path and method are neutralized before the
// -v line is written to the operator's terminal (SEC-BE-001). A crawled/imported
// target can carry percent-decoded control bytes in its path (url.Parse decodes
// %1b into a raw ESC), which would otherwise inject ANSI sequences or split the
// log line.
func TestLogClassificationReasons_SanitizesTerminalEscapes(t *testing.T) {
	var buf bytes.Buffer
	logClassificationReasons(&buf, []classify.ClassifiedRequest{
		// Path carries a raw ESC (0x1b) + CSI clear-screen and an embedded
		// newline; method carries a raw ESC. Neither may reach the terminal raw.
		cr("GET\x1b[31m", "https://example.com/api/\x1b[2J\nitems", "rest", "path-heuristic", 0.6),
	})
	out := buf.String()
	if strings.ContainsRune(out, '\x1b') {
		t.Errorf("raw ESC byte reached terminal output: %q", out)
	}
	// The embedded newline in the path must be escaped, not emitted as a real
	// line break — the whole record must remain a single line (plus the trailing
	// newline the writer appends).
	if strings.Count(strings.TrimRight(out, "\n"), "\n") != 0 {
		t.Errorf("path newline was not neutralized (log-splitting): %q", out)
	}
	// The escaped form is present and the surrounding printable text survives.
	if !strings.Contains(out, `\x1b`) {
		t.Errorf("control byte should be escaped as \\x1b: %q", out)
	}
	if !strings.Contains(out, "items") {
		t.Errorf("printable path text should survive sanitization: %q", out)
	}
}

// TestLogNearMisses_DedupsByEndpoint verifies near-miss output collapses to one
// line per endpoint (method+path), matching how the classified half is
// deduplicated, so repeated below-threshold traffic cannot bury the signal.
//
// Scope of what this pins: query-only variants of one endpoint collapse. It does
// NOT distinguish endpoint-level from line-level dedup, because it cannot today —
// the near-miss band is [NearMissFloor, threshold) and the only REST confidence
// in that band is PathHeuristicBoost (0.15; the others are 0.6/0.7/0.8/0.85), so
// every near-miss for a given method+path renders an identical line either way.
// The key is endpoint identity so it stays correct if a future signal lands in
// the band with a different score.
func TestLogNearMisses_DedupsByEndpoint(t *testing.T) {
	var buf bytes.Buffer
	classifiers := []classify.APIClassifier{&classify.RESTClassifier{}}
	// Three query-only variants of one endpoint, plus a second distinct endpoint.
	requests := []crawl.ObservedRequest{
		{Method: "GET", URL: "https://example.com/api/thing"},
		{Method: "GET", URL: "https://example.com/api/thing?page=1"},
		{Method: "GET", URL: "https://example.com/api/thing?page=2"},
		{Method: "GET", URL: "https://example.com/api/other"},
	}
	logNearMisses(&buf, classifiers, requests, classify.DefaultConfidenceThreshold)

	out := buf.String()
	if out == "" {
		t.Fatal("expected near-miss output")
	}
	// One header line plus one line per distinct endpoint (/api/thing, /api/other).
	body := strings.Split(strings.TrimRight(out, "\n"), "\n")[1:]
	if len(body) != 2 {
		t.Errorf("got %d near-miss lines, want 2 (one per endpoint):\n%s", len(body), out)
	}
	var thing int
	for _, ln := range body {
		if strings.Contains(ln, "/api/thing") {
			thing++
		}
	}
	if thing != 1 {
		t.Errorf("endpoint /api/thing produced %d lines, want 1:\n%s", thing, out)
	}
}

// TestLogNearMisses_SanitizesTerminalEscapes verifies the near-miss -v output
// neutralizes control bytes too. Near-miss lines render the same untrusted
// crawled path as the classified lines, so both share classificationLine and
// the near-miss path must not become a second, unsanitized route to the
// operator's terminal (SEC-BE-001, extended to the Phase 1 near-miss output).
func TestLogNearMisses_SanitizesTerminalEscapes(t *testing.T) {
	var buf bytes.Buffer
	classifiers := []classify.APIClassifier{&classify.RESTClassifier{}}
	// A GET on an api-like path with no captured response and no API Accept
	// header scores the path boost alone (0.15) — inside the near-miss band
	// [NearMissFloor, threshold), so it is dropped from the spec but logged.
	//
	// The control bytes are percent-encoded, which is how they actually reach
	// this code: url.Parse REJECTS raw ASCII control characters outright (so a
	// raw-byte URL would never classify at all), but percent-DECODES %1b/%0a
	// into raw ESC and newline in u.Path — the decoded form classificationLine
	// must neutralize.
	requests := []crawl.ObservedRequest{
		{Method: "GET", URL: "https://example.com/api/%1b[2J%0aitems"},
	}
	logNearMisses(&buf, classifiers, requests, classify.DefaultConfidenceThreshold)

	out := buf.String()
	if out == "" {
		t.Fatal("expected a near-miss line for a path-boost-only api-path GET")
	}
	if strings.ContainsRune(out, '\x1b') {
		t.Errorf("raw ESC byte reached terminal output: %q", out)
	}
	if !strings.Contains(out, `\x1b`) {
		t.Errorf("control byte should be escaped as \\x1b: %q", out)
	}
	// One header line plus one endpoint line; the path's embedded newline must
	// not split the record into a third.
	if got := strings.Count(strings.TrimRight(out, "\n"), "\n"); got != 1 {
		t.Errorf("path newline was not neutralized (log-splitting), %d line breaks: %q", got, out)
	}
}

// TestLogClassificationReasons_NoOutput verifies the no-op guards: a nil writer
// must not panic, and an empty slice produces no output.
func TestLogClassificationReasons_NoOutput(t *testing.T) {
	// nil writer: must not panic and must not attempt to write.
	logClassificationReasons(nil, []classify.ClassifiedRequest{
		cr("GET", "https://example.com/api/items", "rest", "path-heuristic", 0.6),
	})

	// empty slice: no output.
	var buf bytes.Buffer
	logClassificationReasons(&buf, nil)
	if buf.Len() != 0 {
		t.Errorf("empty input should produce no output, got: %q", buf.String())
	}
}

// TestLogNearMisses_ReportsRecoveredNextRoutes is the end-to-end half of the
// Next.js reporting fix. README.md, CLAUDE.md and pkg/analyze/jsstatic/doc.go all
// state that routes recovered from App Router chunk URLs are surfaced under -v.
// Asserting the classifier's confidence band is not enough — logNearMisses applies
// its own floor, so the claim is only true if the route actually reaches this
// output. It did not: a page route scored 0, below classify.NearMissFloor, so it
// was filtered out here and the feature produced nothing an operator could see.
//
// /vaults/{vaultId} is the case the README leads with. The braces arrive
// percent-encoded because jsstatic resolves the route through
// url.ResolveReference, which is the form that actually reaches this code.
func TestLogNearMisses_ReportsRecoveredNextRoutes(t *testing.T) {
	var buf bytes.Buffer
	classifiers := []classify.APIClassifier{&classify.RESTClassifier{}}
	requests := []crawl.ObservedRequest{
		{Method: "GET", URL: "https://app.test/vaults/%7BvaultId%7D", Source: crawl.SourceNextPageRoute},
		{Method: "GET", URL: "https://app.test/api/files", Source: crawl.SourceNextRouteHandler},
	}
	logNearMisses(&buf, classifiers, requests, classify.DefaultConfidenceThreshold)

	out := buf.String()
	for _, want := range []string{"/vaults/{vaultId}", "/api/files"} {
		if !strings.Contains(out, want) {
			t.Errorf("recovered route %q is not reported under -v, so the Next.js "+
				"recovery feature has no observable output for it.\ngot:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "next-route-chunk") {
		t.Errorf("the -v line must name chunk-URL provenance as the reason, so an "+
			"operator can tell a recovered route from a genuine weak-signal endpoint.\ngot:\n%s", out)
	}
}
