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
