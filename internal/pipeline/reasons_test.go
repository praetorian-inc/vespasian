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

// TestLogClassificationReasons_SwitchArmsRenderExpectedValue pins each arm of
// logClassificationReasons' path-rendering switch to the EXACT value it should
// print. Both non-default arms were previously unpinned: replacing arm 1's
// guard with `case false:` (so paths render as origins) and reducing arm 2 to
// u.Hostname() (dropping the port) each survived the whole suite, because the
// only coverage asserted a substring the leaky forms also satisfied.
func TestLogClassificationReasons_SwitchArmsRenderExpectedValue(t *testing.T) {
	for _, tc := range []struct {
		name, rawURL, want, mustNotContain string
	}{
		// Arm 1: a path is present, so print the path -- NOT the origin.
		// mustNotContain pins that it does NOT fall through to the origin form.
		{
			"path arm prints the path",
			"https://api.example.com:8443/api/v1/users", "/api/v1/users",
			"https://api.example.com:8443/api/v1/users",
		},
		// Arm 2: pathless, so print scheme://host INCLUDING the port (which
		// u.Hostname() would silently drop) and WITHOUT the query. The
		// query-drop is what makes deleting the arm visible: without it the
		// value falls through to redactUserinfo, which returns the URL with
		// its query intact, and a bare Contains(want) still passed (mutant M9).
		{
			"host arm keeps the port and drops the query",
			"https://api.example.com:8443?x=1", "https://api.example.com:8443",
			"?x=1",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			logClassificationReasons(&buf, []classify.ClassifiedRequest{
				cr("GET", tc.rawURL, "rest", "path-heuristic", 0.6),
			})
			out := buf.String()
			if !strings.Contains(out, tc.want) {
				t.Errorf("expected rendered value %q, got: %q", tc.want, out)
			}
			if strings.Contains(out, tc.mustNotContain) {
				t.Errorf("arm rendered %q, which it must not: %q", tc.mustNotContain, out)
			}
		})
	}
}

// TestLogClassificationReasons_UnparseablePathFallback verifies that a URL with
// no parseable path falls back to the origin rather than an empty path field.
func TestLogClassificationReasons_UnparseablePathFallback(t *testing.T) {
	// A URL with no path component (Path == "") triggers the origin fallback.
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

// TestLogClassificationReasons_StripsUserinfoExactly pins the LOGIC of the
// last-'@' strip, not merely its presence. Three mutants survived when only
// "does not contain user:pass" was asserted: LastIndex->Index (strips at the
// FIRST '@'), path[i+1:]->path[i:] (keeps the '@'), and replacing the strip
// with path="" (silently guts the whole -v diagnostic). Asserting the EXACT
// rendered remainder kills all three.
//
// Both credential-carrying branches are covered: the switch's default arm
// (url.Parse succeeds but yields neither Path nor Host) and the url.Parse
// ERROR branch (reachable because GRPCClassifier fails open on a malformed URL
// and still classifies on content-type alone).
func TestLogClassificationReasons_StripsUserinfoExactly(t *testing.T) {
	for _, tc := range []struct {
		name, rawURL, want, mustNotContain string
	}{
		{
			// Opaque form: url.Parse fills u.Opaque, leaves Host/Path empty and
			// u.User NIL -> default arm. Two '@' so first-vs-last differ.
			name: "default arm strips at the last @",
			// user:pass is synthetic; final.example.com is an RFC 2606 reserved
			// domain. The fixture asserts the credential is NOT printed.
			rawURL:         "weird:user:pass@first@final.example.com/api/x",
			want:           "final.example.com/api/x",
			mustNotContain: "first@",
		},
		{
			// Invalid port -> url.Parse ERROR -> switch skipped entirely.
			// redactUserinfo is authority-scoped, so the ORIGIN survives; only
			// the userinfo is removed.
			name: "parse-error branch strips userinfo and keeps the origin",
			// user:pass is synthetic; ":8o8" is an intentionally invalid port so
			// url.Parse fails. The fixture asserts non-disclosure.
			rawURL:         "http://user:pass@host:8o8/pkg.Svc/Method",
			want:           "http://host:8o8/pkg.Svc/Method",
			mustNotContain: "user:pass",
		},
		{
			// REGRESSION GUARD: a '@' in the PATH must never be mistaken for a
			// userinfo delimiter. A last-'@'-anywhere strip rendered this as
			// "/api/v1/users", concealing the attacker-controlled origin so it
			// read as a local path -- worse for an operator than the leak it was
			// closing. The whole URL must survive untouched.
			name:           "a @ in the path does not conceal the origin",
			rawURL:         "http://evil.attacker.example:8o8/x@/api/v1/users",
			want:           "http://evil.attacker.example:8o8/x@/api/v1/users",
			mustNotContain: "zz-never-present-zz",
		},
		{
			// Two '@' inside the authority: strip to the LAST, keep the origin.
			// u:p is synthetic; example.test is reserved.
			name:           "multiple @ within the authority",
			rawURL:         "http://u:p@a@host.example.test:8o8/p",
			want:           "http://host.example.test:8o8/p",
			mustNotContain: "u:p@",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			logClassificationReasons(&buf, []classify.ClassifiedRequest{
				cr("POST", tc.rawURL, "grpc", "content-type", 0.95),
			})
			out := buf.String()
			// Kills strip->path="" (nothing rendered) and Index (wrong remainder).
			if !strings.Contains(out, tc.want) {
				t.Errorf("expected rendered remainder %q, got: %q", tc.want, out)
			}
			// Kills LastIndex->Index for the two-'@' case, and any credential leak.
			if strings.Contains(out, tc.mustNotContain) {
				t.Errorf("unexpected %q in output: %q", tc.mustNotContain, out)
			}
			// Kills path[i+1:]->path[i:] (a retained '@' before the remainder).
			// Skipped where want legitimately contains its own '@' (the
			// path-@ regression case above).
			if !strings.Contains(tc.want, "@") && strings.Contains(out, "@"+tc.want) {
				t.Errorf("strip kept the '@' separator: %q", out)
			}
			if strings.Contains(out, "user:pass") {
				t.Errorf("credential leaked: %q", out)
			}
		})
	}
}

// TestLogClassificationReasons_PathlessUserinfoURLNoCredentialLeak verifies
// that a pathless (or query-only) URL carrying embedded HTTP Basic userinfo
// never has that credential printed to the -v Status output. logPath's
// fallback previously used the full raw URL whenever u.Path == "", which
// echoes userinfo verbatim for a URL like "http://user:pass@host" (no path)
// or "http://user:pass@host?x=1" (query only, still no path). user:pass is
// synthetic test data, not a real secret.
func TestLogClassificationReasons_PathlessUserinfoURLNoCredentialLeak(t *testing.T) {
	// Each URL shape below embeds a synthetic credential (user:pass, RFC 2606
	// domain) and must NOT have it echoed to Status. They exercise three
	// distinct arms of logClassificationReasons' switch, and each was verified
	// to leak before the arm covering it existed:
	//
	//   pathless-with-host      -> u.Host arm      (u.Host excludes userinfo)
	//   scheme-colon / opaque   -> default arm     (url.Parse fills u.Opaque and
	//                                               leaves u.User NIL, so a
	//                                               u.User check misses it)
	//   authority-only userinfo -> default arm     (u.User set, Host+Path empty)
	//
	// The last two fell through to printing the raw URL until the default arm
	// was added; a u.Path-bearing URL is covered by the sibling tests above.
	for _, raw := range []string{
		"http://user:pass@example.com",
		"https:user:pass@example.com/api/x",
		"http://user:pass@",
	} {
		var buf bytes.Buffer
		logClassificationReasons(&buf, []classify.ClassifiedRequest{
			cr("GET", raw, "rest", "path-heuristic", 0.6),
		})
		out := buf.String()
		if strings.Contains(out, "user:pass") {
			t.Errorf("credential leaked into Status output for %q: %q", raw, out)
		}
		if strings.Contains(out, "pass@") {
			t.Errorf("partial credential leaked into Status output for %q: %q", raw, out)
		}
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
