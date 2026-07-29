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
		// value falls through to crawl.RedactURL, which returns the URL with
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

// TestLogClassificationReasons_RedactsUserinfo pins that no URL shape carrying
// embedded userinfo reaches the -v Status output with its credential intact.
//
// The redaction is delegated to crawl.RedactURL (a pass-through to
// redactSeedURL, already tested in pkg/crawl), which FAILS CLOSED: whenever it
// cannot prove the result is credential-free it emits a placeholder rather than
// attempting to strip. Three hand-rolled strip attempts in this PR each shipped
// a new reachable defect -- concealing the origin, missing '?'/'#' as authority
// terminators, and leaking the opaque form where url.Parse leaves credentials in
// u.Opaque with u.User nil -- which is why the local helper was removed in
// favor of the reviewed one.
//
// Consequence worth naming: for a URL whose '@' is in the path rather than the
// userinfo, RedactURL cannot cheaply tell the two apart and emits the
// placeholder, and the operator loses host/path context. Note this applies only
// where RedactURL is reached at all: a '@' in the path of an otherwise VALID URL
// takes the u.Path arm and is printed verbatim ("/x@/api/v1/users"), so the
// context loss is confined to the opaque and parse-error shapes. That is a
// deliberate, documented false positive (see redactSeedURL's doc comment) and a
// strictly better failure mode than the alternative this PR shipped twice:
// silently rendering a truncated path that READ as legitimate while the
// attacker-controlled origin had been discarded.
//
// NOTE for alert triage: titus/kingfisher reports "Credentials in a URL"
// against the rawURL fixtures in the table below (e.g. code-scanning alert 112
// against the `http://user:pass@example.com` row). Every one is a synthetic
// `user:pass` against example.com or a syntactically invalid host, no host is
// ever dialed -- these rows never leave logClassificationReasons, which writes
// to an in-memory buffer here -- and the credential IS the input under test:
// this table exists precisely to prove a userinfo-bearing URL never renders its
// credential. Removing or masking the userinfo would delete the test's subject,
// and building the string from concatenated parts to slip past the scanner
// would hide the fixture from readers while defeating a control the repository
// relies on. The values are therefore retained deliberately; the alerts are
// expected and should be dismissed as used-in-tests.
//
// (Deliberately not enumerating the host forms: two prior attempts at that list
// were both wrong, once naming a loopback row that does not exist and once a
// .test domain no fixture uses.)
func TestLogClassificationReasons_RedactsUserinfo(t *testing.T) {
	const placeholder = "<URL with userinfo redacted>"
	for _, tc := range []struct{ name, rawURL, want string }{
		// NOTE: this row does NOT reach crawl.RedactURL. It parses cleanly with
		// a host and no path, so it takes the switch's u.Host arm, which builds
		// scheme://u.Host directly (u.Host excludes userinfo). Kept here because
		// it is the one userinfo-bearing shape that still renders a real value
		// rather than the placeholder -- useful contrast -- but the arm itself is
		// pinned by TestLogClassificationReasons_SwitchArmsRenderExpectedValue,
		// not by this row. Verified: mutating `u.User = nil` out of redactSeedURL
		// is caught by the authority-only row below, not by this one.
		{"host arm renders the origin (not via RedactURL)", "http://user:pass@example.com", "http://example.com"},
		// Authority-only userinfo.
		// Go's URL.String() omits the "//" once u.User is nil and Host is
		// empty, so this renders as "http:" -- credential-free.
		{"authority-only userinfo", "http://user:pass@", "http:"},
		// Opaque: credentials live in u.Opaque, u.User is nil -> fail closed.
		{"opaque form fails closed", "weird:user:pass@first@final.example.com/api/x", placeholder},
		// Opaque with a "//" later in the PATH -- the shape my authority-scoped
		// helper leaked verbatim.
		{"opaque with // in path fails closed", "https:user:pass@example.com//api/x", placeholder},
		// url.Parse error (invalid port) + "@" -> fail closed.
		{"parse error with userinfo fails closed", "http://user:pass@host:8o8/pkg.Svc/Method", placeholder},
		// A '@' in the PATH, indistinguishable from userinfo, so fail closed.
		// Reaches RedactURL via the url.Parse-ERROR branch (the ":8o8" port is
		// invalid), NOT the default arm -- both entry points are covered, this
		// row being one of the two error-branch cases. Deliberate false
		// positive -- reached here only because the invalid port forces a parse
		// error; the same path-'@' in a valid URL prints verbatim via arm 1.
		// The operator loses host/path context, but the origin is
		// never CONCEALED behind a plausible-looking path, which is the
		// regression this replaces.
		{"path @ fails closed rather than concealing the origin",
			"http://evil.attacker.example:8o8/x@/api/v1/users", placeholder},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			logClassificationReasons(&buf, []classify.ClassifiedRequest{
				cr("POST", tc.rawURL, "grpc", "content-type", 0.95),
			})
			out := buf.String()
			if !strings.Contains(out, tc.want) {
				t.Errorf("expected %q in output, got: %q", tc.want, out)
			}
			for _, cred := range []string{"user:pass", "u:p@", "user%3Apass"} {
				if strings.Contains(out, cred) {
					t.Errorf("credential %q leaked: %q", cred, out)
				}
			}
		})
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
