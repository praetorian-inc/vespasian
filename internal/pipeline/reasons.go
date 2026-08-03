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

package pipeline

import (
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
	"unicode"

	"github.com/praetorian-inc/vespasian/pkg/classify"
	"github.com/praetorian-inc/vespasian/pkg/crawl"
)

// sanitizeForTerminal replaces non-printable runes with an escaped \xNN form so
// crawled, attacker-controlled strings cannot inject terminal escape/control
// sequences when echoed to the operator's stderr under -v (CWE-150/CWE-117).
// This neutralizes ANSI CSI injection (ESC 0x1b), newline/carriage-return log
// splitting, and DEL/C1 controls, while leaving printable ASCII and legitimate
// non-ASCII path characters intact. url.Parse percent-decodes path segments, so
// a path like "/%1b[2J" arrives here as raw control bytes and must be escaped.
func sanitizeForTerminal(s string) string {
	if s == "" {
		return s
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			// Rebuild from the start; the inner binding is named rr so it is not
			// mistaken for the outer scan's r, which is unused from here on.
			var b strings.Builder
			b.Grow(len(s))
			for _, rr := range s {
				if unicode.IsPrint(rr) {
					b.WriteRune(rr)
				} else {
					fmt.Fprintf(&b, "\\x%02x", rr)
				}
			}
			return b.String()
		}
	}
	return s
}

// logClassificationReasons writes one line per classified endpoint to the
// verbose status writer, making the REST-vs-not decision explainable for a
// given input (LAB-4678). Output is deterministic — lines are sorted by
// method+path and each Reason is a pure function of the request — so the same
// input always produces the same explanation. It is a no-op when w is nil (the
// status writer is non-nil only under -v), so default artifacts are unchanged.
func logClassificationReasons(w io.Writer, classified []classify.ClassifiedRequest) {
	if w == nil || len(classified) == 0 {
		return
	}
	lines := make([]string, 0, len(classified))
	for _, c := range classified {
		lines = append(lines, classificationLine(c))
	}
	sort.Strings(lines)
	for _, ln := range lines {
		writeStatus(w, "%s\n", ln)
	}
}

// endpointPath reduces a request URL to its path component for display and for
// near-miss endpoint identity, falling back to the full URL when it does not
// parse or carries no path. Shared so the rendered line and the dedup key agree
// on what "the same endpoint" means.
func endpointPath(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil && u.Path != "" {
		return u.Path
	}
	return rawURL
}

// classificationLine formats one endpoint's verdict line for verbose output.
// Shared by logClassificationReasons and logNearMisses so the emitted and
// below-threshold lines have identical shape. The path is reduced to its URL
// path component; an empty Reason renders as "-".
func classificationLine(c classify.ClassifiedRequest) string {
	path := endpointPath(c.URL)
	reason := c.Reason
	if reason == "" {
		reason = "-"
	}
	// path and method derive from the crawled/imported request and are
	// attacker-influenced; sanitize before echoing to the terminal. APIType
	// and reason draw from fixed vocabularies (classifier names, allowlisted
	// media types, fixed tags) and need no sanitization.
	return fmt.Sprintf("  %-6s %s [type=%s confidence=%.2f reason=%s]",
		sanitizeForTerminal(strings.ToUpper(c.Method)), sanitizeForTerminal(path), c.APIType, c.Confidence, reason)
}

// logNearMisses writes, under -v, the endpoints that classified below the API
// threshold but at or above classify.NearMissFloor — requests dropped from the
// spec that still showed some API signal — so -v can explain why an expected
// endpoint is MISSING, not only why a present one is included (LAB-4678 Phase 1).
// It re-runs classification (cheap, in-memory, no probing) to recover the
// sub-threshold band that RunClassifiers discards. Output is deterministic
// (sorted) and it is a no-op when w is nil (i.e. not under -v), so default
// artifacts are unchanged.
func logNearMisses(w io.Writer, classifiers []classify.APIClassifier, requests []crawl.ObservedRequest, threshold float64) {
	if w == nil {
		return
	}
	nm := classify.NearMisses(classifiers, requests, classify.NearMissFloor, threshold)
	if len(nm) == 0 {
		return
	}
	// Collapse to one line per endpoint. NearMisses works over raw requests rather
	// than the deduplicated set, so a page firing the same below-threshold XHR
	// repeatedly would otherwise print one line per occurrence and bury the signal.
	// The key is method+path — endpoint identity, matching how the classified half
	// of this output is deduplicated (classify.Deduplicate) — rather than the
	// rendered line, so the same endpoint seen with differing confidence still
	// collapses. The highest-confidence observation wins as the most informative.
	best := make(map[string]classify.ClassifiedRequest, len(nm))
	for _, c := range nm {
		key := strings.ToUpper(c.Method) + " " + endpointPath(c.URL)
		if prev, ok := best[key]; ok && prev.Confidence >= c.Confidence {
			continue
		}
		best[key] = c
	}
	lines := make([]string, 0, len(best))
	for _, c := range best {
		lines = append(lines, classificationLine(c))
	}
	sort.Strings(lines)
	writeStatus(w, "near-miss endpoints (below threshold %.2f, not emitted):\n", threshold)
	for _, ln := range lines {
		writeStatus(w, "%s\n", ln)
	}
}
