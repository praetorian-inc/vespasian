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
			var b strings.Builder
			b.Grow(len(s))
			for _, r := range s {
				if unicode.IsPrint(r) {
					b.WriteRune(r)
				} else {
					fmt.Fprintf(&b, "\\x%02x", r)
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
		path := c.URL
		if u, err := url.Parse(c.URL); err == nil && u.Path != "" {
			path = u.Path
		}
		reason := c.Reason
		if reason == "" {
			reason = "-"
		}
		// path and method derive from the crawled/imported request and are
		// attacker-influenced; sanitize before echoing to the terminal. APIType
		// and reason draw from fixed vocabularies (classifier names, allowlisted
		// media types, fixed tags) and need no sanitization.
		lines = append(lines, fmt.Sprintf("  %-6s %s [type=%s confidence=%.2f reason=%s]",
			sanitizeForTerminal(strings.ToUpper(c.Method)), sanitizeForTerminal(path), c.APIType, c.Confidence, reason))
	}
	sort.Strings(lines)
	for _, ln := range lines {
		writeStatus(w, "%s\n", ln)
	}
}
