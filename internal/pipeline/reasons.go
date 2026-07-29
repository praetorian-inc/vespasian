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
		if u, err := url.Parse(c.URL); err == nil {
			switch {
			case u.Path != "":
				path = u.Path
			case u.Host != "":
				// Pathless (or query-only): print the origin, not the raw URL.
				// u.Host excludes userinfo (u.User holds it separately).
				path = u.Scheme + "://" + u.Host
			default:
				// Parsed, but neither Path nor Host survived (opaque forms), so
				// `path` still holds the raw c.URL.
				path = redactUserinfo(path)
			}
		} else {
			// url.Parse failed, so the switch never ran and `path` still holds
			// the raw c.URL. Reachable with credentials: GRPCClassifier fails
			// open on a malformed URL (pkg/classify/grpc.go) and still
			// classifies on content-type alone.
			path = redactUserinfo(path)
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

// redactUserinfo removes an embedded userinfo component from raw while
// preserving everything else, for the paths where url.Parse could not give us a
// structured URL to work from (a parse error, or an opaque form that yields
// neither Host nor Path).
//
// The search is confined to the AUTHORITY -- after "//" and before the next "/"
// -- because that is the only place RFC 3986 allows userinfo. An earlier version
// stripped at the last '@' anywhere in the string, which silently discarded the
// origin whenever a '@' appeared in the path: "http://evil.example:8o8/x@/api/v1/users"
// rendered as "/api/v1/users", concealing an attacker-controlled host and making
// it read as a local path. Preserving the origin matters more to an operator
// than trimming the path.
//
// With no "//" at all (opaque / scheme-colon form, e.g. "weird:u:p@h/api/x")
// there is no authority to scope to, so the last-'@' strip applies to the whole
// remainder -- that shape has no origin to conceal.
func redactUserinfo(raw string) string {
	start := strings.Index(raw, "//")
	if start < 0 {
		if i := strings.LastIndex(raw, "@"); i >= 0 {
			return raw[i+1:]
		}
		return raw
	}
	start += 2
	end := strings.IndexByte(raw[start:], '/')
	if end < 0 {
		end = len(raw)
	} else {
		end += start
	}
	authority := raw[start:end]
	i := strings.LastIndex(authority, "@")
	if i < 0 {
		return raw
	}
	return raw[:start] + authority[i+1:] + raw[end:]
}
