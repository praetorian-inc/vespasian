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

package mediatype

import "strings"

// Base returns the lowercased media type from a Content-Type value,
// stripping any charset/parameter suffix.
// E.g., "application/json; charset=utf-8" -> "application/json".
func Base(ct string) string {
	if ct == "" {
		return ""
	}
	if i := strings.Index(ct, ";"); i >= 0 {
		ct = ct[:i]
	}
	return strings.ToLower(strings.TrimSpace(ct))
}

// Header returns the value of the named header, matched case-insensitively,
// or "" if absent. It lives here because both classify and generate/rest need
// a case-insensitive header lookup (capture headers arrive lowercased from the
// browser but title-cased from Burp/HAR imports) and an import cycle prevents
// sharing it directly between those packages.
//
// The lookup is deterministic: an exact key match wins, and if only
// differently-cased variants exist (e.g. both "Content-Type" and
// "content-type" after merging capture sources) the lexicographically smallest
// matching key is chosen rather than whichever Go map iteration happens to
// yield first.
func Header(headers map[string]string, name string) string {
	if v, ok := headers[name]; ok {
		return v
	}
	match := ""
	found := false
	for k := range headers {
		if strings.EqualFold(k, name) && (!found || k < match) {
			match, found = k, true
		}
	}
	if !found {
		return ""
	}
	return headers[match]
}

// IsJavaScript reports whether ct names a JavaScript media type. ct may carry
// parameters; Base is applied internally, so a raw Content-Type header value works.
//
// It lives in this leaf package because two packages have to agree on the answer and
// used not to. pkg/crawl's passive-capture scope filter deliberately RETAINS an
// out-of-scope JavaScript body so pkg/analyze/jsstatic can read it, and it decides
// "this is JavaScript" from the content-type. pkg/classify has to exclude exactly what
// that filter admits, or the exemption becomes a scope escape: a bundle served from an
// extensionless URL as application/javascript was retained by the filter and then
// scored an endpoint by the JSON-body rule, putting an out-of-scope host in the emitted
// spec and its servers list. Both sides now call this, so the two predicates cannot
// drift apart (LAB-4678 review, REQ-005).
//
// The alternation is substring-based rather than an exact-match set because the
// registered and legacy spellings are numerous (application/javascript,
// text/javascript, application/x-javascript, application/ecmascript, …) and a set
// would have to be exhaustive to be correct, where a substring test fails safe: an
// unlisted JavaScript spelling containing "javascript" is still excluded.
func IsJavaScript(ct string) bool {
	base := Base(ct)
	return strings.Contains(base, "javascript") ||
		strings.Contains(base, "ecmascript") ||
		base == "text/js" ||
		base == "application/x-js"
}
