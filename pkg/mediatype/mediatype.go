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
