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

package jsstatic

import (
	"fmt"
	"strings"
)

// exprPlaceholder is jsluice's ExpressionPlaceholder value.
const exprPlaceholder = "EXPR"

// NormalizeEXPRPath replaces jsluice EXPR placeholders in a URL's path with
// OpenAPI-style {paramName} segments using the supplied template tokens. If a
// segment's identifier cannot be resolved, it is replaced with {param},
// {param1}, {param2}, … in left-to-right order. Query string and fragment are
// preserved unchanged.
//
// This function never fails — every input string is normalized to some output.
// (Earlier revisions exposed an error return that was always nil; callers had
// dead error-handling branches.) Malformed URLs are returned with their EXPR
// segments rewritten on a best-effort basis; absolute URLs without a path are
// returned unchanged.
func NormalizeEXPRPath(rawURL string, tokens []string) string {
	// Split off fragment first (it comes after #).
	fragment := ""
	if idx := strings.Index(rawURL, "#"); idx != -1 {
		fragment = rawURL[idx:]
		rawURL = rawURL[:idx]
	}

	// Split off query string.
	query := ""
	if idx := strings.Index(rawURL, "?"); idx != -1 {
		query = rawURL[idx:]
		rawURL = rawURL[:idx]
	}

	// For absolute URLs, split scheme+host from path.
	prefix := ""
	path := rawURL
	if i := strings.Index(rawURL, "://"); i != -1 {
		// Find end of authority (first "/" after "://").
		rest := rawURL[i+3:]
		slashIdx := strings.Index(rest, "/")
		if slashIdx != -1 {
			prefix = rawURL[:i+3+slashIdx]
			path = rawURL[i+3+slashIdx:]
		} else {
			// No path component — nothing to normalize.
			return rawURL + query + fragment
		}
	}

	// Replace EXPR segments with {paramName}.
	tokenIdx := 0
	unnamedCount := 0
	segments := strings.Split(path, "/")
	for i, seg := range segments {
		if seg != exprPlaceholder {
			continue
		}
		if tokenIdx < len(tokens) {
			segments[i] = "{" + tokens[tokenIdx] + "}"
			tokenIdx++
		} else {
			// Fallback naming: first unnamed gets {param}, subsequent get {param1}, {param2}, …
			if unnamedCount == 0 {
				segments[i] = "{param}"
			} else {
				segments[i] = fmt.Sprintf("{param%d}", unnamedCount)
			}
			unnamedCount++
		}
	}

	return prefix + strings.Join(segments, "/") + query + fragment
}
