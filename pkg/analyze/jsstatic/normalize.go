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

	"github.com/BishopFox/jsluice"
)

// NormalizeEXPRPath turns jsluice EXPR placeholders into OpenAPI {paramName} from
// the supplied tokens, falling back to {param}, {param1}, … left to right. Query
// and fragment are preserved.
//
// Never fails: malformed URLs are rewritten best-effort, and an absolute URL with
// no path comes back unchanged.
func NormalizeEXPRPath(rawURL string, tokens []string) string {
	fragment := ""
	if idx := strings.Index(rawURL, "#"); idx != -1 {
		fragment = rawURL[idx:]
		rawURL = rawURL[:idx]
	}

	query := ""
	if idx := strings.Index(rawURL, "?"); idx != -1 {
		query = rawURL[idx:]
		rawURL = rawURL[:idx]
	}

	prefix := ""
	path := rawURL
	if i := strings.Index(rawURL, "://"); i != -1 {
		rest := rawURL[i+3:]
		slashIdx := strings.Index(rest, "/")
		if slashIdx != -1 {
			prefix = rawURL[:i+3+slashIdx]
			path = rawURL[i+3+slashIdx:]
		} else {
			return rawURL + query + fragment // no path to normalize
		}
	}

	// Read the placeholder from jsluice, which exports it as a var: an upstream
	// override then stays in sync with extractor.go.
	tokenIdx := 0
	unnamedCount := 0
	segments := strings.Split(path, "/")
	for i, seg := range segments {
		if seg != jsluice.ExpressionPlaceholder {
			continue
		}
		if tokenIdx < len(tokens) {
			segments[i] = "{" + tokens[tokenIdx] + "}"
			tokenIdx++
		} else {
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
