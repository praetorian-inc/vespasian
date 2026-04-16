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

package crawl

import (
	"net/url"
	"strings"

	"github.com/go-rod/rod"
)

// linkSelectors defines the CSS selectors and their attributes to extract URLs
// from the DOM. Each selector is paired with the attribute that holds the URL.
var linkSelectors = []struct {
	selector  string
	attribute string
}{
	{"a[href]", "href"},
	{"form[action]", "action"},
	{"iframe[src]", "src"},
	{"area[href]", "href"},
	{"[data-href]", "data-href"},
	{"[data-url]", "data-url"},
}

// extractLinks extracts all navigable URLs from the current page DOM.
// It queries for links, forms, iframes, and common SPA data attributes,
// resolving all URLs to absolute form against the page's current URL.
// Returned URLs are deduplicated.
func extractLinks(page *rod.Page) ([]string, error) {
	pageInfo, err := page.Info()
	if err != nil {
		return nil, err
	}
	baseURL := pageInfo.URL

	seen := make(map[string]bool)
	var links []string

	for _, sel := range linkSelectors {
		elements, err := page.Elements(sel.selector)
		if err != nil {
			continue // non-fatal: some selectors may not match
		}
		for _, el := range elements {
			raw, err := el.Attribute(sel.attribute)
			if err != nil || raw == nil || *raw == "" {
				continue
			}

			resolved, err := resolveURL(baseURL, *raw)
			if err != nil {
				continue
			}

			if seen[resolved] {
				continue
			}
			seen[resolved] = true
			links = append(links, resolved)
		}
	}

	return links, nil
}

// resolveURL resolves a potentially relative URL against the base URL.
// It returns an error for unparseable URLs and skips non-HTTP schemes
// (javascript:, mailto:, data:, etc.).
func resolveURL(base, ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", url.EscapeError("empty reference")
	}

	// Skip non-navigable schemes early.
	lower := strings.ToLower(ref)
	if strings.HasPrefix(lower, "javascript:") ||
		strings.HasPrefix(lower, "mailto:") ||
		strings.HasPrefix(lower, "data:") ||
		strings.HasPrefix(lower, "tel:") ||
		strings.HasPrefix(lower, "blob:") {
		return "", url.EscapeError("non-navigable scheme")
	}

	baseU, err := url.Parse(base)
	if err != nil {
		return "", err
	}

	refU, err := url.Parse(ref)
	if err != nil {
		return "", err
	}

	resolved := baseU.ResolveReference(refU)

	// Only keep HTTP(S) URLs.
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return "", url.EscapeError("non-http scheme")
	}

	// Strip fragment for cleaner URLs.
	resolved.Fragment = ""
	return resolved.String(), nil
}
