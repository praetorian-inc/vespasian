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

// nonPageExtensions lists URL path suffixes for resources that are never
// crawlable HTML pages. Navigating to them wastes the page budget and can
// produce recursive "nested" paths on SPAs whose server returns a catch-all
// HTML body for any path (e.g., /socket.io/socket.io/... on Juice Shop).
var nonPageExtensions = []string{
	".js", ".mjs", ".cjs", ".css", ".map",
	".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".bmp", ".avif",
	".woff", ".woff2", ".ttf", ".otf", ".eot",
	".mp3", ".mp4", ".webm", ".ogg", ".wav", ".avi", ".mov",
	".pdf", ".zip", ".tar", ".gz", ".rar", ".7z",
}

// nonPagePathSegments lists path segments that indicate real-time or
// streaming transports rather than crawlable pages. Matching is done per
// path segment (split on "/") so that bare forms like /socket.io and
// /socket.io?EIO=… are caught alongside /socket.io/…. Navigating to these
// endpoints would either 400 or (on SPA catch-all servers) return the SPA
// shell HTML and trigger the same app code again at a nested path.
var nonPagePathSegments = []string{
	"socket.io",
	"engine.io",
}

// extractLinks extracts all navigable URLs from the current page DOM.
// It queries for links, forms, iframes, and common SPA data attributes,
// resolves all URLs against the page's <base href> (falling back to the
// current page URL if no base tag is present), and filters out non-page
// resources (JS bundles, images, fonts, socket.io, etc.) whose content is
// already captured via CDP network interception.
func extractLinks(page *rod.Page) ([]string, error) {
	pageInfo, err := page.Info()
	if err != nil {
		return nil, err
	}
	baseURL := effectiveBaseURL(page, pageInfo.URL)

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

			if !isLikelyPage(resolved) {
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

// effectiveBaseURL returns the URL that relative references on the page should
// be resolved against. It mirrors the browser's algorithm: use <base href>
// when present (resolving it against the current page URL first in case the
// base tag itself holds a relative value), otherwise fall back to the page
// URL. Returns pageURL on any parse failure.
func effectiveBaseURL(page *rod.Page, pageURL string) string {
	// Use Elements (plural) rather than Element: the singular variant
	// waits/retries until the page's context timeout when the selector
	// is absent. Most pages have no <base>, so this would add a 1s+
	// stall to every page visit.
	elements, err := page.Elements("base[href]")
	if err != nil || len(elements) == 0 {
		return pageURL
	}
	href, err := elements[0].Attribute("href")
	if err != nil || href == nil || strings.TrimSpace(*href) == "" {
		return pageURL
	}

	pageU, err := url.Parse(pageURL)
	if err != nil {
		return pageURL
	}
	refU, err := url.Parse(strings.TrimSpace(*href))
	if err != nil {
		return pageURL
	}
	resolved := pageU.ResolveReference(refU)
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return pageURL
	}
	return resolved.String()
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

// isLikelyPage returns true when rawURL is plausibly a crawlable HTML page.
// It rejects URLs with obvious non-HTML file extensions and known
// non-crawlable transport paths (socket.io, engine.io). Returning false
// prevents the frontier from enqueuing a URL whose only content is static
// assets already captured via network interception, or an endpoint whose
// SPA catch-all response would cause recursive path nesting.
//
// Parse failures return true (permissive): the frontier/scope stages can
// still reject malformed URLs. The function is advisory, not authoritative.
func isLikelyPage(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return true
	}
	path := strings.ToLower(u.Path)
	for _, seg := range strings.Split(path, "/") {
		if seg == "" {
			continue
		}
		for _, blocked := range nonPagePathSegments {
			if seg == blocked {
				return false
			}
		}
	}
	// Look at the last segment only — a path like /assets/main.js/index
	// would be navigable, but /assets/main.js itself is a bundle.
	last := path
	if idx := strings.LastIndex(path, "/"); idx >= 0 {
		last = path[idx+1:]
	}
	for _, ext := range nonPageExtensions {
		if strings.HasSuffix(last, ext) {
			return false
		}
	}
	return true
}
