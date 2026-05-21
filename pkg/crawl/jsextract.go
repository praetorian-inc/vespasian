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
	"strings"

	"github.com/BishopFox/jsluice"
	"github.com/go-rod/rod"
)

// jsExtractedURL represents an endpoint discovered by jsluice from JavaScript
// source code. It carries richer metadata than a plain URL string.
type jsExtractedURL struct {
	URL         string
	Method      string
	ContentType string
}

// extractURLsFromJS runs jsluice on JavaScript source code and returns
// discovered URLs. It filters out obviously non-API URLs (data: URIs,
// fragment-only refs, etc.).
func extractURLsFromJS(source []byte) []jsExtractedURL {
	if len(source) == 0 {
		return nil
	}

	analyzer := jsluice.NewAnalyzer(source)
	urls := analyzer.GetURLs()

	var results []jsExtractedURL
	for _, u := range urls {
		raw := strings.TrimSpace(u.URL)
		if raw == "" {
			continue
		}

		// Skip non-navigable URLs.
		lower := strings.ToLower(raw)
		if strings.HasPrefix(lower, "javascript:") ||
			strings.HasPrefix(lower, "data:") ||
			strings.HasPrefix(lower, "blob:") ||
			strings.HasPrefix(lower, "mailto:") ||
			strings.HasPrefix(lower, "tel:") {
			continue
		}

		// Skip placeholder/template URLs that jsluice couldn't fully resolve.
		if strings.Contains(raw, jsluice.ExpressionPlaceholder) {
			continue
		}

		method := strings.ToUpper(u.Method)
		if method == "" {
			method = "GET"
		}

		results = append(results, jsExtractedURL{
			URL:         raw,
			Method:      method,
			ContentType: u.ContentType,
		})
	}
	return results
}

// extractURLsFromInlineScripts collects all inline <script> tag contents from
// the current page DOM and runs jsluice on each. This captures endpoints
// defined in inline JavaScript that aren't in external .js files.
func extractURLsFromInlineScripts(page *rod.Page) []jsExtractedURL {
	elements, err := page.Elements("script:not([src])")
	if err != nil {
		return nil
	}

	var results []jsExtractedURL
	for _, el := range elements {
		text, err := el.Text()
		if err != nil || len(strings.TrimSpace(text)) == 0 {
			continue
		}
		results = append(results, extractURLsFromJS([]byte(text))...)
	}
	return results
}

// extractURLsFromResponses runs jsluice on captured JavaScript response bodies
// from network interception. This discovers endpoints embedded in external JS
// files that the browser downloaded but whose code paths weren't triggered
// during the page visit.
func extractURLsFromResponses(captured []ObservedRequest) []jsExtractedURL {
	var results []jsExtractedURL
	for _, req := range captured {
		ct := strings.ToLower(req.Response.ContentType)
		if !isJavaScriptContentType(ct) {
			continue
		}
		if len(req.Response.Body) == 0 {
			continue
		}
		results = append(results, extractURLsFromJS(req.Response.Body)...)
	}
	return results
}

// isJavaScriptContentType returns true if the content type indicates JavaScript.
func isJavaScriptContentType(ct string) bool {
	return strings.Contains(ct, "javascript") ||
		strings.Contains(ct, "ecmascript") ||
		ct == "text/js" ||
		ct == "application/x-js"
}

// jsExtractedToLinks resolves jsluice-discovered URLs against a base URL and
// returns them as plain URL strings suitable for pushing to the frontier.
// URLs pointing at static assets or streaming transports (JS/CSS/images/
// socket.io/...) are dropped — their content is already captured via network
// interception and navigating to them wastes the page budget (and produces
// nested "mangled" paths on SPA catch-all servers).
func jsExtractedToLinks(extracted []jsExtractedURL, baseURL string) []string {
	seen := make(map[string]bool)
	var links []string

	for _, e := range extracted {
		resolved, err := resolveURL(baseURL, e.URL)
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
	return links
}
