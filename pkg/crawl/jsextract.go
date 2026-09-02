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

	"github.com/praetorian-inc/vespasian/pkg/mediatype"
)

// jsExtractedURL is a jsluice endpoint with its metadata.
type jsExtractedURL struct {
	URL         string
	Method      string
	ContentType string
}

// extractURLsFromJS runs jsluice, dropping data: URIs and fragment-only refs.
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

// extractURLsFromInlineScripts covers endpoints defined inline rather than in
// external .js files.
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

// extractURLsFromResponses covers endpoints in downloaded JS whose code paths the
// page visit never triggered.
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

// Delegates to mediatype.IsJavaScript so pkg/classify's static-asset exclusion and this
// package's retention exemption test the same bytes; a second copy here let the scope
// filter admit a media type the classifier did not reject (LAB-4678).
func isJavaScriptContentType(ct string) bool {
	return mediatype.IsJavaScript(ct)
}

// jsExtractedToLinks resolves against base for the frontier, dropping static
// assets and streaming transports: they are not useful frontier targets, and
// navigating wastes the page budget and nests paths on SPA catch-all servers. On
// the headless path CDP interception has already captured their content.
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
