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
	"bytes"

	"github.com/PuerkitoBio/goquery"
)

// extractFromHTML parses an HTML body and returns all navigable URLs discovered
// via the same linkSelectors set used by the rod-based extractLinks. Each raw
// attribute value is resolved against the effective base URL — the <base href>
// tag when present (matching the rod path's effectiveBaseURL call), otherwise
// pageURL — and filtered through isLikelyPage (dropping JS bundles, images,
// etc.). Scope enforcement is left to the frontier.
//
// This is the goquery analog of extractLinks (links.go:68) — same selectors
// and filters, no *rod.Page dependency.
func extractFromHTML(body []byte, pageURL string) []string {
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
	if err != nil {
		return nil
	}

	// Resolve the effective base URL: honor <base href> when present, applying
	// the same scheme-downgrade and cross-host guards as effectiveBaseURLFrom.
	base := pageURL
	if href, exists := doc.Find("base[href]").First().Attr("href"); exists {
		base = effectiveBaseURLFrom(href, pageURL)
	}

	seen := make(map[string]bool)
	var links []string

	for _, sel := range linkSelectors {
		doc.Find(sel.selector).Each(func(_ int, s *goquery.Selection) {
			raw, exists := s.Attr(sel.attribute)
			if !exists || raw == "" {
				return
			}

			resolved, err := resolveURL(base, raw)
			if err != nil {
				return
			}

			if !isLikelyPage(resolved) {
				return
			}

			if seen[resolved] {
				return
			}
			seen[resolved] = true
			links = append(links, resolved)
		})
	}

	return links
}

// extractEffectiveBase parses body for a <base href> element and returns the
// effective base URL for the page (applying the same scheme-downgrade and
// cross-host guards as effectiveBaseURLFrom). Returns pageURL when no valid
// <base href> is present. This is the pure-HTML analog of effectiveBaseURL
// (links.go), allowing callers to obtain the same base without re-parsing.
func extractEffectiveBase(body []byte, pageURL string) string {
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
	if err != nil {
		return pageURL
	}
	href, exists := doc.Find("base[href]").First().Attr("href")
	if !exists {
		return pageURL
	}
	return effectiveBaseURLFrom(href, pageURL)
}

// extractInlineScripts finds all inline <script> tags (those without a src
// attribute) in the HTML body and runs jsluice on each one. This is the goquery
// analog of extractURLsFromInlineScripts (jsextract.go:82) — same filtering,
// no *rod.Page dependency.
func extractInlineScripts(body []byte) []jsExtractedURL {
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
	if err != nil {
		return nil
	}

	var results []jsExtractedURL
	doc.Find("script:not([src])").Each(func(_ int, s *goquery.Selection) {
		text := s.Text()
		if len(text) == 0 {
			return
		}
		results = append(results, extractURLsFromJS([]byte(text))...)
	})
	return results
}
