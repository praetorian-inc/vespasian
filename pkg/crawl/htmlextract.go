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

// extractFromHTML parses an HTML body once and returns (links, base): all
// navigable URLs discovered via the same linkSelectors set used by the
// rod-based extractLinks, plus the effective base URL it resolved them against.
// The base is the <base href> tag when present (matching the rod path's
// effectiveBaseURL call, applying the same scheme-downgrade and cross-host
// guards via effectiveBaseURLFrom), otherwise pageURL. Links are filtered
// through isLikelyPage (dropping JS bundles, images, etc.); scope enforcement
// is left to the frontier. Returning the base lets callers resolve other
// page-relative URLs (e.g. inline-script endpoints) against the same base
// without re-parsing the body.
//
// This is the goquery analog of extractLinks (links.go:68) — same selectors
// and filters, no *rod.Page dependency.
func extractFromHTML(body []byte, pageURL string) ([]string, string) {
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
	if err != nil {
		return nil, pageURL
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

	return links, base
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
