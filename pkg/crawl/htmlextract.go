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

// extractFromHTMLDoc extracts navigable links and the effective base URL from
// an already-parsed *goquery.Document. Callers that need both links and
// inline-script results should use extractHTMLAndInlineScripts to avoid
// parsing the document twice.
func extractFromHTMLDoc(doc *goquery.Document, pageURL string) ([]string, string) {
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

// extractHTMLAndInlineScripts parses the HTML body exactly once and returns
// both the navigable links (with the effective base URL) and any jsluice
// results from inline <script> tags.
func extractHTMLAndInlineScripts(body []byte, pageURL string) (links []string, base string, inlineScripts []jsExtractedURL) {
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
	if err != nil {
		return nil, pageURL, nil
	}
	links, base = extractFromHTMLDoc(doc, pageURL)
	inlineScripts = extractInlineScriptsFromDoc(doc)
	return links, base, inlineScripts
}

// extractInlineScriptsFromDoc runs jsluice on all inline <script> tags (those
// without a src attribute) in an already-parsed *goquery.Document. Callers
// that hold a doc from a prior parse should call this directly to avoid
// re-parsing the body.
func extractInlineScriptsFromDoc(doc *goquery.Document) []jsExtractedURL {
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
