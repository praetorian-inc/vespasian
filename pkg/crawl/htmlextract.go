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

// extractFromHTMLDoc works on an already-parsed document. For links AND
// inline-script results use extractHTMLAndInlineScripts, which parses once.
func extractFromHTMLDoc(doc *goquery.Document, pageURL string) ([]string, string) {
	// Same scheme-downgrade and cross-host guards as the rod path.
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

// extractHTMLAndInlineScripts parses once, returning links, base and
// inline-script results.
func extractHTMLAndInlineScripts(body []byte, pageURL string) (links []string, base string, inlineScripts []jsExtractedURL) {
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
	if err != nil {
		return nil, pageURL, nil
	}
	links, base = extractFromHTMLDoc(doc, pageURL)
	inlineScripts = extractInlineScriptsFromDoc(doc)
	return links, base, inlineScripts
}

// extractInlineScriptsFromDoc runs jsluice on src-less <script> tags. Call it
// directly when a parsed doc is already in hand.
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
