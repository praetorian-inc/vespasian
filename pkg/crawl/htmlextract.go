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
	links, base := extractFromHTMLDoc(doc, pageURL)
	return links, base
}

// extractFromHTMLDoc extracts navigable links and the effective base URL from
// an already-parsed *goquery.Document. It is the single-parse core shared by
// extractFromHTML and extractHTMLAndInlineScripts. Callers that need both links
// and inline-script results should use extractHTMLAndInlineScripts to avoid
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
// results from inline <script> tags. This avoids the double parse that would
// occur if extractFromHTML and extractInlineScripts were called separately on
// the same body (QUAL-002).
func extractHTMLAndInlineScripts(body []byte, pageURL string) (links []string, base string, inlineScripts []jsExtractedURL) {
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
	if err != nil {
		return nil, pageURL, nil
	}
	links, base = extractFromHTMLDoc(doc, pageURL)
	inlineScripts = extractInlineScriptsFromDoc(doc)
	return links, base, inlineScripts
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
	return extractInlineScriptsFromDoc(doc)
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
