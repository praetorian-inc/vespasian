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

// linkSelectors pairs each CSS selector with the attribute holding the URL.
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

// nonPageExtensions are never crawlable pages. Navigating to them wastes the page
// budget and, on SPA catch-all servers, nests paths (/socket.io/socket.io/...).
var nonPageExtensions = []string{
	".js", ".mjs", ".cjs", ".css", ".map",
	".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".bmp", ".avif",
	".woff", ".woff2", ".ttf", ".otf", ".eot",
	".mp3", ".mp4", ".webm", ".ogg", ".wav", ".avi", ".mov",
	".pdf", ".zip", ".tar", ".gz", ".rar", ".7z",
}

// nonPagePathSegments are streaming transports, matched per segment so /socket.io
// and /socket.io?EIO=… are caught alongside /socket.io/….
var nonPagePathSegments = []string{
	"socket.io",
	"engine.io",
}

// extractLinks returns navigable URLs from the DOM, resolved against baseURL,
// which the caller precomputes so this does not issue a CDP round-trip per page.
// Non-page resources are dropped — CDP interception already captured them.
func extractLinks(page *rod.Page, baseURL string) ([]string, error) {
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

// effectiveBaseURL mirrors the browser: <base href> if present, resolved against
// the page URL in case it is itself relative, else pageURL. The DOM read is split
// from [effectiveBaseURLFrom] so the resolution logic is testable without a
// browser.
func effectiveBaseURL(page *rod.Page, pageURL string) string {
	// Elements, not Element: the singular form waits until the page context times
	// out when the selector is absent, and most pages have no <base> — a 1s+ stall
	// on every visit.
	elements, err := page.Elements("base[href]")
	if err != nil || len(elements) == 0 {
		return pageURL
	}
	href, err := elements[0].Attribute("href")
	if err != nil || href == nil {
		return pageURL
	}
	return effectiveBaseURLFrom(*href, pageURL)
}

// effectiveBaseURLFrom resolves rawHref against pageURL, returning pageURL
// unchanged when the input is empty, unparseable, non-http(s), or fails either
// guard below.
//
// Scheme-downgrade guard: <base href="http://target.com/"> on an HTTPS crawl would
// resolve every relative ref to http://, stripping TLS from requests carrying the
// operator's Authorization, cookies and CSRF tokens. https base on an http page is
// safe and allowed.
//
// Cross-host guard: <base href="https://attacker.com/"> on an in-scope page, via
// stored XSS or an owned subdomain, must not re-anchor relative refs. Synthetic
// form ObservedRequests reach captured without a scope filter at this stage, so
// those entries would poison capture.json and the generated spec. Relative and
// root-relative bases still work — ResolveReference keeps them same-host
// (LAB-2221).
func effectiveBaseURLFrom(rawHref, pageURL string) string {
	href := strings.TrimSpace(rawHref)
	if href == "" {
		return pageURL
	}
	pageU, err := url.Parse(pageURL)
	if err != nil {
		return pageURL
	}
	refU, err := url.Parse(href)
	if err != nil {
		return pageURL
	}
	resolved := pageU.ResolveReference(refU)
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return pageURL
	}
	if pageU.Scheme == "https" && resolved.Scheme == "http" {
		return pageURL
	}
	if resolved.Host != "" && !strings.EqualFold(resolved.Host, pageU.Host) {
		return pageURL
	}
	return resolved.String()
}

// resolveURL rejects unparseable URLs and non-HTTP schemes.
func resolveURL(base, ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", url.EscapeError("empty reference")
	}

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

	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return "", url.EscapeError("non-http scheme")
	}

	resolved.Fragment = ""
	return resolved.String(), nil
}

// isLikelyPage keeps static assets and streaming transports out of the frontier.
// Advisory only, and permissive on parse failure — the frontier and scope stages
// still reject malformed URLs.
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
	// Last segment only: /assets/main.js/index is navigable, /assets/main.js is
	// a bundle.
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
