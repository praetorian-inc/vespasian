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
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// JSReplayConfig configures the JS API path extraction and probing step.
type JSReplayConfig struct {
	// Headers are injected into every probe request (e.g., Authorization).
	Headers map[string]string

	// Timeout is the per-request timeout. Defaults to 10 seconds.
	Timeout time.Duration

	// MaxEndpoints limits the number of URLs probed. Defaults to 500.
	MaxEndpoints int

	// Client is the HTTP client. If nil, a default client is created.
	Client *http.Client

	// Verbose enables debug logging to Stderr.
	Verbose bool

	// Stderr is the writer for debug output. Defaults to io.Discard.
	Stderr io.Writer
}

// withDefaults fills in zero-value fields with sensible defaults.
func (cfg JSReplayConfig) withDefaults() JSReplayConfig {
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.MaxEndpoints == 0 {
		cfg.MaxEndpoints = 500
	}
	if cfg.Client == nil {
		cfg.Client = &http.Client{
			Timeout: cfg.Timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	if cfg.Stderr == nil {
		cfg.Stderr = io.Discard
	}
	return cfg
}

// maxReplayBodySize limits response body reads during probing (1 MB).
const maxReplayBodySize = 1 << 20

// maxJSBodySize limits the JS body read for API path extraction (10 MB).
// This is intentionally larger than MaxResponseBodySize (1 MB) used during crawl,
// because SPA JS bundles are often >1 MB and the API paths may be past the
// crawl truncation point.
const maxJSBodySize = 10 << 20

// jsContentTypes identifies JavaScript response content types.
var jsContentTypes = []string{
	"application/javascript",
	"text/javascript",
	"application/x-javascript",
}

// --- Extraction patterns ---

// apiPathPattern matches API-like path strings in single/double-quoted JS strings.
// Captures paths containing /api/, /v1/, /v2/, /rest/, /rpc/, /graphql.
var apiPathPattern = regexp.MustCompile(
	`["']` +
		`(/?` +
		`(?:[a-zA-Z0-9_-]+/)*` +
		`(?:api/|v[1-9][0-9]*/|rest/|rpc/|graphql)` +
		`[a-zA-Z0-9/_\{}.:-]*)` +
		`["']`,
)

// templateLiteralPattern matches API-like paths in JS template literals (backticks).
// Handles interpolation placeholders like ${id} by treating ${ as a path terminator.
var templateLiteralPattern = regexp.MustCompile(
	"`" +
		`(/?` +
		`(?:[a-zA-Z0-9_-]+/)*` +
		`(?:api/|v[1-9][0-9]*/|rest/|rpc/|graphql)` +
		`[a-zA-Z0-9/_\{}.:-]*)` +
		"(?:`|\\$\\{)",
)

// fullURLPattern matches full API URLs (http/https) in JS strings.
// E.g., "https://api.example.com/v1/users"
var fullURLPattern = regexp.MustCompile(
	`["'` + "`]" +
		`(https?://[a-zA-Z0-9._-]+(?::[0-9]+)?` +
		`/(?:[a-zA-Z0-9_-]+/)*` +
		`(?:api/|v[1-9][0-9]*/|rest/|rpc/|graphql)` +
		`[a-zA-Z0-9/_\{}.:-]*)` +
		`["'` + "`]",
)

// servicePrefixPattern matches service prefix strings concatenated with API paths.
// E.g., "identity/" + "api/auth/login" — captures "identity/".
var servicePrefixPattern = regexp.MustCompile(
	`["']([a-zA-Z][a-zA-Z0-9_-]{1,30}/)["']\s*\+\s*["'](?:api/|v[1-9])`,
)

// apiIndicators are the path segments that signal an API endpoint.
var apiIndicators = []string{"api/", "v1/", "v2/", "v3/", "v4/", "rest/", "rpc/", "graphql"}

// staticFileExts are file extensions to skip when extracting API paths.
var staticFileExts = []string{".js", ".css", ".map", ".html", ".htm", ".png", ".jpg", ".svg"}

// --- Helper functions ---

// isJSResponse reports whether the response content type indicates JavaScript.
func isJSResponse(contentType string) bool {
	ct := strings.ToLower(contentType)
	if idx := strings.Index(ct, ";"); idx != -1 {
		ct = strings.TrimSpace(ct[:idx])
	}
	for _, jsCT := range jsContentTypes {
		if ct == jsCT {
			return true
		}
	}
	return false
}

// isJSURL reports whether the URL path ends with a JavaScript file extension.
func isJSURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	lower := strings.ToLower(u.Path)
	return strings.HasSuffix(lower, ".js") || strings.HasSuffix(lower, ".mjs")
}

// isStaticFile reports whether a path looks like a static file reference.
func isStaticFile(path string) bool {
	lower := strings.ToLower(path)
	for _, ext := range staticFileExts {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

// hasInlinePrefix reports whether the path has a non-API segment before the
// first API indicator, meaning it already contains a service prefix
// (e.g., "identity/api/..." or "community/v2/...").
// Paths like "api/v2/users" do NOT have an inline prefix — "api/" before "v2/"
// is itself an API indicator, not a service prefix.
func hasInlinePrefix(trimmedPath string) bool {
	// Find the earliest API indicator in the path.
	earliest := -1
	for _, indicator := range apiIndicators {
		idx := strings.Index(trimmedPath, indicator)
		if idx >= 0 && (earliest < 0 || idx < earliest) {
			earliest = idx
		}
	}
	// If the first API indicator is not at the start, there's a prefix before it.
	return earliest > 0
}

// resolveBaseURL extracts the scheme and host from a target URL.
func resolveBaseURL(targetURL string) string {
	u, err := url.Parse(targetURL)
	if err != nil {
		return targetURL
	}
	return u.Scheme + "://" + u.Host
}

// --- Extraction logic ---

// extractServicePrefixes discovers service prefix strings using two strategies:
//
//  1. JS concatenation pattern: "identity/" + "api/auth/login"
//  2. Crawl results: Katana extracts prefix strings from JS and resolves them
//     relative to the JS file URL, producing URLs like /static/js/identity/.
//     These are identified by matching crawl results whose source is a JS file
//     and whose URL is a single segment appended to the JS file's directory.
func extractServicePrefixes(jsBody []byte, requests []ObservedRequest) []string {
	seen := make(map[string]bool)
	var prefixes []string

	add := func(prefix string) {
		if !seen[prefix] {
			seen[prefix] = true
			prefixes = append(prefixes, prefix)
		}
	}

	// Strategy 1: JS concatenation pattern ("prefix/" + "api/...").
	for _, match := range servicePrefixPattern.FindAllSubmatch(jsBody, -1) {
		if len(match) >= 2 {
			add(string(match[1]))
		}
	}

	// Strategy 2: Crawl results — find URLs extracted from JS files that are
	// a single path segment appended to the JS directory (e.g., /static/js/identity/).
	jsURLs := make(map[string]bool)
	for _, req := range requests {
		if isJSURL(req.URL) {
			jsURLs[req.URL] = true
		}
	}

	for _, req := range requests {
		// Only consider results sourced from a JS file.
		if !isJSURL(req.Source) {
			continue
		}
		if !jsURLs[req.Source] {
			continue
		}

		// Parse both URLs to compare paths.
		srcURL, err1 := url.Parse(req.Source)
		reqURL, err2 := url.Parse(req.URL)
		if err1 != nil || err2 != nil {
			continue
		}

		// Get the JS file's directory and the request path.
		jsDir := srcURL.Path[:strings.LastIndex(srcURL.Path, "/")+1]
		reqPath := reqURL.Path

		// Check if reqPath is jsDir + "word/" (single segment under JS directory).
		if !strings.HasPrefix(reqPath, jsDir) {
			continue
		}
		suffix := strings.TrimPrefix(reqPath, jsDir)
		suffix = strings.TrimSuffix(suffix, "/")

		// Must be a single non-empty segment (no slashes, no dots).
		if suffix == "" || strings.Contains(suffix, "/") || strings.Contains(suffix, ".") {
			continue
		}

		// Must be a reasonable service name (lowercase alpha, short).
		valid := true
		for _, c := range suffix {
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
				valid = false
				break
			}
		}
		if valid && len(suffix) >= 2 && len(suffix) <= 30 {
			add(suffix + "/")
		}
	}

	return prefixes
}

// extractAPIPaths scans JavaScript source code for API path patterns using
// multiple extraction strategies:
//  1. Single/double-quoted strings containing API indicators
//  2. Template literals (backticks) with interpolation
//  3. Full URLs (http/https) pointing to API endpoints
//  4. Service prefix concatenation (e.g., "identity/" + "api/auth/login")
//
// Returns deduplicated path strings. Paths with discovered service prefixes
// are expanded; already-prefixed and full-URL paths are kept as-is.
func extractAPIPaths(jsBody []byte, requests []ObservedRequest) []string {
	prefixes := extractServicePrefixes(jsBody, requests)

	seen := make(map[string]bool)
	var paths []string

	addPath := func(raw string) {
		if isStaticFile(raw) {
			return
		}

		// Full URLs are kept as-is (they include scheme+host).
		if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
			raw = strings.TrimRight(raw, "/")
			if !seen[raw] {
				seen[raw] = true
				paths = append(paths, raw)
			}
			return
		}

		// Normalize: ensure leading slash, trim trailing slash.
		if !strings.HasPrefix(raw, "/") {
			raw = "/" + raw
		}
		raw = strings.TrimRight(raw, "/")
		if raw == "" {
			return
		}

		trimmed := strings.TrimPrefix(raw, "/")

		// Check if path already has a known service prefix.
		knownPrefix := false
		for _, prefix := range prefixes {
			if strings.HasPrefix(trimmed, prefix) {
				knownPrefix = true
				break
			}
		}

		// Check if path has an inline prefix (segment before API indicator).
		if knownPrefix || hasInlinePrefix(trimmed) || len(prefixes) == 0 {
			if !seen[raw] {
				seen[raw] = true
				paths = append(paths, raw)
			}
		} else {
			// No prefix — combine with each discovered service prefix.
			// Wrong combinations will return 404/HTML and get filtered by the classifier.
			for _, prefix := range prefixes {
				fullPath := "/" + prefix + trimmed
				if !seen[fullPath] {
					seen[fullPath] = true
					paths = append(paths, fullPath)
				}
			}
		}
	}

	// Strategy 1: Single/double-quoted API paths.
	for _, match := range apiPathPattern.FindAllSubmatch(jsBody, -1) {
		if len(match) >= 2 {
			addPath(string(match[1]))
		}
	}

	// Strategy 2: Template literal API paths.
	for _, match := range templateLiteralPattern.FindAllSubmatch(jsBody, -1) {
		if len(match) >= 2 {
			addPath(string(match[1]))
		}
	}

	// Strategy 3: Full URL API paths.
	for _, match := range fullURLPattern.FindAllSubmatch(jsBody, -1) {
		if len(match) >= 2 {
			addPath(string(match[1]))
		}
	}

	return paths
}

// --- Main pipeline ---

// ReplayJSExtracted scans JavaScript response bodies from crawl results for
// API path patterns, then probes those paths with raw HTTP requests to obtain
// actual API responses. Discovered endpoints are appended to the returned slice.
//
// This addresses a fundamental limitation of headless browser crawling for SPAs:
// JavaScript bundles contain API path strings that the headless browser cannot
// exercise (they require user interactions, authentication state, or are string
// concatenations that jsluice cannot resolve). By regex-extracting these paths
// from the JS body and probing them directly with raw HTTP, we bypass both the
// SPA catch-all routing and jsluice's static analysis limitations.
func ReplayJSExtracted(ctx context.Context, requests []ObservedRequest, cfg JSReplayConfig) []ObservedRequest {
	cfg = cfg.withDefaults()

	// Determine the base URL from the first request.
	baseURL := ""
	for _, req := range requests {
		if req.URL != "" {
			baseURL = resolveBaseURL(req.URL)
			break
		}
	}
	if baseURL == "" {
		return requests
	}

	// Scan all JS response bodies for API paths.
	allPaths := make(map[string]bool)
	for _, req := range requests {
		if !isJSURL(req.URL) && !isJSResponse(req.Response.ContentType) {
			continue
		}
		if cfg.Verbose {
			fmt.Fprintf(cfg.Stderr, "js-extract: found JS file %s (ct=%q, body=%d bytes)\n",
				req.URL, req.Response.ContentType, len(req.Response.Body))
		}

		jsBody := req.Response.Body

		// If the body was truncated at MaxResponseBodySize (1 MB), re-fetch
		// the full JS file. SPA bundles are often >1 MB and API path strings
		// may be past the truncation point.
		if len(jsBody) >= MaxResponseBodySize {
			if cfg.Verbose {
				fmt.Fprintf(cfg.Stderr, "js-extract: body truncated at %d bytes, re-fetching %s\n",
					MaxResponseBodySize, req.URL)
			}
			fullBody := fetchJSBody(ctx, cfg, req.URL)
			if fullBody != nil {
				jsBody = fullBody
				if cfg.Verbose {
					fmt.Fprintf(cfg.Stderr, "js-extract: re-fetched %d bytes from %s\n", len(jsBody), req.URL)
				}
			}
		}

		if len(jsBody) == 0 {
			if cfg.Verbose {
				fmt.Fprintf(cfg.Stderr, "js-extract: skipping %s (empty body)\n", req.URL)
			}
			continue
		}

		paths := extractAPIPaths(jsBody, requests)
		if cfg.Verbose {
			fmt.Fprintf(cfg.Stderr, "js-extract: extracted %d API paths from %s\n", len(paths), req.URL)
			for _, p := range paths {
				fmt.Fprintf(cfg.Stderr, "  %s\n", p)
			}
		}
		for _, p := range paths {
			allPaths[p] = true
		}
	}

	if cfg.Verbose {
		fmt.Fprintf(cfg.Stderr, "js-extract: %d unique API paths found across all JS files\n", len(allPaths))
	}

	if len(allPaths) == 0 {
		return requests
	}

	// Probe each discovered API path with a raw HTTP request.
	result := make([]ObservedRequest, len(requests))
	copy(result, requests)

	probed := 0
	for path := range allPaths {
		if probed >= cfg.MaxEndpoints {
			break
		}

		// Full URLs are probed as-is; relative paths are resolved against baseURL.
		fullURL := path
		if !strings.HasPrefix(path, "http://") && !strings.HasPrefix(path, "https://") {
			fullURL = baseURL + path
		}

		resp := probeURL(ctx, cfg, fullURL)
		if resp == nil {
			continue
		}

		// Skip 404 responses — these are typically wrong service prefix
		// combinations (e.g., /identity/api/shop/products when the correct
		// prefix is /workshop/). Keeping them would pollute the spec with
		// endpoints that don't actually exist on that service.
		if resp.StatusCode == http.StatusNotFound {
			continue
		}

		result = append(result, ObservedRequest{
			Method:   "GET",
			URL:      fullURL,
			Headers:  cfg.Headers,
			Response: *resp,
			Source:   "js-extract",
		})
		probed++
	}

	return result
}

// --- HTTP helpers ---

// fetchJSBody re-fetches a JS file with a larger body limit than the crawler uses.
func fetchJSBody(ctx context.Context, cfg JSReplayConfig, rawURL string) []byte {
	reqCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil
	}
	for k, v := range cfg.Headers {
		req.Header.Set(k, v)
	}

	resp, err := cfg.Client.Do(req)
	if err != nil {
		return nil
	}
	defer func() {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)) //nolint:errcheck
		resp.Body.Close()                                     //nolint:errcheck
	}()

	if resp.StatusCode >= 400 {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJSBodySize))
	if err != nil {
		return nil
	}
	return body
}

// probeURL makes a direct HTTP GET request to the URL and returns the response.
func probeURL(ctx context.Context, cfg JSReplayConfig, rawURL string) *ObservedResponse {
	reqCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil
	}
	for k, v := range cfg.Headers {
		req.Header.Set(k, v)
	}

	resp, err := cfg.Client.Do(req)
	if err != nil {
		return nil
	}
	defer func() {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)) //nolint:errcheck
		resp.Body.Close()                                     //nolint:errcheck
	}()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxReplayBodySize))
	if err != nil {
		return nil
	}

	return &ObservedResponse{
		StatusCode:  resp.StatusCode,
		Headers:     flattenHeaders(resp.Header),
		ContentType: resp.Header.Get("Content-Type"),
		Body:        body,
	}
}

// flattenHeaders converts http.Header (multi-value) to a single-value map.
func flattenHeaders(h http.Header) map[string]string {
	result := make(map[string]string, len(h))
	for k, vals := range h {
		if len(vals) > 0 {
			result[k] = vals[0]
		}
	}
	return result
}
