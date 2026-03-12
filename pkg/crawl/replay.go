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
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// replayTimeout is the per-request timeout for replay HTTP calls.
	replayTimeout = 10 * time.Second
	// replayMaxBodySize limits response body reads during replay (1 MB).
	replayMaxBodySize = 1 * 1024 * 1024
	// replayMaxRequests limits the number of URLs replayed to prevent abuse.
	replayMaxRequests = 500
)

// needsReplay returns true if the request has a URL that looks like an API
// endpoint but lacks a meaningful response (e.g., XHR-extracted URLs from Katana
// that only captured the URL, not the full request/response pair).
func needsReplay(req ObservedRequest) bool {
	// Must have a URL to replay.
	if req.URL == "" {
		return false
	}

	// Skip requests that already have a response with a body or status code.
	if req.Response.StatusCode > 0 && len(req.Response.Body) > 0 {
		return false
	}

	return true
}

// ReplayRequests re-issues HTTP requests for crawled URLs that lack complete
// responses (e.g., XHR-extracted URLs discovered by Katana). This fills in the
// response data needed for accurate API classification and spec generation.
//
// Only URLs with missing or empty responses are replayed. Auth headers from the
// -H flag are injected into each request. The original request list is not
// modified; a new slice with updated entries is returned.
func ReplayRequests(ctx context.Context, requests []ObservedRequest, headers map[string]string) []ObservedRequest {
	if len(headers) == 0 {
		return requests
	}

	// Identify requests that need replay, deduplicated by URL.
	type replayTarget struct {
		url    string
		method string
		index  int // index into requests slice
	}

	seen := make(map[string]bool)
	var targets []replayTarget

	for i, req := range requests {
		if !needsReplay(req) {
			continue
		}
		if seen[req.URL] {
			continue
		}
		if len(targets) >= replayMaxRequests {
			slog.Warn("replay: hit max request limit", "limit", replayMaxRequests)
			break
		}
		seen[req.URL] = true
		method := req.Method
		if method == "" {
			method = http.MethodGet
		}
		targets = append(targets, replayTarget{url: req.URL, method: method, index: i})
	}

	if len(targets) == 0 {
		return requests
	}

	slog.Info("replaying requests with auth headers", "count", len(targets))

	client := &http.Client{
		Timeout: replayTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Build results map: URL → replayed response.
	type replayResult struct {
		response ObservedResponse
		method   string
	}
	results := make(map[string]replayResult)

	for _, t := range targets {
		if ctx.Err() != nil {
			break
		}
		resp, method := replayURL(ctx, client, t.url, t.method, headers)
		if resp != nil {
			results[t.url] = replayResult{response: *resp, method: method}
		}
	}

	if len(results) == 0 {
		return requests
	}

	slog.Info("replay completed", "successful", len(results), "attempted", len(targets))

	// Copy requests and update those with replay results.
	out := make([]ObservedRequest, len(requests))
	copy(out, requests)

	for i := range out {
		if r, ok := results[out[i].URL]; ok {
			out[i].Response = r.response
			if out[i].Method == "" || out[i].Method == "GET" {
				out[i].Method = r.method
			}
			if out[i].Source != "" {
				out[i].Source = out[i].Source + "+replay"
			} else {
				out[i].Source = "replay"
			}
		}
	}

	return out
}

// replayURL issues an HTTP request to the given URL with auth headers and
// captures the full response. Returns nil if the request fails or returns
// a non-useful response.
func replayURL(ctx context.Context, client *http.Client, rawURL string, method string, headers map[string]string) (*ObservedResponse, string) {
	reqCtx, cancel := context.WithTimeout(ctx, replayTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, method, rawURL, nil)
	if err != nil {
		slog.Debug("replay: failed to create request", "url", rawURL, "error", err)
		return nil, method
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		slog.Debug("replay: request failed", "url", rawURL, "error", err)
		return nil, method
	}
	defer func() {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)) //nolint:errcheck // best-effort drain
		resp.Body.Close()                                     //nolint:errcheck // best-effort close
	}()

	body, err := io.ReadAll(io.LimitReader(resp.Body, replayMaxBodySize))
	if err != nil {
		slog.Debug("replay: failed to read response body", "url", rawURL, "error", err)
		return nil, method
	}

	respHeaders := make(map[string]string)
	for k := range resp.Header {
		respHeaders[k] = resp.Header.Get(k)
	}

	contentType := resp.Header.Get("Content-Type")

	result := &ObservedResponse{
		StatusCode:  resp.StatusCode,
		Headers:     respHeaders,
		ContentType: contentType,
		Body:        body,
	}

	// Also parse query params if the original request didn't have them.
	slog.Debug("replay: captured response",
		"url", rawURL,
		"status", resp.StatusCode,
		"content_type", contentType,
		"body_size", len(body),
	)

	return result, method
}

// ReplayAndMerge replays requests that need it and also discovers new endpoints
// by following API patterns found in responses. It returns the merged set of
// observed requests including any newly discovered endpoints.
func ReplayAndMerge(ctx context.Context, requests []ObservedRequest, headers map[string]string) []ObservedRequest {
	// Phase 1: Replay existing requests that lack responses.
	replayed := ReplayRequests(ctx, requests, headers)

	// Phase 2: Look for API base URLs in the replayed responses and try to
	// discover additional endpoints by probing common API patterns.
	discovered := discoverFromResponses(ctx, replayed, headers)
	if len(discovered) > 0 {
		slog.Info("discovered additional endpoints from replay responses", "count", len(discovered))
		replayed = append(replayed, discovered...)
	}

	return replayed
}

// discoverFromResponses scans replayed responses for links or API references
// that point to additional endpoints not yet in the request list.
func discoverFromResponses(ctx context.Context, requests []ObservedRequest, headers map[string]string) []ObservedRequest {
	// Collect all known URLs for dedup.
	known := make(map[string]bool)
	for _, req := range requests {
		known[req.URL] = true
	}

	// Extract potential API URLs from JSON response bodies.
	var newURLs []string
	for _, req := range requests {
		if req.Response.StatusCode == 0 || len(req.Response.Body) == 0 {
			continue
		}
		if !isJSONResponse(req.Response.ContentType) {
			continue
		}

		// Extract URLs from the response body text.
		urls := extractURLsFromBody(string(req.Response.Body), req.URL)
		for _, u := range urls {
			if !known[u] {
				known[u] = true
				newURLs = append(newURLs, u)
			}
		}
	}

	if len(newURLs) == 0 {
		return nil
	}

	// Cap discovery to avoid runaway requests.
	if len(newURLs) > replayMaxRequests {
		newURLs = newURLs[:replayMaxRequests]
	}

	slog.Info("probing discovered URLs from responses", "count", len(newURLs))

	client := &http.Client{
		Timeout: replayTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var discovered []ObservedRequest
	for _, rawURL := range newURLs {
		if ctx.Err() != nil {
			break
		}
		resp, _ := replayURL(ctx, client, rawURL, http.MethodGet, headers)
		if resp == nil || resp.StatusCode >= 400 {
			continue
		}

		u, err := url.Parse(rawURL)
		if err != nil {
			continue
		}
		qp := make(map[string]string)
		for key, values := range u.Query() {
			if len(values) > 0 {
				qp[key] = values[0]
			}
		}

		discovered = append(discovered, ObservedRequest{
			Method:      "GET",
			URL:         rawURL,
			QueryParams: qp,
			Response:    *resp,
			Source:      "replay-discovery",
		})
	}

	return discovered
}

// isJSONResponse checks if the content type indicates JSON.
func isJSONResponse(ct string) bool {
	ct = strings.ToLower(ct)
	if idx := strings.Index(ct, ";"); idx != -1 {
		ct = strings.TrimSpace(ct[:idx])
	}
	return strings.HasSuffix(ct, "/json") || strings.HasSuffix(ct, "+json")
}

// extractURLsFromBody extracts HTTP/HTTPS URLs from a response body string
// that appear to be API endpoints on the same origin.
func extractURLsFromBody(body string, sourceURL string) []string {
	sourceU, err := url.Parse(sourceURL)
	if err != nil {
		return nil
	}
	sourceOrigin := sourceU.Scheme + "://" + sourceU.Host

	var urls []string
	// Simple URL extraction: find quoted strings that look like HTTP URLs.
	for _, sep := range []string{`"`, `'`} {
		parts := strings.Split(body, sep)
		for _, part := range parts {
			part = strings.TrimSpace(part)

			// Handle relative URLs (e.g., "/api/users").
			if strings.HasPrefix(part, "/") && !strings.HasPrefix(part, "//") && len(part) > 1 && len(part) < 500 {
				candidate := sourceOrigin + part
				if looksLikeAPIURL(candidate) {
					urls = append(urls, candidate)
				}
				continue
			}

			// Handle absolute URLs on the same origin.
			if !strings.HasPrefix(part, "http://") && !strings.HasPrefix(part, "https://") {
				continue
			}
			if len(part) > 2000 {
				continue
			}
			u, err := url.Parse(part)
			if err != nil {
				continue
			}
			if u.Host != sourceU.Host {
				continue
			}
			if looksLikeAPIURL(part) {
				urls = append(urls, part)
			}
		}
	}

	return urls
}

// looksLikeAPIURL returns true if the URL path suggests an API endpoint.
func looksLikeAPIURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	path := strings.ToLower(u.Path)

	// Reject static assets.
	for _, ext := range []string{".js", ".css", ".png", ".jpg", ".gif", ".svg", ".ico", ".woff", ".ttf", ".map", ".html", ".htm"} {
		if strings.HasSuffix(path, ext) {
			return false
		}
	}

	// Accept paths with API-like segments.
	apiSegments := []string{"/api/", "/api", "/v1/", "/v2/", "/v3/", "/rest/", "/graphql"}
	for _, seg := range apiSegments {
		if strings.Contains(path, seg) {
			return true
		}
	}

	return false
}
