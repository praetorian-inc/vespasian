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
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"golang.org/x/time/rate"
)

// Crawl runs the non-headless crawl using the stdlib net/http engine.
// It replaces the previous Katana-based crawlStandard.
func (c *HTTPCrawler) Crawl(ctx context.Context, targetURL string) ([]ObservedRequest, error) {
	maxPages, err := validateCrawlInputs(c.opts, targetURL)
	if err != nil {
		return nil, err
	}

	// Early return if context is already canceled.
	if ctx.Err() != nil {
		if c.opts.Stderr != nil {
			fmt.Fprintf(c.opts.Stderr, "\ninterrupt received, stopping crawl...\n") //nolint:errcheck // best-effort
		}
		return nil, ctx.Err()
	}

	// Apply the overall crawl timeout if configured.
	if c.opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.opts.Timeout)
		defer cancel()
	}

	// Set up scope checker (includes SSRF protection).
	scopeFn, err := scopeChecker(targetURL, c.opts.Scope, c.opts.AllowPrivate)
	if err != nil {
		return nil, fmt.Errorf("scope setup: %w", err)
	}

	// Set up the frontier in DFS (depth-first) mode.
	frontier := newURLFrontier(c.opts.Depth, scopeFn)
	frontier.SetDFS(true)

	// Shared rate limiter at 150 rps.
	limiter := rate.NewLimiter(rate.Limit(150), 150)

	// HTTP client with redirect scope guard.
	client := &http.Client{
		CheckRedirect: redirectScopeGuard(scopeFn),
	}

	// Seed the frontier. Reject if the seed itself doesn't pass scope/SSRF.
	if frontier.Push([]urlEntry{{URL: targetURL, Depth: 0}}) == 0 {
		return nil, fmt.Errorf("seed URL rejected by frontier (scope, SSRF, or parse): %s; "+
			"if crawling a private host (localhost, 127.0.0.1, RFC1918, link-local), "+
			"pass %s", redactSeedURL(targetURL), flagDangerousAllowPrivate)
	}

	var (
		mu        sync.Mutex
		results   = make([]ObservedRequest, 0, min(maxPages, 1000))
		pageCount int
	)

	crawlCtx, crawlCancel := context.WithCancel(ctx)
	defer crawlCancel()

	n := clampConcurrency(c.opts.Concurrency)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for {
				if crawlCtx.Err() != nil {
					return
				}

				entry, ok := frontier.Pop()
				if !ok {
					return
				}
				frontier.MarkActive()

				observed, links := c.fetchPage(crawlCtx, client, limiter, entry)

				if observed != nil {
					mu.Lock()
					if pageCount < maxPages {
						pageCount++
						results = append(results, *observed)
						if pageCount >= maxPages {
							crawlCancel()
						}
					}
					mu.Unlock()
				}

				if len(links) > 0 {
					entries := make([]urlEntry, len(links))
					for i, link := range links {
						entries[i] = urlEntry{URL: link, Depth: entry.Depth + 1}
					}
					frontier.Push(entries)
				}

				frontier.MarkIdle()
				_ = id
			}
		}(i)
	}

	wg.Wait()
	frontier.Close()

	if ctx.Err() != nil {
		if c.opts.Stderr != nil {
			fmt.Fprintf(c.opts.Stderr, "\ninterrupt received, stopping crawl...\n") //nolint:errcheck // best-effort
		}
		mu.Lock()
		snapshot := make([]ObservedRequest, len(results))
		copy(snapshot, results)
		mu.Unlock()
		return snapshot, ctx.Err()
	}

	mu.Lock()
	snapshot := make([]ObservedRequest, len(results))
	copy(snapshot, results)
	mu.Unlock()
	return snapshot, nil
}

// fetchPage performs a single HTTP GET for the given entry. It applies a
// per-page timeout, rate limiting, and the configured headers. On success it
// returns the observed request and discovered links. On error it logs to Stderr
// (if set) and returns (nil, nil) so the worker can continue.
func (c *HTTPCrawler) fetchPage(ctx context.Context, client *http.Client, limiter *rate.Limiter, entry urlEntry) (*ObservedRequest, []string) {
	pageCtx, cancel := context.WithTimeout(ctx, PageTimeout*1e9) // PageTimeout seconds
	defer cancel()

	// Rate-limit before fetching. A limiter.Wait error (context canceled or
	// deadline exceeded) must be handled identically to a client.Do error —
	// log to Stderr and skip this page.
	if err := limiter.Wait(pageCtx); err != nil {
		if c.opts.Stderr != nil {
			fmt.Fprintf(c.opts.Stderr, "rate limiter: %s: %v\n", entry.URL, err) //nolint:errcheck // best-effort
		}
		return nil, nil
	}

	req, err := http.NewRequestWithContext(pageCtx, http.MethodGet, entry.URL, nil)
	if err != nil {
		if c.opts.Stderr != nil {
			fmt.Fprintf(c.opts.Stderr, "build request: %s: %v\n", entry.URL, err) //nolint:errcheck // best-effort
		}
		return nil, nil
	}

	applyHeaders(req, c.opts.Headers)

	resp, err := client.Do(req)
	if err != nil {
		if c.opts.Stderr != nil {
			fmt.Fprintf(c.opts.Stderr, "fetch: %s: %v\n", entry.URL, err) //nolint:errcheck // best-effort
		}
		return nil, nil
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort

	// Read up to MaxHTTPBodySize (DoS cap).
	body, _ := io.ReadAll(io.LimitReader(resp.Body, MaxHTTPBodySize))

	observed := buildObservedRequest(req, resp, body)
	links := c.extractLinks(observed, entry.URL)

	return &observed, links
}

// extractLinks discovers navigable URLs from an observed request using HTML
// parsing (goquery) and jsluice. It handles both HTML pages and JavaScript
// response bodies.
func (c *HTTPCrawler) extractLinks(observed ObservedRequest, pageURL string) []string {
	var links []string

	ct := strings.ToLower(observed.Response.ContentType)
	if isHTMLContentType(ct) {
		baseURL := effectiveBaseURLFrom("", pageURL) // no base href parsing here; use pageURL as base
		// Try to extract base href from body for more accurate resolution.
		if len(observed.Response.Body) > 0 {
			// Pass the raw body to see if there's a <base href="...">.
			// effectiveBaseURLFrom already handles this correctly if we
			// re-parse; for simplicity, let htmlextract handle the actual
			// resolution against pageURL.
			baseURL = pageURL
		}
		links = append(links, extractFromHTML(observed.Response.Body, baseURL)...)
		links = append(links, jsExtractedToLinks(extractInlineScripts(observed.Response.Body), baseURL)...)
	}

	links = append(links, jsExtractedToLinks(extractURLsFromResponses([]ObservedRequest{observed}), pageURL)...)
	return links
}

// buildObservedRequest constructs an ObservedRequest from an http.Request and
// http.Response pair. The Source is set to "http". The stored response body is
// capped at MaxResponseBodySize (retention cap), separate from the read cap.
func buildObservedRequest(req *http.Request, resp *http.Response, body []byte) ObservedRequest {
	// Use the final URL after any redirects.
	finalURL := req.URL.String()
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}

	// Collect request headers.
	reqHeaders := make(map[string]string, len(req.Header))
	for k, vs := range req.Header {
		if len(vs) > 0 {
			reqHeaders[k] = vs[0]
		}
	}

	// Parse query params.
	var queryParams url.Values
	if u, err := url.Parse(finalURL); err == nil {
		queryParams = CapQueryValues(u.Query())
	}

	// Collect response headers (flatten multi-value to first value).
	respHeaders := make(map[string]string, len(resp.Header))
	for k, vs := range resp.Header {
		if len(vs) > 0 {
			respHeaders[k] = vs[0]
		}
	}

	contentType := resp.Header.Get("Content-Type")

	// Apply retention cap (1 MB) to stored body.
	storedBody := body
	if len(storedBody) > MaxResponseBodySize {
		storedBody = storedBody[:MaxResponseBodySize]
	}

	return ObservedRequest{
		Method:      req.Method,
		URL:         finalURL,
		Headers:     reqHeaders,
		QueryParams: queryParams,
		Source:      "http",
		Response: ObservedResponse{
			StatusCode:  resp.StatusCode,
			Headers:     respHeaders,
			ContentType: contentType,
			Body:        storedBody,
		},
	}
}

// applyHeaders sets each key-value pair from headers onto the request.
// Cookie headers are set as a regular static header (no cookie-jar semantics
// needed for the HTTP engine).
func applyHeaders(req *http.Request, headers map[string]string) {
	for k, v := range headers {
		req.Header.Set(k, v)
	}
}

// clampConcurrency returns the effective worker concurrency, mirroring
// engine.go:126-134. Zero maps to DefaultConcurrency; values above
// MaxConcurrency are capped.
func clampConcurrency(n int) int {
	if n <= 0 {
		return DefaultConcurrency
	}
	if n > MaxConcurrency {
		return MaxConcurrency
	}
	return n
}

// redirectScopeGuard returns a CheckRedirect function that blocks redirects
// to out-of-scope or private (SSRF) hosts. It mirrors the stdlib default of
// refusing more than 10 redirects.
func redirectScopeGuard(scopeFn func(string) bool) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		if scopeFn != nil && !scopeFn(req.URL.String()) {
			return fmt.Errorf("redirect to out-of-scope/private host blocked: %s", req.URL.Host)
		}
		return nil
	}
}

// isHTMLContentType returns true if the content type indicates HTML.
func isHTMLContentType(ct string) bool {
	return strings.Contains(ct, "text/html") ||
		strings.Contains(ct, "application/xhtml")
}
