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
	"time"

	"golang.org/x/time/rate"
)

// httpPageTimeout is the per-page fetch timeout for the HTTP engine. It defaults
// to PageTimeout seconds and is a package var (not a const) solely so tests can
// shrink it to exercise the per-page-timeout path without a multi-second sleep —
// the same test-seam pattern used by mergeEnrichedLinksFn. Production never
// reassigns it. NOT safe to mutate concurrently with a running crawl.
var httpPageTimeout = time.Duration(PageTimeout) * time.Second

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

	// HTTP client with redirect scope guard and bounded timeout.
	// The per-page context (PageTimeout) already cancels hung fetches, but an
	// explicit Client.Timeout provides defense-in-depth if the context is ever
	// mis-wired on a future code path (SEC-BE-001).
	transport := http.DefaultTransport
	if !c.opts.AllowPrivate {
		// Clone DefaultTransport and override only DialContext so we keep its
		// TLS, keep-alive, HTTP/2, proxy, and idle-connection tunings while
		// re-resolving and re-validating IPs at connect time, closing the
		// DNS-rebinding TOCTOU window (SEC-BE-002).
		base, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			// Defensive: stdlib always sets *http.Transport, but if a future
			// runtime changes that, fall back to a fresh transport rather than
			// silently dropping the SSRF dial guard.
			base = &http.Transport{}
		}
		t := base.Clone()
		t.DialContext = ssrfSafeDialContext
		transport = t
	}
	client := &http.Client{
		CheckRedirect: redirectScopeGuard(scopeFn),
		Transport:     transport,
		Timeout:       time.Duration(PageTimeout) * time.Second,
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
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.runWorker(crawlCtx, crawlCancel, client, limiter, frontier, &mu, &results, &pageCount, maxPages)
		}()
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

// runWorker is the per-goroutine crawl loop. It pops entries from the frontier,
// fetches pages, records results, and pushes discovered links back.
func (c *HTTPCrawler) runWorker(
	ctx context.Context,
	cancel context.CancelFunc,
	client *http.Client,
	limiter *rate.Limiter,
	frontier *urlFrontier,
	mu *sync.Mutex,
	results *[]ObservedRequest,
	pageCount *int,
	maxPages int,
) {
	for {
		if ctx.Err() != nil {
			return
		}

		entry, ok := frontier.Pop()
		if !ok {
			return
		}
		// MarkActive is NOT called here: Pop atomically increments the active
		// counter before returning, making dequeue+activate a single critical
		// section. Callers only need MarkIdle() after processing completes.

		observed, links := c.fetchPage(ctx, client, limiter, entry)

		if observed != nil {
			mu.Lock()
			if *pageCount < maxPages {
				*pageCount++
				*results = append(*results, *observed)
				if *pageCount >= maxPages {
					cancel()
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
	}
}

// fetchPage performs a single HTTP GET for the given entry. It applies a
// per-page timeout, rate limiting, and the configured headers. On success it
// returns the observed request and discovered links. On error it logs to Stderr
// (if set) and returns (nil, nil) so the worker can continue.
func (c *HTTPCrawler) fetchPage(ctx context.Context, client *http.Client, limiter *rate.Limiter, entry urlEntry) (*ObservedRequest, []string) {
	pageCtx, cancel := context.WithTimeout(ctx, httpPageTimeout)
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

	// Read up to MaxHTTPBodySize (DoS cap). Partial reads are intentional.
	body, _ := io.ReadAll(io.LimitReader(resp.Body, MaxHTTPBodySize)) //nolint:errcheck // best-effort; partial body is acceptable

	observed := buildObservedRequest(req, resp, body)
	links := c.extractLinks(observed, entry.URL)

	return &observed, links
}

// extractLinks discovers navigable URLs from an observed request using HTML
// parsing (goquery) and jsluice. It handles both HTML pages and JavaScript
// response bodies.
//
// For HTML responses, extractFromHTML reads the <base href> tag (if present)
// and resolves relative links against it, exactly matching the rod path's
// effectiveBaseURL behavior. Inline-script URLs are resolved against the same
// base so that jsluice-extracted paths honor the page's declared base.
func (c *HTTPCrawler) extractLinks(observed ObservedRequest, pageURL string) []string {
	var links []string

	ct := strings.ToLower(observed.Response.ContentType)
	if isHTMLContentType(ct) {
		// extractFromHTML resolves <base href> internally; pass pageURL as
		// the fallback base. Derive the same effective base for inline scripts
		// so both extraction paths are consistent.
		links = append(links, extractFromHTML(observed.Response.Body, pageURL)...)
		base := extractEffectiveBase(observed.Response.Body, pageURL)
		links = append(links, jsExtractedToLinks(extractInlineScripts(observed.Response.Body), base)...)
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
