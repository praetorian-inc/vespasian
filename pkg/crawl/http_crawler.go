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
	"crypto/tls"
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

// newHTTPClient builds an *http.Client for the HTTPCrawler. Its transport is
// selected in three branches; the client's CheckRedirect is always set to
// redirectScopeGuard(scopeFn):
//
//   - proxyURL != nil: a clone of http.DefaultTransport with Proxy set to the
//     given URL. TLS certificate verification stays ON by default; it is
//     disabled only when proxyInsecure is set AND the proxy is http/https,
//     the explicit opt-in for an intercepting proxy (Burp, mitmproxy) that
//     presents its own CA for HTTPS MITM. The dial-time SSRF guard
//     (ssrfSafeDialContext) is deliberately NOT installed: with a proxy the
//     client dials the proxy (commonly loopback), not the target, so pinning
//     the dialed IP would block the proxy and offers no target protection.
//     Target scope stays enforced at the URL level by the upfront scope/SSRF
//     check and redirectScopeGuard. (LAB-4011.)
//   - proxyURL == nil, allowPrivate false: a clone of http.DefaultTransport
//     with DialContext wired to ssrfSafeDialContext so the DNS-rebinding TOCTOU
//     window is closed at connect time (SEC-BE-002).
//   - proxyURL == nil, allowPrivate true: http.DefaultTransport unchanged.
func newHTTPClient(scopeFn func(string) bool, allowPrivate bool, timeout time.Duration, proxyURL *url.URL, proxyInsecure bool) *http.Client {
	transport := http.RoundTripper(http.DefaultTransport)
	switch {
	case proxyURL != nil:
		// Clone DefaultTransport and route through the proxy, keeping its
		// keep-alive, HTTP/2, and idle-connection tunings.
		base, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			base = &http.Transport{}
		}
		t := base.Clone()
		t.Proxy = http.ProxyURL(proxyURL)
		// TLS verification stays on by default. It is disabled only when the
		// operator explicitly opts in via --proxy-insecure AND the proxy is
		// http/https: an intercepting proxy (Burp, mitmproxy) terminates TLS and
		// presents its own CA for the target, so verification must be off for
		// that substitute certificate to be accepted, and the Go client has no
		// OS trust store to fall back on the way headless Chrome does. socks5 is
		// a transparent TCP tunnel: the Go client performs TLS directly with the
		// real target through the tunnel and no substitute CA is involved, so
		// verification is always kept for socks5 regardless of proxyInsecure.
		if proxyInsecure && (proxyURL.Scheme == "http" || proxyURL.Scheme == "https") {
			t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // G402: opt-in via --proxy-insecure for http/https proxy MITM (see doc comment)
		}
		transport = t
	case !allowPrivate:
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
	return &http.Client{
		CheckRedirect: redirectScopeGuard(scopeFn),
		Transport:     transport,
		Timeout:       timeout,
	}
}

// Crawl runs the non-headless crawl using the stdlib net/http engine — the
// HTTP-only path used when --headless=false.
func (c *HTTPCrawler) Crawl(ctx context.Context, targetURL string) ([]ObservedRequest, error) {
	// Apply default per-page timeout when the struct was constructed directly
	// (bypassing NewCrawler) and pageTimeout was left at zero.
	if c.pageTimeout == 0 {
		c.pageTimeout = time.Duration(PageTimeout) * time.Second
	}

	maxPages, err := validateCrawlInputs(c.opts, targetURL)
	if err != nil {
		return nil, err
	}
	// The net/http backend records exactly one request per visited page, so the
	// request budget reduces to a page cap here (LAB-4678 Phase 3). The headless
	// engine, where one page fires many requests, enforces MaxRequests as a
	// distinct running count.
	maxPages = httpPageCap(maxPages, c.opts.MaxRequests)

	warnInteractUnsupported(c.opts.Stderr, c.opts.Interact)

	// Validate and parse the proxy on the HTTP path. The CLI validates too
	// (cmd/vespasian doCrawl), but this guards library/SDK callers that build
	// an HTTPCrawler directly. A nil proxyURL means "no proxy" (default path).
	var proxyURL *url.URL
	if c.opts.Proxy != "" {
		if err := ValidateProxyAddr(c.opts.Proxy); err != nil {
			return nil, err
		}
		// ValidateProxyAddr already parsed the address; re-parse for the URL.
		proxyURL, err = url.Parse(c.opts.Proxy)
		if err != nil {
			return nil, fmt.Errorf("parse proxy address: %w", err)
		}
	}

	// Early return if context is already canceled.
	if ctx.Err() != nil {
		if c.opts.Stderr != nil {
			fmt.Fprint(c.opts.Stderr, interruptMessage) //nolint:errcheck // best-effort
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
	// The per-page context (c.pageTimeout) already cancels hung fetches, but an
	// explicit Client.Timeout provides defense-in-depth if the context is ever
	// mis-wired on a future code path (SEC-BE-001). Both use c.pageTimeout so
	// they track the same source (QUAL-004).
	client := newHTTPClient(scopeFn, c.opts.AllowPrivate, c.pageTimeout, proxyURL, c.opts.ProxyInsecure)

	resumeCfg := c.opts.resume(targetURL)
	if err := c.restoreAndSeed(frontier, targetURL, resumeCfg); err != nil {
		return nil, err
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

	// Capture resume state after the workers have stopped, on every exit path
	// including budget truncation and cancellation (LAB-4678 Phase 4).
	captureCheckpoint(frontier, resumeCfg, time.Now())

	if ctx.Err() != nil {
		if c.opts.Stderr != nil {
			fmt.Fprint(c.opts.Stderr, interruptMessage) //nolint:errcheck // best-effort
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

// restoreAndSeed applies any resume state to the frontier and then seeds it with
// the target, returning an error only when there is genuinely nothing to crawl.
// Resume must be restored BEFORE seeding so already-covered pages are not
// re-crawled (LAB-4678 Phase 4). A resumed frontier has already seen the seed, so
// Push returns 0 for it — that is expected, not a rejection, which is why the
// failure condition also requires an empty queue. Split out of Crawl to keep it
// under the cyclomatic complexity gate.
func (c *HTTPCrawler) restoreAndSeed(frontier *urlFrontier, targetURL string, resumeCfg resumeOptions) error {
	resumed := resumeFrontier(frontier, resumeCfg, time.Now(), c.opts.Stderr)

	if frontier.Push([]urlEntry{{URL: targetURL, Depth: 0}}) == 0 && frontier.Len() == 0 {
		if resumed {
			return fmt.Errorf("resumed checkpoint has no pending pages and seed URL %s "+
				"was already covered; nothing to crawl", redactSeedURL(targetURL))
		}
		return fmt.Errorf("seed URL rejected by frontier (scope, SSRF, or parse): %s; "+
			"if crawling a private host (localhost, 127.0.0.1, RFC1918, link-local), "+
			"pass %s", redactSeedURL(targetURL), flagDangerousAllowPrivate)
	}
	return nil
}

// warnInteractUnsupported reports that --interact does nothing on the net/http
// backend. That backend has no DOM to click, so the option is ignored; staying
// silent left an operator who passed "--interact --headless=false" to conclude the
// target had no interaction-only surface. Mirrors the concurrency-cap warning in
// newRodEngine. No-op when the option was not requested or Stderr is nil.
func warnInteractUnsupported(stderr io.Writer, interact bool) {
	if !interact || stderr == nil {
		return
	}
	fmt.Fprint(stderr, "warning: --interact requires the headless backend (it clicks DOM elements); ignoring it with --headless=false\n") //nolint:errcheck // best-effort
}

// httpPageCap folds the request budget into the page cap for the net/http
// backend: that backend records one request per page, so a MaxRequests bound
// (maxRequests > 0) reduces to a page cap. A zero maxRequests leaves maxPages
// unchanged. Kept as a helper so HTTPCrawler.Crawl stays under the cyclomatic
// complexity gate.
//
// maxPages MUST already be resolved to a positive value — validateCrawlInputs
// normalizes the "0 means unlimited" sentinel to DefaultMaxPages before this is
// called. The guard below enforces that rather than trusting it: with maxPages
// as an unlimited sentinel, a naive `maxRequests < maxPages` comparison is false
// and the request budget would be silently discarded, failing a politeness
// control open against a sensitive target.
func httpPageCap(maxPages, maxRequests int) int {
	if maxRequests <= 0 {
		return maxPages
	}
	if maxPages <= 0 {
		// Unlimited pages: the request budget is the only bound left.
		return maxRequests
	}
	return min(maxRequests, maxPages)
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

		// The page cap cancels the shared context, so a worker blocked in Pop can
		// wake up holding an entry it must not fetch. Return it to the queue
		// instead of dropping it — with the default concurrency this path was
		// draining the entire pending queue, leaving cross-run resume with
		// nothing to continue from (LAB-4678 Phase 4).
		if ctx.Err() != nil {
			frontier.Requeue(entry)
			frontier.MarkIdle()
			return
		}

		observed, links := c.fetchPage(ctx, client, limiter, entry)

		// Not covered: either the fetch was canceled, or the budget filled while
		// it was in flight and the result is about to be discarded below. Either
		// way the page still needs crawling, so requeue it.
		if observed == nil && ctx.Err() != nil {
			frontier.Requeue(entry)
			frontier.MarkIdle()
			return
		}

		// fetchPage returns nil only on a transport-level failure (DNS, connection
		// reset, rate-limiter or per-page timeout, request build) — an HTTP error
		// STATUS still yields an observation. With the context alive that is a
		// plausibly transient failure, so keep the page out of the persisted
		// seen-set: Checkpoint.Seen accumulates across resume cycles, so leaving it
		// there turned one bad fetch into a permanent drop. It is not requeued now,
		// so this run does not retry it.
		if observed == nil {
			frontier.MarkFailed(entry.URL)
		}

		if observed != nil {
			recorded := false
			mu.Lock()
			if *pageCount < maxPages {
				*pageCount++
				*results = append(*results, *observed)
				recorded = true
				if *pageCount >= maxPages {
					cancel()
				}
			}
			mu.Unlock()
			// The budget filled while this fetch was in flight, so its result was
			// dropped. The URL is already in seen, so without a requeue the page
			// would be permanently uncrawlable on resume.
			if !recorded {
				frontier.Requeue(entry)
				frontier.MarkIdle()
				return
			}
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
	pageCtx, cancel := context.WithTimeout(ctx, c.pageTimeout)
	defer cancel()

	// Rate-limit before fetching. A limiter.Wait error (context canceled or
	// deadline exceeded) must be handled identically to a client.Do error —
	// log to Stderr and skip this page.
	if err := limiter.Wait(pageCtx); err != nil {
		if c.opts.Stderr != nil {
			fmt.Fprintf(c.opts.Stderr, "rate limiter: %s: %v\n", redactSeedURL(entry.URL), err) //nolint:errcheck // best-effort
		}
		return nil, nil
	}

	req, err := http.NewRequestWithContext(pageCtx, http.MethodGet, entry.URL, nil)
	if err != nil {
		if c.opts.Stderr != nil {
			fmt.Fprintf(c.opts.Stderr, "build request: %s: %v\n", redactSeedURL(entry.URL), err) //nolint:errcheck // best-effort
		}
		return nil, nil
	}

	applyHeaders(req, c.opts.Headers)

	resp, err := client.Do(req)
	if err != nil {
		if c.opts.Stderr != nil {
			fmt.Fprintf(c.opts.Stderr, "fetch: %s: %v\n", redactSeedURL(entry.URL), err) //nolint:errcheck // best-effort
		}
		return nil, nil
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort

	// Read up to MaxHTTPBodySize (DoS cap). Partial reads are intentional.
	body, _ := io.ReadAll(io.LimitReader(resp.Body, MaxHTTPBodySize)) //nolint:errcheck // best-effort; partial body is acceptable

	observed := buildObservedRequest(req, resp, body)
	// Extract links from the full read body (up to MaxHTTPBodySize / 10 MB), NOT
	// from observed.Response.Body, which buildObservedRequest truncates to the 1 MB
	// retention cap. Using the stored body here would silently drop every endpoint
	// that appears past the first 1 MB of a large HTML/JS page even though we paid
	// to read up to 10 MB.
	//
	// Resolve discovered links against the FINAL response URL (observed.URL,
	// post-redirect), not the queued entry.URL — otherwise a redirect from
	// /start to /app/ would resolve href="next" as /next instead of /app/next.
	links := c.extractLinks(observed, body, observed.URL)

	return &observed, links
}

// extractLinks discovers navigable URLs from a fetched page using HTML parsing
// (goquery) and jsluice. It handles both HTML pages and JavaScript response
// bodies.
//
// fullBody is the body as read from the wire (capped only by MaxHTTPBodySize),
// which is what link discovery operates on. observed carries the content type,
// final URL, and the 1 MB-retention-capped body used for storage; its Body field
// is deliberately NOT used for extraction (see fetchPage).
//
// For HTML responses, extractFromHTML reads the <base href> tag (if present)
// and resolves relative links against it, exactly matching the rod path's
// effectiveBaseURL behavior. Inline-script URLs are resolved against the same
// base so that jsluice-extracted paths honor the page's declared base.
func (c *HTTPCrawler) extractLinks(observed ObservedRequest, fullBody []byte, pageURL string) []string {
	var links []string

	// base is the <base href>-aware base for HTML pages, else the (final,
	// post-redirect) pageURL. All jsluice-derived URLs resolve against it so the
	// inline-script and JS-response paths stay consistent with the DOM links.
	base := pageURL

	ct := strings.ToLower(observed.Response.ContentType)
	if isHTMLContentType(ct) {
		// extractHTMLAndInlineScripts parses the body exactly once, returning
		// both the navigable links and inline-script jsluice results. Previously
		// extractFromHTML and extractInlineScripts each called
		// goquery.NewDocumentFromReader separately (QUAL-002 double-parse fix).
		var htmlLinks []string
		var inlineScripts []jsExtractedURL
		htmlLinks, base, inlineScripts = extractHTMLAndInlineScripts(fullBody, pageURL)
		links = append(links, htmlLinks...)
		links = append(links, jsExtractedToLinks(inlineScripts, base)...)
	}

	// extractURLsFromResponses keys off the response body, so feed it a view of
	// the observed request that carries the full (read-capped) body rather than
	// the 1 MB-retention-capped stored body.
	full := observed
	full.Response.Body = fullBody
	links = append(links, jsExtractedToLinks(extractURLsFromResponses([]ObservedRequest{full}), base)...)
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

// redirectScopeGuard returns a CheckRedirect function that blocks redirects
// to out-of-scope or private (SSRF) hosts. It mirrors the stdlib default of
// refusing more than 10 redirects.
//
// This is a defense-in-depth scope confinement layer: it prevents the HTTP
// client from following redirects that leave the crawl scope or target
// private/link-local addresses. The authoritative DNS-rebinding control on
// the HTTP path is ssrfSafeDialContext (wired into the transport's DialContext),
// which re-resolves the host at connect time, closing the TOCTOU window.
func redirectScopeGuard(scopeFn func(string) bool) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		if scopeFn != nil && !scopeFn(req.URL.String()) {
			return fmt.Errorf("redirect to out-of-scope/private host blocked: %s", redactSeedURL(req.URL.String()))
		}
		return nil
	}
}

// isHTMLContentType returns true if the content type indicates HTML.
func isHTMLContentType(ct string) bool {
	return strings.Contains(ct, "text/html") ||
		strings.Contains(ct, "application/xhtml")
}
