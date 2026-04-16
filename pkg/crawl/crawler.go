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
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/katana/pkg/engine/hybrid"
	"github.com/projectdiscovery/katana/pkg/engine/standard"
	"github.com/projectdiscovery/katana/pkg/output"
	"github.com/projectdiscovery/katana/pkg/types"
)

const (
	// DefaultMaxPages is the maximum number of pages to crawl when no limit is specified.
	DefaultMaxPages = 1000
	// MaxResponseBodySize is the maximum response body size to retain for classification (1 MB).
	MaxResponseBodySize = 1 * 1024 * 1024
	// PageTimeout is the per-page timeout in seconds for go-rod and HTTP requests.
	// This is an internal constant, not user-configurable — it prevents a single
	// unresponsive page from blocking the sequential headless crawl.
	PageTimeout = 30
	// ShutdownGracePeriod is the bounded wait after killing Chrome for Katana's
	// internal result buffer to drain. Chrome is dead at this point — no network
	// activity — we're just collecting already-buffered results.
	ShutdownGracePeriod = 2 * time.Second
	// DrainTimeout is the secondary bounded wait after engine.Close() for the
	// crawl goroutine to exit. Prevents goroutine leaks when the engine is slow
	// to shut down.
	DrainTimeout = 500 * time.Millisecond
)

// CrawlerOptions configures the crawler behavior.
type CrawlerOptions struct {
	Depth    int
	MaxPages int
	Timeout  time.Duration
	Scope    string
	Headless bool
	Headers  map[string]string
	Proxy    string    // optional: proxy address for Chrome (e.g., "http://127.0.0.1:8080")
	Stderr   io.Writer // user-facing status messages; nil disables output

	// BrowserMgr provides a caller-owned Chrome instance. When set, Crawl()
	// connects to this browser instead of launching its own. Callers who want
	// immediate signal-based browser termination (force-exit killing Chrome on
	// second SIGINT) MUST provide their own BrowserManager and wire it into
	// their signal handler. The internal fallback (BrowserMgr == nil) launches
	// a browser that lacks force-exit integration.
	BrowserMgr *BrowserManager
}

// Crawler performs web crawling to capture HTTP traffic.
type Crawler struct {
	opts CrawlerOptions
}

// NewCrawler creates a new crawler with the given options.
func NewCrawler(opts CrawlerOptions) *Crawler {
	return &Crawler{opts: opts}
}

// Crawl crawls the target URL and returns observed requests.
func (c *Crawler) Crawl(ctx context.Context, targetURL string) ([]ObservedRequest, error) { //nolint:gocyclo // top-level crawl orchestration
	maxPages := c.opts.MaxPages
	if maxPages <= 0 {
		maxPages = DefaultMaxPages
	}

	if c.opts.Depth < 0 {
		return nil, fmt.Errorf("depth must be non-negative, got %d", c.opts.Depth)
	}

	u, err := url.Parse(targetURL)
	if err != nil || targetURL == "" || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("invalid target URL: %q", targetURL)
	}

	// Early return if the parent context is already canceled. This avoids
	// initializing Katana (LevelDB, filters, output writer) only to tear
	// everything down immediately, and prevents internal goroutine leaks
	// that cause data races on Katana's global CustomFieldsMap.
	if ctx.Err() != nil {
		if c.opts.Stderr != nil {
			fmt.Fprintf(c.opts.Stderr, "\ninterrupt received, stopping crawl...\n") //nolint:errcheck // best-effort status message
		}
		return nil, ctx.Err()
	}

	// Use caller-provided browser or launch Chrome under vespasian's control.
	// This lets us kill the browser immediately on signal, stopping all
	// outbound requests — Katana's internal context is disconnected from ours.
	var browserMgr *BrowserManager
	if c.opts.BrowserMgr != nil {
		browserMgr = c.opts.BrowserMgr
		// Caller owns lifecycle — don't defer Close here.
	} else if c.opts.Headless {
		browserMgr, err = NewBrowserManager(BrowserOptions{Headless: true, Proxy: c.opts.Proxy})
		if err != nil {
			return nil, fmt.Errorf("launch browser: %w", err)
		}
		defer browserMgr.Close()
	}

	// Extract Cookie headers for direct injection into Chrome's cookie store.
	// Network.setExtraHTTPHeaders (Katana's addHeadersToPage) does not reliably
	// propagate Cookie headers across redirects and Fetch-intercepted requests
	// in headless Chrome. Injecting via Storage.setCookies ensures cookies
	// survive the full browser session.
	headers := c.opts.Headers
	var hasCookies bool
	if c.opts.Headless && browserMgr != nil {
		cookieValue, remaining := ExtractCookieHeader(headers)
		if cookieValue != "" {
			cookies, parseErr := ParseCookiesToParams(targetURL, cookieValue)
			if parseErr != nil {
				return nil, fmt.Errorf("parse cookie header: %w", parseErr)
			}
			if err := browserMgr.SetCookies(cookies); err != nil {
				return nil, fmt.Errorf("inject cookies into browser: %w", err)
			}
			headers = remaining
			hasCookies = true
		}
	}

	// Create a cancellable context to stop Katana when MaxPages is reached.
	crawlCtx, crawlCancel := context.WithCancel(ctx)
	defer crawlCancel()

	// Pre-allocate results slice with capacity, capped at 1000 to limit initial allocation
	results := make([]ObservedRequest, 0, min(maxPages, 1000))
	var mu sync.Mutex
	pageCount := 0

	// Build Katana options
	katanaOpts := &types.Options{
		MaxDepth:      c.opts.Depth,
		Timeout:       PageTimeout,
		CrawlDuration: c.opts.Timeout,
		FieldScope:    MapScope(c.opts.Scope),
		Headless:      c.opts.Headless,
		CustomHeaders: ToStringSlice(headers),
		// Disable incognito mode when cookies were injected into Chrome's
		// default browser context. Incognito creates a fresh context with an
		// empty cookie jar, discarding the injected cookies.
		HeadlessNoIncognito: hasCookies,
		Strategy:            "depth-first",
		// BodyReadSize (10 MB) is intentionally larger than MaxResponseBodySize (1 MB).
		// Katana needs the full body for link extraction and JS parsing to maximize
		// crawl coverage; we only retain MaxResponseBodySize for classification.
		// Peak memory: up to Concurrency × BodyReadSize (100 MB with 10 workers).
		BodyReadSize:           10 * 1024 * 1024,
		Concurrency:            10,
		Parallelism:            10,
		RateLimit:              150,
		TimeStable:             3, // seconds to wait for DOM stability; 0 causes go-rod panic in time.NewTicker
		ScrapeJSResponses:      true,
		ScrapeJSLuiceResponses: true,
		XhrExtraction:          true,
		Silent:                 true,
		OnResult: func(result output.Result) {
			// Map result outside the lock — MapResult may do URL parsing
			// and body truncation, which is wasted work under contention.
			mapped := MapResult(result)

			mu.Lock()
			defer mu.Unlock()

			// Check MaxPages limit (using resolved maxPages)
			if pageCount >= maxPages {
				return
			}
			pageCount++

			results = append(results, mapped)
			// Stop Katana once MaxPages is reached to avoid wasting resources.
			if pageCount >= maxPages {
				crawlCancel()
			}
		},
	}

	// When vespasian owns the browser, pass the WS URL to Katana so it
	// connects to our Chrome instance instead of launching its own.
	if browserMgr != nil {
		katanaOpts.ChromeWSUrl = browserMgr.wsURL()
	}

	// Initialize crawler options
	crawlerOpts, err := types.NewCrawlerOptions(katanaOpts)
	if err != nil {
		return nil, err
	}
	defer crawlerOpts.Close() //nolint:errcheck // best-effort cleanup

	// Create engine based on headless mode
	var engine interface {
		Crawl(string) error
		Close() error
	}

	if c.opts.Headless {
		engine, err = hybrid.New(crawlerOpts)
	} else {
		engine, err = standard.New(crawlerOpts)
	}
	if err != nil {
		return nil, err
	}
	var closeOnce sync.Once
	closeEngine := func() { closeOnce.Do(func() { engine.Close() }) } //nolint:errcheck,gosec // best-effort cleanup
	defer closeEngine()

	// Run crawl in goroutine with context cancellation
	crawlErr := make(chan error, 1)
	go func() {
		crawlErr <- engine.Crawl(targetURL)
	}()

	select {
	case err := <-crawlErr:
		if err != nil {
			mu.Lock()
			snapshot := make([]ObservedRequest, len(results))
			copy(snapshot, results)
			mu.Unlock()
			return snapshot, err
		}
	case <-crawlCtx.Done():
		// crawlCtx fires for both MaxPages (crawlCancel in OnResult) and
		// signal (parent ctx canceled). Check which case we're in.
		if ctx.Err() != nil {
			// Signal received (SIGINT/SIGTERM or programmatic cancel).
			// Notify the user immediately before any cleanup.
			if c.opts.Stderr != nil {
				fmt.Fprintf(c.opts.Stderr, "\ninterrupt received, stopping crawl...\n") //nolint:errcheck // best-effort status message
			}

			// Kill Chrome immediately to stop all outbound requests.
			if browserMgr != nil {
				browserMgr.Kill()
			}

			// Bounded wait: drain Katana's internal result buffer.
			// Chrome is dead — no network activity — we're just collecting
			// already-buffered results.
			timer := time.NewTimer(ShutdownGracePeriod)
			var timerExpired bool
			select {
			case <-crawlErr:
				// Crawl goroutine exited cleanly.
			case <-timer.C:
				timerExpired = true
			}
			timer.Stop()

			// Close engine with a bounded wait — engine.Close() may block
			// if the killed Chrome process left the engine in a bad state.
			boundedRun(closeEngine, DrainTimeout)

			if timerExpired {
				// engine.Close() causes engine.Crawl() to return shortly.
				// Wait briefly to prevent goroutine leak.
				drainTimer := time.NewTimer(DrainTimeout)
				select {
				case <-crawlErr:
				case <-drainTimer.C:
				}
				drainTimer.Stop()
			}

			// Snapshot results under lock — Katana's internal goroutines
			// may still be calling OnResult during shutdown.
			mu.Lock()
			snapshot := make([]ObservedRequest, len(results))
			copy(snapshot, results)
			mu.Unlock()
			return snapshot, ctx.Err()
		}

		// MaxPages reached — close engine with bounded wait, then drain
		// crawl goroutine to match the signal path's timeout discipline.
		boundedRun(closeEngine, DrainTimeout)

		drainTimer := time.NewTimer(ShutdownGracePeriod)
		select {
		case <-crawlErr:
		case <-drainTimer.C:
		}
		drainTimer.Stop()
	}

	mu.Lock()
	snapshot := make([]ObservedRequest, len(results))
	copy(snapshot, results)
	mu.Unlock()
	return snapshot, nil
}

// MapResult converts Katana output.Result to ObservedRequest.
func MapResult(r output.Result) ObservedRequest {
	req := ObservedRequest{
		Method: "GET",
		Source: "katana",
	}

	if r.Request != nil {
		if r.Request.Method != "" {
			req.Method = r.Request.Method
		}
		req.URL = r.Request.URL
		req.Headers = r.Request.Headers
		req.Body = []byte(r.Request.Body)
		// Truncate request body if it exceeds MaxResponseBodySize
		if len(req.Body) > MaxResponseBodySize {
			req.Body = req.Body[:MaxResponseBodySize]
		}
		req.Source = r.Request.Source
		req.Tag = r.Request.Tag
		req.Attribute = r.Request.Attribute
	}

	// Parse query params from URL
	// QueryParams stores only the first value for each key. Multi-value
	// query parameters (e.g., ?ids=1&ids=2) retain only the first value.
	// This is intentional -- the classifier needs parameter names, not all values.
	if req.URL != "" {
		if u, err := url.Parse(req.URL); err == nil {
			req.QueryParams = make(map[string]string)
			for key, values := range u.Query() {
				if len(values) > 0 {
					req.QueryParams[key] = values[0]
				}
			}
		}
	}

	if r.Response != nil {
		req.Response = ObservedResponse{
			StatusCode:  r.Response.StatusCode,
			Headers:     map[string]string(r.Response.Headers),
			Body:        []byte(r.Response.Body),
			ContentType: getHeader(r.Response.Headers, "Content-Type"),
		}
		// Truncate response body if it exceeds MaxResponseBodySize
		if len(req.Response.Body) > MaxResponseBodySize {
			req.Response.Body = req.Response.Body[:MaxResponseBodySize]
		}
	}

	return req
}

// getHeader performs a case-insensitive lookup of a header name in a map.
func getHeader(headers map[string]string, name string) string {
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

// MapScope converts scope string to Katana FieldScope.
func MapScope(scope string) string {
	if scope == "same-domain" {
		return "rdn"
	}
	return "fqdn"
}

// ToStringSlice converts headers map to goflags.StringSlice.
func ToStringSlice(headers map[string]string) goflags.StringSlice {
	var result goflags.StringSlice
	for key, value := range headers {
		result = append(result, key+": "+value)
	}
	return result
}

// boundedRun executes fn in a goroutine and waits up to timeout for it to
// complete. If fn doesn't finish in time, boundedRun returns and the goroutine
// remains alive until fn eventually returns.
func boundedRun(fn func(), timeout time.Duration) {
	done := make(chan struct{})
	go func() {
		fn()
		close(done)
	}()
	t := time.NewTimer(timeout)
	select {
	case <-done:
	case <-t.C:
	}
	t.Stop()
}
