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
	Depth        int
	MaxPages     int
	Timeout      time.Duration
	Scope        string
	Headless     bool
	Headers      map[string]string
	Proxy        string    // optional: proxy address for Chrome (e.g., "http://127.0.0.1:8080")
	Concurrency  int       // headless tab concurrency; 0 uses DefaultConcurrency (10)
	AllowPrivate bool      // disable SSRF protection, allowing private/internal targets
	Stderr       io.Writer // user-facing status messages; nil disables output

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
func (c *Crawler) Crawl(ctx context.Context, targetURL string) ([]ObservedRequest, error) {
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

	// Early return if the parent context is already canceled.
	if ctx.Err() != nil {
		if c.opts.Stderr != nil {
			fmt.Fprintf(c.opts.Stderr, "\ninterrupt received, stopping crawl...\n") //nolint:errcheck // best-effort status message
		}
		return nil, ctx.Err()
	}

	// Use caller-provided browser or launch Chrome under vespasian's control.
	var browserMgr *BrowserManager
	if c.opts.BrowserMgr != nil {
		browserMgr = c.opts.BrowserMgr
	} else if c.opts.Headless {
		browserMgr, err = NewBrowserManager(BrowserOptions{Headless: true, Proxy: c.opts.Proxy})
		if err != nil {
			return nil, fmt.Errorf("launch browser: %w", err)
		}
		defer browserMgr.Close()
	}

	if c.opts.Headless {
		return c.crawlHeadless(ctx, targetURL, maxPages, browserMgr)
	}
	return c.crawlStandard(ctx, targetURL, maxPages, browserMgr)
}

// crawlHeadless runs a concurrent headless crawl using go-rod directly,
// bypassing Katana's serial hybrid engine. This enables overlapping DOM
// stability waits across multiple browser tabs for significantly faster crawls.
func (c *Crawler) crawlHeadless(ctx context.Context, targetURL string, maxPages int, browserMgr *BrowserManager) ([]ObservedRequest, error) {
	// Apply the overall crawl timeout if configured.
	if c.opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.opts.Timeout)
		defer cancel()
	}

	scopeFn, err := scopeChecker(targetURL, c.opts.Scope, c.opts.AllowPrivate)
	if err != nil {
		return nil, fmt.Errorf("scope setup: %w", err)
	}

	// LAB-2222: a Cookie value passed via --header must be injected into
	// Chrome's cookie store (Storage.setCookies), not attached as an extra
	// HTTP header. Extra headers set via Network.setExtraHTTPHeaders don't
	// survive server-side redirects (e.g., Spring Security's 302→/login on
	// WebGoat strips the JSESSIONID, breaking session auth). Cookies in
	// Chrome's own store persist across redirects, new tabs, and fetches.
	cookieValue, extraHeaders := ExtractCookieHeader(c.opts.Headers)
	if cookieValue != "" {
		params, cerr := ParseCookiesToParams(targetURL, cookieValue)
		if cerr != nil {
			return nil, fmt.Errorf("parse cookies: %w", cerr)
		}
		if serr := browserMgr.SetCookies(params); serr != nil {
			return nil, fmt.Errorf("inject cookies: %w", serr)
		}
	}

	engine, err := newRodEngine(browserMgr.wsURL(), engineOptions{
		Concurrency:   c.opts.Concurrency,
		MaxPages:      maxPages,
		MaxDepth:      c.opts.Depth,
		PageTimeout:   time.Duration(PageTimeout) * time.Second,
		StableTimeout: DefaultStableWait,
		Headers:       extraHeaders,
		ScopeCheck:    scopeFn,
		Stderr:        c.opts.Stderr,
	})
	if err != nil {
		return nil, fmt.Errorf("create engine: %w", err)
	}
	defer engine.Close() //nolint:errcheck // best-effort cleanup

	results := make([]ObservedRequest, 0, min(maxPages, 1000))
	var mu sync.Mutex

	err = engine.Crawl(ctx, targetURL, func(req ObservedRequest) {
		mu.Lock()
		results = append(results, req)
		mu.Unlock()
	})

	// On signal, kill Chrome immediately to stop all outbound requests.
	if ctx.Err() != nil {
		if c.opts.Stderr != nil {
			fmt.Fprintf(c.opts.Stderr, "\ninterrupt received, stopping crawl...\n") //nolint:errcheck // best-effort status message
		}
		if browserMgr != nil {
			browserMgr.Kill()
		}
	}

	mu.Lock()
	snapshot := make([]ObservedRequest, len(results))
	copy(snapshot, results)
	mu.Unlock()

	if err != nil && ctx.Err() == nil {
		return snapshot, err
	}
	return snapshot, ctx.Err()
}

// crawlStandard runs the non-headless crawl using Katana's standard HTTP engine.
// This path is unchanged from the original implementation and will be removed
// when Katana is fully replaced in a separate ticket.
func (c *Crawler) crawlStandard(ctx context.Context, targetURL string, maxPages int, browserMgr *BrowserManager) ([]ObservedRequest, error) { //nolint:gocyclo // legacy Katana orchestration
	crawlCtx, crawlCancel := context.WithCancel(ctx)
	defer crawlCancel()

	results := make([]ObservedRequest, 0, min(maxPages, 1000))
	var mu sync.Mutex
	pageCount := 0

	katanaOpts := &types.Options{
		MaxDepth:               c.opts.Depth,
		Timeout:                PageTimeout,
		CrawlDuration:          c.opts.Timeout,
		FieldScope:             MapScope(c.opts.Scope),
		Headless:               false,
		CustomHeaders:          ToStringSlice(c.opts.Headers),
		Strategy:               "depth-first",
		BodyReadSize:           10 * 1024 * 1024,
		Concurrency:            10,
		Parallelism:            10,
		RateLimit:              150,
		TimeStable:             3,
		ScrapeJSResponses:      true,
		ScrapeJSLuiceResponses: true,
		XhrExtraction:          true,
		Silent:                 true,
		OnResult: func(result output.Result) {
			mapped := MapResult(result)

			mu.Lock()
			defer mu.Unlock()

			if pageCount >= maxPages {
				return
			}
			pageCount++
			results = append(results, mapped)
			if pageCount >= maxPages {
				crawlCancel()
			}
		},
	}

	if browserMgr != nil {
		katanaOpts.ChromeWSUrl = browserMgr.wsURL()
	}

	crawlerOpts, err := types.NewCrawlerOptions(katanaOpts)
	if err != nil {
		return nil, err
	}
	defer crawlerOpts.Close() //nolint:errcheck // best-effort cleanup

	engine, err := standard.New(crawlerOpts)
	if err != nil {
		return nil, err
	}
	var closeOnce sync.Once
	closeEngine := func() { closeOnce.Do(func() { engine.Close() }) } //nolint:errcheck,gosec // best-effort cleanup
	defer closeEngine()

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
		if ctx.Err() != nil {
			if c.opts.Stderr != nil {
				fmt.Fprintf(c.opts.Stderr, "\ninterrupt received, stopping crawl...\n") //nolint:errcheck // best-effort status message
			}

			if browserMgr != nil {
				browserMgr.Kill()
			}

			timer := time.NewTimer(ShutdownGracePeriod)
			var timerExpired bool
			select {
			case <-crawlErr:
			case <-timer.C:
				timerExpired = true
			}
			timer.Stop()

			boundedRun(closeEngine, DrainTimeout)

			if timerExpired {
				drainTimer := time.NewTimer(DrainTimeout)
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
			return snapshot, ctx.Err()
		}

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
