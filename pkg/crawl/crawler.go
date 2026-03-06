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
	"net/url"
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
)

// CrawlerOptions configures the crawler behavior.
type CrawlerOptions struct {
	Depth    int
	MaxPages int
	Timeout  time.Duration
	Scope    string
	Headless bool
	Headers  map[string]string
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
	if err != nil || targetURL == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("invalid target URL: %q", targetURL)
	}

	// Launch Chrome under vespasian's control when in headless mode.
	// This lets us kill the browser immediately on signal, stopping all
	// outbound requests — Katana's internal context is disconnected from ours.
	var browserMgr *BrowserManager
	if c.opts.Headless {
		browserMgr, err = NewBrowserManager(BrowserOptions{Headless: true})
		if err != nil {
			return nil, fmt.Errorf("launch browser: %w", err)
		}
		defer browserMgr.Close()
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
		MaxDepth:          c.opts.Depth,
		Timeout:           PageTimeout,
		CrawlDuration:     c.opts.Timeout,
		FieldScope:        MapScope(c.opts.Scope),
		Headless:          c.opts.Headless,
		CustomHeaders:     ToStringSlice(c.opts.Headers),
		Strategy:          "depth-first",
		BodyReadSize:      10 * 1024 * 1024, // 10 MB limit to prevent memory exhaustion from hostile targets
		Concurrency:       10,
		Parallelism:       10,
		RateLimit:         150,
		TimeStable:        3, // seconds to wait for DOM stability; 0 causes go-rod panic in time.NewTicker
		ScrapeJSResponses: true,
		XhrExtraction:     true,
		Silent:            true,
		OnResult: func(result output.Result) {
			mu.Lock()
			defer mu.Unlock()

			// Check MaxPages limit (using resolved maxPages)
			if pageCount >= maxPages {
				return
			}
			pageCount++

			results = append(results, MapResult(result))
			// Stop Katana once MaxPages is reached to avoid wasting resources.
			if pageCount >= maxPages {
				crawlCancel()
			}
		},
	}

	// When vespasian owns the browser, pass the WS URL to Katana so it
	// connects to our Chrome instance instead of launching its own.
	if browserMgr != nil {
		katanaOpts.ChromeWSUrl = browserMgr.WSURL()
	}

	// Initialize crawler options
	crawlerOpts, err := types.NewCrawlerOptions(katanaOpts)
	if err != nil {
		return nil, err
	}
	defer func() { _ = crawlerOpts.Close() }()

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
	defer func() { _ = engine.Close() }()

	// Run crawl in goroutine with context cancellation
	crawlErr := make(chan error, 1)
	go func() {
		crawlErr <- engine.Crawl(targetURL)
	}()

	select {
	case err := <-crawlErr:
		if err != nil {
			return results, err
		}
	case <-crawlCtx.Done():
		// crawlCtx fires for both MaxPages (crawlCancel in OnResult) and
		// signal (parent ctx canceled). Check which case we're in.
		if ctx.Err() != nil {
			// Signal received (SIGINT/SIGTERM or programmatic cancel).
			// Kill Chrome immediately to stop all outbound requests.
			if browserMgr != nil {
				browserMgr.Kill()
			}

			// Bounded wait: drain Katana's internal result buffer.
			// Chrome is dead — no network activity — we're just collecting
			// already-buffered results.
			timer := time.NewTimer(ShutdownGracePeriod)
			defer timer.Stop()
			select {
			case <-crawlErr:
				// Crawl goroutine exited cleanly.
			case <-timer.C:
				// Goroutine leaked but Chrome is dead — no network activity.
			}

			_ = engine.Close()
			return results, ctx.Err()
		}

		// MaxPages reached — close engine and drain goroutine.
		_ = engine.Close()
		<-crawlErr
	}

	return results, nil
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
			ContentType: r.Response.Headers["Content-Type"],
		}
		// Truncate response body if it exceeds MaxResponseBodySize
		if len(req.Response.Body) > MaxResponseBodySize {
			req.Response.Body = req.Response.Body[:MaxResponseBodySize]
		}
	}

	return req
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
