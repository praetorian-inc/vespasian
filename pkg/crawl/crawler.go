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
	"sync"
	"time"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/katana/pkg/engine/headless"
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

	if c.opts.Headless {
		return c.crawlHeadless(ctx, targetURL, maxPages)
	}
	return c.crawlStandard(ctx, targetURL, maxPages)
}

// crawlHeadless uses Katana's new headless engine which has its own Chrome
// lifecycle and CDP-based network capture. This produces significantly better
// SPA crawl coverage than the hybrid engine.
func (c *Crawler) crawlHeadless(ctx context.Context, targetURL string, maxPages int) ([]ObservedRequest, error) {
	results := make([]ObservedRequest, 0, min(maxPages, 1000))
	var mu sync.Mutex

	katanaOpts := &types.Options{
		MaxDepth:      c.opts.Depth,
		Timeout:       PageTimeout,
		CrawlDuration: c.opts.Timeout,
		FieldScope:    MapScope(c.opts.Scope),
		Headless:      true,
		CustomHeaders: ToStringSlice(c.opts.Headers),
		Proxy:         c.opts.Proxy,
		Silent:        true,
	}

	crawlerOpts, err := types.NewCrawlerOptions(katanaOpts)
	if err != nil {
		return nil, err
	}
	defer func() { _ = crawlerOpts.Close() }()

	// Replace the default output writer with one that captures results
	// into our slice. The headless engine calls OutputWriter.Write() for
	// each discovered request — OnResult is not used by this engine.
	crawlerOpts.OutputWriter = &resultCaptureWriter{
		results:  &results,
		mu:       &mu,
		maxPages: maxPages,
	}

	engine, err := headless.New(crawlerOpts)
	if err != nil {
		return nil, err
	}
	defer engine.Close()

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
	case <-ctx.Done():
		if c.opts.Stderr != nil {
			fmt.Fprintf(c.opts.Stderr, "\ninterrupt received, stopping crawl...\n")
		}
		// The headless engine manages its own browser. Closing the engine
		// will terminate the browser. engine.Close() is deferred above.
		// Wait briefly for the crawl goroutine to finish.
		timer := time.NewTimer(ShutdownGracePeriod)
		select {
		case <-crawlErr:
		case <-timer.C:
		}
		timer.Stop()

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

// crawlStandard uses Katana's standard (non-headless) HTTP engine.
func (c *Crawler) crawlStandard(ctx context.Context, targetURL string, maxPages int) ([]ObservedRequest, error) {
	crawlCtx, crawlCancel := context.WithCancel(ctx)
	defer crawlCancel()

	results := make([]ObservedRequest, 0, min(maxPages, 1000))
	var mu sync.Mutex
	pageCount := 0

	katanaOpts := &types.Options{
		MaxDepth:      c.opts.Depth,
		Timeout:       PageTimeout,
		CrawlDuration: c.opts.Timeout,
		FieldScope:    MapScope(c.opts.Scope),
		Headless:      false,
		CustomHeaders: ToStringSlice(c.opts.Headers),
		Proxy:         c.opts.Proxy,
		Strategy:      "depth-first",
		BodyReadSize:  10 * 1024 * 1024,
		Concurrency:   10,
		Parallelism:   10,
		RateLimit:     150,
		Silent:        true,
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

	crawlerOpts, err := types.NewCrawlerOptions(katanaOpts)
	if err != nil {
		return nil, err
	}
	defer func() { _ = crawlerOpts.Close() }()

	engine, err := standard.New(crawlerOpts)
	if err != nil {
		return nil, err
	}
	var closeOnce sync.Once
	closeEngine := func() { closeOnce.Do(func() { _ = engine.Close() }) }
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
				fmt.Fprintf(c.opts.Stderr, "\ninterrupt received, stopping crawl...\n")
			}

			timer := time.NewTimer(ShutdownGracePeriod)
			select {
			case <-crawlErr:
			case <-timer.C:
			}
			timer.Stop()

			boundedRun(closeEngine, DrainTimeout)

			mu.Lock()
			snapshot := make([]ObservedRequest, len(results))
			copy(snapshot, results)
			mu.Unlock()
			return snapshot, ctx.Err()
		}

		// MaxPages reached
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

// resultCaptureWriter implements output.Writer to capture crawl results
// into a slice instead of writing to stdout/file. Used by the headless
// engine which calls OutputWriter.Write() for each discovered request.
type resultCaptureWriter struct {
	results  *[]ObservedRequest
	mu       *sync.Mutex
	maxPages int
}

func (w *resultCaptureWriter) Write(result *output.Result) error {
	if result == nil {
		return nil
	}
	mapped := MapResult(*result)

	w.mu.Lock()
	defer w.mu.Unlock()

	if len(*w.results) >= w.maxPages {
		return nil
	}
	*w.results = append(*w.results, mapped)
	return nil
}

func (w *resultCaptureWriter) WriteErr(_ *output.Error) error { return nil }
func (w *resultCaptureWriter) Close() error                   { return nil }

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
