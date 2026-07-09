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
	"time"
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
	// MaxHTTPBodySize is the maximum body size to read per HTTP response in the
	// HTTPCrawler (10 MB DoS cap). Distinct from MaxResponseBodySize (1 MB
	// retention cap) — both serve different purposes.
	MaxHTTPBodySize = 10 * 1024 * 1024

	// interruptMessage is printed to Stderr when the crawl is stopped by a
	// canceled context (e.g., SIGINT). Shared by HTTPCrawler and RodCrawler.
	interruptMessage = "\ninterrupt received, stopping crawl...\n"

	// DefaultConcurrency is the default number of concurrent browser tabs / HTTP workers.
	DefaultConcurrency = 10
	// MaxConcurrency is the upper bound on concurrent browser tabs / HTTP workers. Each
	// tab consumes significant Chrome process memory (~50 MB), so unbounded values
	// could exhaust system resources.
	MaxConcurrency = 50
)

// CrawlerOptions configures the crawler behavior.
type CrawlerOptions struct {
	Depth         int
	MaxPages      int
	Timeout       time.Duration
	Scope         string
	Headless      bool
	Headers       map[string]string
	Proxy         string    // optional: proxy address for the crawler backend (e.g., "http://127.0.0.1:8080")
	ProxyInsecure bool      // net/http backend only: disable TLS verification for an http/https intercepting proxy (Burp/mitmproxy MITM). Off by default; no effect on the headless backend or on socks5.
	Concurrency   int       // headless tab concurrency; 0 uses DefaultConcurrency (10)
	AllowPrivate  bool      // disable SSRF protection, allowing private/internal targets
	Stderr        io.Writer // user-facing status messages; nil disables output

	// BrowserMgr provides a caller-owned Chrome instance. When set, Crawl()
	// connects to this browser instead of launching its own. Callers who want
	// immediate signal-based browser termination (force-exit killing Chrome on
	// second SIGINT) MUST provide their own BrowserManager and wire it into
	// their signal handler. The internal fallback (BrowserMgr == nil) launches
	// a browser that lacks force-exit integration.
	BrowserMgr *BrowserManager
}

// Crawler is the interface for web crawling to capture HTTP traffic.
// There are two implementations: RodCrawler (headless go-rod engine) and
// HTTPCrawler (stdlib net/http engine).
type Crawler interface {
	Crawl(ctx context.Context, targetURL string) ([]ObservedRequest, error)
}

// RodCrawler implements Crawler using the go-rod headless browser engine.
// The Crawl method lives in rod_crawler.go.
type RodCrawler struct{ opts CrawlerOptions }

// HTTPCrawler implements Crawler using the stdlib net/http engine.
// The Crawl method lives in http_crawler.go.
type HTTPCrawler struct {
	opts        CrawlerOptions
	pageTimeout time.Duration // per-page fetch timeout; defaults to PageTimeout seconds when zero
}

// NewCrawler creates a new crawler with the given options.
// When opts.Headless is true, it returns a RodCrawler (headless go-rod engine).
// Otherwise it returns an HTTPCrawler (stdlib net/http engine).
func NewCrawler(opts CrawlerOptions) Crawler {
	if opts.Headless {
		return &RodCrawler{opts: opts}
	}
	return &HTTPCrawler{opts: opts}
}

// clampConcurrency returns the effective worker concurrency for both the HTTP
// and headless backends. Zero maps to DefaultConcurrency; values above
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

// validateCrawlInputs validates the crawl options and target URL, returning the
// effective maxPages and any validation error. The error strings are stable and
// asserted by tests.
func validateCrawlInputs(opts CrawlerOptions, targetURL string) (int, error) {
	maxPages := opts.MaxPages
	if maxPages <= 0 {
		maxPages = DefaultMaxPages
	}

	if opts.Depth < 0 {
		return 0, fmt.Errorf("depth must be non-negative, got %d", opts.Depth)
	}

	u, err := url.Parse(targetURL)
	if err != nil || targetURL == "" || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return 0, fmt.Errorf("invalid target URL: %q", redactSeedURL(targetURL))
	}

	return maxPages, nil
}
