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
	// DefaultMaxPages applies when MaxPages is unset.
	DefaultMaxPages = 1000

	// MaxResponseBodySize is what is RETAINED for classification; link extraction
	// runs over the larger MaxHTTPBodySize read.
	MaxResponseBodySize = 1 * 1024 * 1024

	// PageTimeout (seconds) is internal, not user-configurable: it stops one
	// unresponsive page blocking the crawl.
	PageTimeout = 30

	// MaxHTTPBodySize is the per-response read cap.
	MaxHTTPBodySize = 10 * 1024 * 1024

	interruptMessage = "\ninterrupt received, stopping crawl...\n"

	// DefaultConcurrency is the tab/worker count when Concurrency is unset.
	DefaultConcurrency = 10

	// MaxConcurrency is capped because each tab costs ~50 MB of Chrome.
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

// Crawler captures HTTP traffic. See RodCrawler and HTTPCrawler.
type Crawler interface {
	Crawl(ctx context.Context, targetURL string) ([]ObservedRequest, error)
}

// RodCrawler is the headless go-rod backend; Crawl is in rod_crawler.go.
type RodCrawler struct{ opts CrawlerOptions }

// HTTPCrawler is the net/http backend; Crawl is in http_crawler.go.
type HTTPCrawler struct {
	opts        CrawlerOptions
	pageTimeout time.Duration // per-page fetch timeout; defaults to PageTimeout seconds when zero
}

// NewCrawler returns a RodCrawler when opts.Headless, else an HTTPCrawler.
func NewCrawler(opts CrawlerOptions) Crawler {
	if opts.Headless {
		return &RodCrawler{opts: opts}
	}
	return &HTTPCrawler{opts: opts}
}

// clampConcurrency maps 0 to DefaultConcurrency and caps at MaxConcurrency.
func clampConcurrency(n int) int {
	if n <= 0 {
		return DefaultConcurrency
	}
	if n > MaxConcurrency {
		return MaxConcurrency
	}
	return n
}

// validateCrawlInputs returns the effective maxPages. Error strings are asserted
// by tests, so keep them stable.
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
