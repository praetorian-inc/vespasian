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
	"net/url"
	"sync"
	"time"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/katana/pkg/engine/hybrid"
	"github.com/projectdiscovery/katana/pkg/engine/standard"
	"github.com/projectdiscovery/katana/pkg/output"
	"github.com/projectdiscovery/katana/pkg/types"
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
	var results []ObservedRequest
	var mu sync.Mutex
	pageCount := 0

	// Build Katana options
	katanaOpts := &types.Options{
		MaxDepth:          c.opts.Depth,
		Timeout:           int(c.opts.Timeout.Seconds()),
		CrawlDuration:     c.opts.Timeout,
		FieldScope:        MapScope(c.opts.Scope),
		Headless:          c.opts.Headless,
		CustomHeaders:     ToStringSlice(c.opts.Headers),
		Strategy:          "depth-first",
		BodyReadSize:      10 * 1024 * 1024, // 10 MB limit to prevent unbounded memory allocation
		Concurrency:       10,
		Parallelism:       10,
		RateLimit:         150,
		ScrapeJSResponses: true,
		XhrExtraction:     true,
		Silent:            true,
		OnResult: func(result output.Result) {
			mu.Lock()
			defer mu.Unlock()

			// Check MaxPages limit
			if c.opts.MaxPages > 0 && pageCount >= c.opts.MaxPages {
				return
			}
			pageCount++

			results = append(results, MapResult(result))
		},
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

	// Start crawling
	if err := engine.Crawl(targetURL); err != nil {
		return nil, err
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
		req.Source = r.Request.Source
	}

	// Parse query params from URL
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
