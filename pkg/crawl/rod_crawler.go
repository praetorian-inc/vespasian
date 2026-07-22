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
	"sync"
	"time"
)

// Crawl runs a concurrent headless crawl using go-rod directly.
// This is a verbatim wrapper of the original crawlHeadless logic.
func (c *RodCrawler) Crawl(ctx context.Context, targetURL string) ([]ObservedRequest, error) {
	maxPages, err := validateCrawlInputs(c.opts, targetURL)
	if err != nil {
		return nil, err
	}

	// Early return if the parent context is already canceled.
	if ctx.Err() != nil {
		if c.opts.Stderr != nil {
			fmt.Fprint(c.opts.Stderr, interruptMessage) //nolint:errcheck // best-effort status message
		}
		return nil, ctx.Err()
	}

	// Use caller-provided browser or launch Chrome under vespasian's control.
	var browserMgr *BrowserManager
	if c.opts.BrowserMgr != nil {
		browserMgr = c.opts.BrowserMgr
	} else {
		browserMgr, err = NewBrowserManager(BrowserOptions{Headless: true, Proxy: c.opts.Proxy})
		if err != nil {
			return nil, fmt.Errorf("launch browser: %w", err)
		}
		defer browserMgr.Close()
	}

	return c.crawlHeadless(ctx, targetURL, maxPages, browserMgr)
}

// crawlHeadless runs a concurrent headless crawl using go-rod directly. It
// drives multiple browser tabs in parallel so DOM-stability waits overlap
// across pages, making crawls significantly faster than a serial page-by-page
// visit.
//
// SSRF note: the headless backend relies on Chrome's own networking stack and
// the upfront scopeChecker SSRF check. It does NOT have a Go dial-time IP pin
// (ssrfSafeDialContext) equivalent — Chrome's DNS resolution is outside Go's
// net.Dialer. This is a known limitation; the HTTPCrawler path uses
// ssrfSafeDialContext as the authoritative DNS-rebinding control.
func (c *RodCrawler) crawlHeadless(ctx context.Context, targetURL string, maxPages int, browserMgr *BrowserManager) ([]ObservedRequest, error) {
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
	// See ApplyCookieHeader for the extract/parse/inject pipeline and
	// cookies_test.go for the wiring coverage.
	extraHeaders, err := ApplyCookieHeader(c.opts.Headers, targetURL, browserMgr.SetCookies)
	if err != nil {
		return nil, err
	}

	engine, err := newRodEngine(browserMgr.wsURL(), engineOptions{
		Concurrency:   c.opts.Concurrency,
		MaxPages:      maxPages,
		MaxRequests:   c.opts.MaxRequests,
		Interact:      c.opts.Interact,
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
			fmt.Fprint(c.opts.Stderr, interruptMessage) //nolint:errcheck // best-effort status message
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
