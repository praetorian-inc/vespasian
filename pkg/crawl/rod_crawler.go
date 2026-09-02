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

// Crawl runs a concurrent headless crawl.
func (c *RodCrawler) Crawl(ctx context.Context, targetURL string) ([]ObservedRequest, error) {
	maxPages, err := validateCrawlInputs(c.opts, targetURL)
	if err != nil {
		return nil, err
	}

	if ctx.Err() != nil {
		if c.opts.Stderr != nil {
			fmt.Fprint(c.opts.Stderr, interruptMessage) //nolint:errcheck // best-effort status message
		}
		return nil, ctx.Err()
	}

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

// crawlHeadless drives tabs in parallel so DOM-stability waits overlap.
//
// SSRF: no Go dial-time IP pin here — Chrome resolves DNS outside net.Dialer, so
// only the upfront scopeChecker check applies. Known limitation; HTTPCrawler uses
// ssrfSafeDialContext as the authoritative rebinding control.
func (c *RodCrawler) crawlHeadless(ctx context.Context, targetURL string, maxPages int, browserMgr *BrowserManager) ([]ObservedRequest, error) {
	if c.opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.opts.Timeout)
		defer cancel()
	}

	// newSeedScope wraps the policy predicate with the seed-effective-origin
	// widening: Chrome follows a seed redirect and tags every captured request
	// with the post-redirect origin, which the exact same-origin predicate would
	// otherwise reject wholesale. See [seedScope] for the containment bounds.
	scope, err := newSeedScope(targetURL, c.opts.Scope, c.opts.AllowPrivate, c.opts.Stderr)
	if err != nil {
		return nil, fmt.Errorf("scope setup: %w", err)
	}

	// A --header Cookie goes into Chrome's store via Storage.setCookies, not
	// Network.setExtraHTTPHeaders: extra headers do not survive server-side
	// redirects — Spring Security's 302 to /login on WebGoat strips the JSESSIONID
	// and breaks session auth (LAB-2222).
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
		ScopeCheck:    scope.Check,
		Stderr:        c.opts.Stderr,
		Resume:        c.opts.resume(targetURL),

		LearnEffectiveOrigin: scope.LearnEffectiveOrigin,
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

	// Killing Chrome is what actually stops outbound requests.
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
