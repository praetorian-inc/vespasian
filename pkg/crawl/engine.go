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
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
)

// DefaultConcurrency is the default number of concurrent browser tabs.
const DefaultConcurrency = 10

// flagDangerousAllowPrivate is the CLI flag name that disables SSRF protection
// for private/localhost targets. It is referenced in operator-facing error
// messages so operators can copy-paste it verbatim; keep this in sync with the
// `name:"..."` tag on CrawlCmd.DangerousAllowPrivate / ScanCmd.DangerousAllowPrivate
// in cmd/vespasian/main.go.
const flagDangerousAllowPrivate = "--dangerous-allow-private"

// MaxConcurrency is the upper bound on concurrent browser tabs. Each tab
// consumes significant Chrome process memory (~50 MB), so unbounded values
// could exhaust system resources.
const MaxConcurrency = 50

// DefaultStableWait is the default DOM stability wait duration.
const DefaultStableWait = 3 * time.Second

// engineOptions configures the concurrent headless crawl engine.
type engineOptions struct {
	Concurrency   int               // concurrent tabs (0 → DefaultConcurrency)
	MaxPages      int               // max pages to visit (0 → unlimited)
	MaxDepth      int               // max crawl depth
	PageTimeout   time.Duration     // per-page navigation timeout (0 → 30s)
	StableTimeout time.Duration     // DOM stability wait (0 → DefaultStableWait)
	Headers       map[string]string // custom headers injected into every page
	ScopeCheck    func(string) bool // returns true if a URL is in scope
	Stderr        io.Writer         // user-facing status messages
}

// rodEngine implements a concurrent headless crawl using go-rod. It connects
// to an existing Chrome instance (managed by BrowserManager) and runs N worker
// goroutines, each operating its own browser tab.
type rodEngine struct {
	browser  *rod.Browser
	opts     engineOptions
	frontier *urlFrontier
}

// newRodEngine connects to the Chrome instance at wsURL and returns a crawl
// engine ready to start. The caller must call Close() when done.
func newRodEngine(wsURL string, opts engineOptions) (*rodEngine, error) {
	if opts.Concurrency <= 0 {
		opts.Concurrency = DefaultConcurrency
	}
	if opts.Concurrency > MaxConcurrency {
		if opts.Stderr != nil {
			fmt.Fprintf(opts.Stderr, "warning: --concurrency %d exceeds maximum (%d), capping\n", opts.Concurrency, MaxConcurrency) //nolint:errcheck // best-effort
		}
		opts.Concurrency = MaxConcurrency
	}
	if opts.PageTimeout <= 0 {
		opts.PageTimeout = time.Duration(PageTimeout) * time.Second
	}
	if opts.StableTimeout <= 0 {
		opts.StableTimeout = DefaultStableWait
	}

	browser := rod.New().ControlURL(wsURL)
	if err := browser.Connect(); err != nil {
		return nil, fmt.Errorf("connect to browser: %w", err)
	}

	frontier := newURLFrontier(opts.MaxDepth, opts.ScopeCheck)

	return &rodEngine{
		browser:  browser,
		opts:     opts,
		frontier: frontier,
	}, nil
}

// Crawl starts the concurrent crawl from seedURL. It blocks until the crawl
// completes (frontier exhausted, maxPages reached, or ctx canceled). Each
// captured network request is passed to onResult as it is observed.
func (e *rodEngine) Crawl(ctx context.Context, seedURL string, onResult func(ObservedRequest)) error {
	// Seed the frontier. If Push adds zero entries the seed was rejected
	// (malformed URL, scope mismatch, or — the common case — the seed is a
	// private host such as localhost / 127.0.0.1 / RFC1918 / 169.254.*, which
	// the scope predicate's SSRF check rejects unless flagDangerousAllowPrivate
	// is set). Without this guard the crawl silently returned zero captures
	// with no error to help the operator diagnose (LAB-2438).
	if e.frontier.Push([]urlEntry{{URL: seedURL, Depth: 0}}) == 0 {
		return fmt.Errorf("seed URL rejected by frontier (scope, SSRF, or parse): %s; "+
			"if crawling a private host (localhost, 127.0.0.1, RFC1918, link-local), "+
			"pass %s", seedURL, flagDangerousAllowPrivate)
	}

	// Track page count for MaxPages enforcement. The onResult callback in
	// Crawler.crawlHeadless also tracks this, but we need our own counter
	// here to stop launching new pages.
	var (
		mu        sync.Mutex
		pageCount int
	)

	crawlCtx, crawlCancel := context.WithCancel(ctx)
	defer crawlCancel()

	// wrappedOnResult passes results to the caller and tracks page count.
	wrappedOnResult := func(req ObservedRequest) {
		mu.Lock()
		if e.opts.MaxPages > 0 && pageCount >= e.opts.MaxPages {
			mu.Unlock()
			return
		}
		pageCount++
		hitMax := e.opts.MaxPages > 0 && pageCount >= e.opts.MaxPages
		mu.Unlock()

		onResult(req)

		if hitMax {
			crawlCancel()
		}
	}

	var wg sync.WaitGroup
	for i := range e.opts.Concurrency {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			e.worker(crawlCtx, id, wrappedOnResult)
		}(i)
	}

	wg.Wait()
	e.frontier.Close()
	return ctx.Err()
}

// Close disconnects from the browser. It does NOT kill Chrome — BrowserManager
// owns that lifecycle.
func (e *rodEngine) Close() error {
	return e.browser.Close()
}

// worker is the per-tab goroutine. It takes URLs from the frontier, visits
// each one in a fresh tab, captures network events, extracts links, and pushes
// discovered URLs back to the frontier.
func (e *rodEngine) worker(ctx context.Context, id int, onResult func(ObservedRequest)) {
	for {
		// Check context before blocking on Pop.
		if ctx.Err() != nil {
			return
		}

		entry, ok := e.frontier.Pop()
		if !ok {
			return // frontier exhausted
		}
		e.frontier.MarkActive()

		requests, links, err := e.visitPage(ctx, entry)
		if err != nil {
			if ctx.Err() != nil {
				e.frontier.MarkIdle()
				return
			}
			if e.opts.Stderr != nil {
				fmt.Fprintf(e.opts.Stderr, "worker %d: error visiting %s: %v\n", id, entry.URL, err) //nolint:errcheck // best-effort
			}
			e.frontier.MarkIdle()
			continue
		}

		// Emit captured requests.
		for _, req := range requests {
			if ctx.Err() != nil {
				e.frontier.MarkIdle()
				return
			}
			onResult(req)
		}

		// Push discovered links at depth+1.
		if len(links) > 0 {
			entries := make([]urlEntry, len(links))
			for i, link := range links {
				entries[i] = urlEntry{URL: link, Depth: entry.Depth + 1}
			}
			e.frontier.Push(entries)
		}

		e.frontier.MarkIdle()
	}
}

// visitPage navigates a fresh tab to the given URL, captures network events,
// waits for DOM stability, and extracts links.
func (e *rodEngine) visitPage(ctx context.Context, target urlEntry) ([]ObservedRequest, []string, error) {
	// Create a new tab for each visit to avoid stale state.
	page, err := e.browser.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		return nil, nil, fmt.Errorf("create tab: %w", err)
	}
	defer func() {
		page.Close() //nolint:errcheck,gosec // best-effort close; page may already be closed
	}()

	// Apply context and per-page timeout.
	page = page.Context(ctx).Timeout(e.opts.PageTimeout)

	// Enable the Network domain for capturing requests.
	enableNetwork := proto.NetworkEnable{}
	if err := enableNetwork.Call(page); err != nil {
		return nil, nil, fmt.Errorf("enable network: %w", err)
	}

	// Set custom headers if configured.
	if len(e.opts.Headers) > 0 {
		headerPairs := make([]string, 0, len(e.opts.Headers)*2)
		for k, v := range e.opts.Headers {
			headerPairs = append(headerPairs, k, v)
		}
		cleanup, err := page.SetExtraHeaders(headerPairs)
		if err != nil {
			return nil, nil, fmt.Errorf("set headers: %w", err)
		}
		defer cleanup()
	}

	// Wire up network capture before navigation.
	capture, waitEvents := newPageNetworkCapture(page, target.URL)

	// Start the event listener in a goroutine. The goroutine exits when
	// the page is closed (deferred above) or the page context expires.
	// go-rod's EachEvent internally listens on the page's CDP session,
	// which is torn down by page.Close().
	go waitEvents()

	// Navigate to the target URL.
	if err := page.Navigate(target.URL); err != nil {
		return nil, nil, fmt.Errorf("navigate: %w", err)
	}

	// Wait for page load event.
	if err := page.WaitLoad(); err != nil {
		// Non-fatal: some pages may not fire load event before timeout.
		// Continue to collect whatever network events were captured.
		if ctx.Err() != nil {
			return capture.Results(), nil, nil
		}
	}

	// Wait for DOM stability — the key optimization: these waits overlap
	// across concurrent workers instead of serializing.
	if err := page.WaitStable(e.opts.StableTimeout); err != nil {
		// Non-fatal: collect partial results.
		if ctx.Err() != nil {
			return capture.Results(), nil, nil
		}
	}

	// Give network events a brief moment to settle after DOM stability.
	// This catches late XHR/fetch calls triggered by mutation observers
	// or intersection observers that fire during DOM stabilization.
	settle := time.NewTimer(200 * time.Millisecond)
	select {
	case <-settle.C:
	case <-ctx.Done():
		settle.Stop()
		return capture.Results(), nil, nil
	}

	// Extract links, run jsluice, and discover forms from the stabilized page.
	capturedResults := capture.Results()
	results, links := enrichFromPage(page, capturedResults, target.URL, e.opts.Stderr)
	return results, links, nil
}

// enrichFromPage extracts links from the DOM, runs jsluice on JS sources and
// inline scripts, and discovers forms. It returns the enriched results and all
// discovered links for the frontier. Errors are logged to stderr (if non-nil)
// but are non-fatal — captured network results are always returned.
func enrichFromPage(page *rod.Page, captured []ObservedRequest, pageURL string, stderr io.Writer) ([]ObservedRequest, []string) {
	// Extract links from the DOM.
	links, err := extractLinks(page)
	if err != nil {
		if stderr != nil {
			fmt.Fprintf(stderr, "link extraction failed for %s: %v\n", pageURL, err) //nolint:errcheck // best-effort
		}
		return captured, nil
	}

	// Run jsluice on captured JS response bodies.
	jsFromResponses := extractURLsFromResponses(captured)
	if len(jsFromResponses) > 0 {
		links = append(links, jsExtractedToLinks(jsFromResponses, pageURL)...)
	}

	// Run jsluice on inline <script> tags.
	jsFromInline := extractURLsFromInlineScripts(page)
	if len(jsFromInline) > 0 {
		links = append(links, jsExtractedToLinks(jsFromInline, pageURL)...)
	}

	// Extract forms and emit synthetic ObservedRequests for POST endpoints.
	forms, err := extractForms(page)
	if err == nil && len(forms) > 0 {
		formRequests := formsToObservedRequests(forms, pageURL)
		captured = append(captured, formRequests...)
		for _, f := range forms {
			links = append(links, f.Action)
		}
	}

	return captured, links
}
