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
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
)

// DefaultStableWait is the default DOM-stability wait.
const DefaultStableWait = 3 * time.Second

// Kept in sync with the `name:"..."` tag on CrawlCmd.DangerousAllowPrivate and
// ScanCmd.DangerousAllowPrivate; operators copy-paste it from error messages.
const flagDangerousAllowPrivate = "--dangerous-allow-private"

const redactedURLPlaceholder = "<URL with userinfo redacted>"

// redactSeedURL strips userinfo so the seed URL can be echoed to stderr.
//
// Fails closed on any residual "@": an opaque URL ("http:user:pass@host/path")
// parses into u.Opaque, so u.User = nil is a no-op and credentials would survive
// u.String(). A parse failure with "@" would echo them verbatim. "@" also appears
// unencoded in paths and queries, which cannot cheaply be told apart from the
// credential case, so those lose host context — a deliberate false positive.
func redactSeedURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		if strings.Contains(raw, "@") {
			return redactedURLPlaceholder
		}
		return raw
	}
	u.User = nil
	out := u.String()
	if strings.Contains(out, "@") {
		return redactedURLPlaceholder
	}
	return out
}

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

// rodEngine connects to a BrowserManager-owned Chrome and runs one worker
// goroutine per tab.
type rodEngine struct {
	browser  *rod.Browser
	opts     engineOptions
	frontier *urlFrontier
}

// newRodEngine connects to wsURL. The caller must Close().
func newRodEngine(wsURL string, opts engineOptions) (*rodEngine, error) {
	if opts.Concurrency > MaxConcurrency && opts.Stderr != nil {
		fmt.Fprintf(opts.Stderr, "warning: --concurrency %d exceeds maximum (%d), capping\n", opts.Concurrency, MaxConcurrency) //nolint:errcheck // best-effort
	}
	opts.Concurrency = clampConcurrency(opts.Concurrency)
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

// Crawl blocks until the frontier is exhausted, maxPages is hit, or ctx is
// canceled, passing each captured request to onResult.
func (e *rodEngine) Crawl(ctx context.Context, seedURL string, onResult func(ObservedRequest)) error {
	// Push returns 0 when the seed is rejected: malformed, out of scope, or —
	// usually — a private host the SSRF check refuses without
	// flagDangerousAllowPrivate. Erroring is what stops that looking like a
	// successful crawl of nothing (LAB-2438).
	if e.frontier.Push([]urlEntry{{URL: seedURL, Depth: 0}}) == 0 {
		return fmt.Errorf("seed URL rejected by frontier (scope, SSRF, or parse): %s; "+
			"if crawling a private host (localhost, 127.0.0.1, RFC1918, link-local), "+
			"pass %s", redactSeedURL(seedURL), flagDangerousAllowPrivate)
	}

	// MaxPages counts pages, not requests — one SPA page fires dozens of XHR calls
	// (LAB-4678). Slots are reserved under this mutex before visiting, which makes
	// the cap exact, and hitting it does NOT cancel ctx: in-flight pages finalize
	// and emit everything they captured rather than being cut off mid-page. Which
	// pages land inside the budget still varies run to run.
	var (
		mu        sync.Mutex
		pageCount int
	)

	var wg sync.WaitGroup
	for i := range e.opts.Concurrency {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			e.worker(ctx, id, onResult, &mu, &pageCount, e.opts.MaxPages)
		}(i)
	}

	wg.Wait()
	e.frontier.Close()
	return ctx.Err()
}

// Close disconnects only. BrowserManager owns the Chrome lifecycle.
func (e *rodEngine) Close() error {
	return e.browser.Close()
}

// pageBudgetReached checks under mu; maxPages <= 0 is unlimited. With reserve, the
// compare and the increment share one critical section, so workers cannot
// overshoot — a separate check-then-increment would race. reserve=false is for the
// pre-Pop early-out, which must not consume a slot.
func pageBudgetReached(mu *sync.Mutex, pageCount *int, maxPages int, reserve bool) bool {
	mu.Lock()
	defer mu.Unlock()
	if maxPages > 0 && *pageCount >= maxPages {
		return true
	}
	if reserve {
		*pageCount++
	}
	return false
}

// worker is the per-tab goroutine: pop, visit, capture, push discovered links.
func (e *rodEngine) worker(ctx context.Context, id int, onResult func(ObservedRequest), mu *sync.Mutex, pageCount *int, maxPages int) {
	for {
		if ctx.Err() != nil {
			return
		}

		// Check-only: nothing popped yet, so no slot to reserve.
		if pageBudgetReached(mu, pageCount, maxPages, false) {
			return
		}

		entry, ok := e.frontier.Pop()
		if !ok {
			return // frontier exhausted
		}
		// MarkActive is NOT called: Pop already incremented the active counter
		// inside its own critical section, making dequeue+activate atomic. Only
		// MarkIdle() is needed after processing.

		// Another worker may have filled the budget while this one blocked in Pop,
		// so release without visiting. Reserving before the visit rather than
		// counting after is what avoids overshooting by up to Concurrency pages.
		if pageBudgetReached(mu, pageCount, maxPages, true) {
			e.frontier.MarkIdle()
			return
		}

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

		for _, req := range requests {
			if ctx.Err() != nil {
				e.frontier.MarkIdle()
				return
			}
			onResult(req)
		}

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

// visitPage navigates a fresh tab, captures network events, waits for DOM
// stability, and extracts links.
func (e *rodEngine) visitPage(ctx context.Context, target urlEntry) ([]ObservedRequest, []string, error) {
	// Fresh tab per visit: no stale state carried between pages.
	page, err := e.browser.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		return nil, nil, fmt.Errorf("create tab: %w", err)
	}
	defer func() {
		page.Close() //nolint:errcheck,gosec // best-effort close; page may already be closed
	}()

	page = page.Context(ctx).Timeout(e.opts.PageTimeout)

	enableNetwork := proto.NetworkEnable{}
	if err := enableNetwork.Call(page); err != nil {
		return nil, nil, fmt.Errorf("enable network: %w", err)
	}

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

	// Before navigation, or the first requests are missed.
	capture, waitEvents := newPageNetworkCapture(page, target.URL)

	// Exits when page.Close() tears down the CDP session EachEvent listens on, or
	// when the page context expires.
	go waitEvents()

	if err := page.Navigate(target.URL); err != nil {
		return nil, nil, fmt.Errorf("navigate: %w", err)
	}

	if err := page.WaitLoad(); err != nil {
		// Non-fatal: not every page fires load before the timeout.
		if ctx.Err() != nil {
			return capture.Results(), nil, nil
		}
	}

	// These waits overlap across workers rather than serializing.
	if err := page.WaitStable(e.opts.StableTimeout); err != nil {
		if ctx.Err() != nil {
			return capture.Results(), nil, nil
		}
	}

	// Catches late XHR/fetch from mutation and intersection observers that fire
	// during stabilization.
	settle := time.NewTimer(200 * time.Millisecond)
	select {
	case <-settle.C:
	case <-ctx.Done():
		settle.Stop()
		return capture.Results(), nil, nil
	}

	capturedResults := capture.Results()
	results, links := enrichFromPage(page, capturedResults, target.URL, e.opts.Stderr, e.opts.ScopeCheck)
	return results, links, nil
}

// enrichFromPage does the DOM-reading half — links, jsluice, forms — then hands
// the pure combining logic to [mergeEnrichedLinks], which is unit tested. Errors
// are non-fatal; captured network results are always returned.
//
// pageURL is where the worker navigated, used for form PageURL tagging and as the
// resolution fallback when there is no <base href> and page.Info() errors.
func enrichFromPage(page *rod.Page, captured []ObservedRequest, pageURL string, stderr io.Writer, scopeFn func(string) bool) ([]ObservedRequest, []string) {
	// No production caller passes nil today; the guard exists so the
	// merger-threading contract is testable without a real rod.Page.
	if page == nil {
		captured, links := mergeEnrichedLinksFn(captured, nil, nil, nil, nil, pageURL, pageURL, scopeFn)
		return captured, links
	}

	// jsluice URLs and form actions must honor <base href> like the browser, or
	// the frontier queues mangled nested paths.
	resolvedPageURL := pageURL
	if info, err := page.Info(); err == nil && info.URL != "" {
		resolvedPageURL = info.URL
	}
	baseURL := effectiveBaseURL(page, resolvedPageURL)

	// Non-fatal: domLinks=nil still leaves the JS, inline-script and form paths.
	domLinks, err := extractLinks(page, baseURL)
	if err != nil {
		if stderr != nil {
			fmt.Fprintf(stderr, "link extraction failed for %s: %v\n", pageURL, err) //nolint:errcheck // best-effort
		}
		domLinks = nil
	}

	jsFromResponses := extractURLsFromResponses(captured)
	jsFromInline := extractURLsFromInlineScripts(page)

	// resolvedPageURL for no-action forms per the HTML spec, baseURL for explicit
	// action refs per browser behavior. A DOM error means no forms.
	forms, ferr := extractForms(page, resolvedPageURL, baseURL)
	if ferr != nil && stderr != nil {
		fmt.Fprintf(stderr, "form extraction failed for %s: %v\n", pageURL, ferr) //nolint:errcheck // best-effort
	}

	captured, links := mergeEnrichedLinksFn(captured, domLinks, jsFromResponses, jsFromInline, forms, resolvedPageURL, baseURL, scopeFn)
	return captured, links
}

// mergeEnrichedLinksFn is a var so tests can check scopeFn is threaded from
// e.opts.ScopeCheck through to mergeEnrichedLinks without a browser (LAB-2221).
//
// NOT PARALLEL-SAFE: tests swap it and MUST NOT call t.Parallel().
// Unsynchronized because production reads it single-threaded per page.
var mergeEnrichedLinksFn = mergeEnrichedLinks

// mergeEnrichedLinks is the pure, DOM-free half of enrichFromPage: it merges every
// link source and appends synthetic form ObservedRequests to captured.
//
// Both pageURL and baseURL are needed: forms tag PageURL from the former and
// resolve explicit action refs against the latter. scopeFn filters form actions,
// which the frontier's Push-time scope check cannot do because these go straight
// into captured. Nil scopeFn means no filtering.
//
// Returned links may hold cross-source duplicates; the frontier dedupes on Push,
// so do not add another layer.
func mergeEnrichedLinks(
	captured []ObservedRequest,
	domLinks []string,
	jsFromResponses, jsFromInline []jsExtractedURL,
	forms []discoveredForm,
	pageURL, baseURL string,
	scopeFn func(string) bool,
) ([]ObservedRequest, []string) {
	links := slices.Clone(domLinks)

	if len(jsFromResponses) > 0 {
		links = append(links, jsExtractedToLinks(jsFromResponses, baseURL)...)
	}
	if len(jsFromInline) > 0 {
		links = append(links, jsExtractedToLinks(jsFromInline, baseURL)...)
	}

	if len(forms) > 0 {
		// Without this, <form action="https://attacker/x"> on an in-scope page
		// reaches capture.json and then the probe stage, which re-requests it with
		// the operator's headers attached. Empty Action spec-defaults to pageURL and
		// is same-origin, so keep those.
		//
		// Nil scopeFn aliases `forms` to avoid an allocation — do NOT mutate
		// scopedForms in that case, the alias reaches the caller's slice.
		scopedForms := forms
		if scopeFn != nil {
			scopedForms = make([]discoveredForm, 0, len(forms))
			for _, f := range forms {
				if f.Action == "" || scopeFn(f.Action) {
					scopedForms = append(scopedForms, f)
				}
			}
		}
		formRequests := formsToObservedRequests(scopedForms, pageURL)
		captured = append(captured, formRequests...)
		for _, f := range scopedForms {
			if f.Action == "" {
				continue
			}
			if isLikelyPage(f.Action) {
				links = append(links, f.Action)
			}
		}
	}

	return captured, links
}
