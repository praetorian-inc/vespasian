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

	"github.com/praetorian-inc/vespasian/pkg/mediatype"
)

// DefaultStableWait is the default DOM-stability wait.
const DefaultStableWait = 3 * time.Second

// Completion-driven capture bounds (LAB-4678). After DOM stability the crawl waits
// for the network to go quiet instead of a fixed settle window, so late and dynamic
// XHR/fetch calls are captured. The wait is bounded by a floor (a minimum wait even
// when the network already looks idle), a quiet period (how long it must stay idle
// before stopping), and a per-request timeout (the age past which a still-pending
// request no longer counts as in flight, so one hung request cannot stall the wait).
//
// The ceiling is a per-page deadline of PageTimeout, computed once in visitPage and
// shared by the baseline wait and every interaction wait. It is enforced explicitly
// rather than by the rod page timeout: these waits poll local capture state and issue
// no CDP call, so the page timeout never fires inside them.
const (
	DefaultNetworkIdleFloor   = 500 * time.Millisecond
	DefaultNetworkQuietPeriod = 500 * time.Millisecond
	DefaultPerRequestTimeout  = 10 * time.Second
	networkIdlePollInterval   = 100 * time.Millisecond
)

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

// RedactURL redacts userinfo from raw. It is the exported form of
// redactSeedURL, for callers outside this package that echo a capture- or
// bundle-derived URL to an operator (currently internal/pipeline's
// classification-reason output). It is a thin pass-through, NOT a second
// implementation: redactSeedURL remains the single definition, so the two
// cannot diverge.
//
// This is the same shape as SanitizeForLog, the one other
// exported-wrapper-over-private-twin in this package. SameOrigin,
// ResolveTargetOrigin and IsPrintableASCIIURL are also exported for
// cross-package use, but they are primary definitions with no private twin --
// a different pattern.
//
// The "Seed" in the underlying name predates this general use; the logic is
// not seed-specific -- it redacts userinfo from any URL and fails closed to a
// placeholder whenever it cannot prove the result is credential-free.
func RedactURL(raw string) string { return redactSeedURL(raw) }

// engineOptions configures the concurrent headless crawl engine.
type engineOptions struct {
	Concurrency   int               // concurrent tabs (0 → DefaultConcurrency)
	MaxPages      int               // max pages to visit (0 → unlimited)
	MaxRequests   int               // admission budget over captured requests (0 → unlimited); a page may overshoot it, see crawlBudget
	MaxDepth      int               // max crawl depth
	PageTimeout   time.Duration     // per-page navigation timeout (0 → 30s)
	StableTimeout time.Duration     // DOM stability wait (0 → DefaultStableWait)
	Headers       map[string]string // custom headers injected into every page
	ScopeCheck    func(string) bool // returns true if a URL is in scope
	Stderr        io.Writer         // user-facing status messages

	// LearnEffectiveOrigin, when set, is called exactly once with the URL the
	// SEED page actually resolved to after redirects. It lets the scope predicate
	// treat the seed's effective origin as in scope, which is what makes an
	// "http → https" or "apex → www" seed redirect crawlable instead of yielding
	// an empty capture. Only the visit of the SEED ITSELF calls it, gated on
	// frontier-key identity rather than on Depth == 0 — resume restores pending
	// entries before the seed is pushed and honors the depth the checkpoint claims,
	// so depth 0 stopped being a reliable proxy for "is the seed" (LAB-4678 review).
	// See [learnSeedOrigin] and [seedScope] for the containment reasoning.
	LearnEffectiveOrigin func(effectiveURL string)

	// Completion-driven capture bounds (0 → the Default* above).
	NetworkIdleFloor   time.Duration // minimum wait after DOM stability
	NetworkQuietPeriod time.Duration // idle duration required before stopping
	PerRequestTimeout  time.Duration // age after which a pending request stops counting in-flight

	// Interact enables the opt-in interaction pass (clicks / client-side route
	// changes) to surface interaction-only endpoints. Off by default — clicking
	// can mutate state, so it must be explicitly requested (LAB-4678 Phase 2).
	Interact bool

	// Resume carries cross-run checkpoint wiring (LAB-4678 Phase 4). Zero value
	// disables both restore and capture.
	Resume resumeOptions
}

// rodEngine connects to a BrowserManager-owned Chrome and runs one worker
// goroutine per tab.
type rodEngine struct {
	browser  *rod.Browser
	opts     engineOptions
	frontier *urlFrontier

	// seedKey is seenKey(seedURL), set by Crawl before any worker starts and
	// read-only afterwards. It identifies the SEED entry so learnSeedOrigin can gate
	// on "is this the seed" rather than on "is this depth 0"; see learnSeedOrigin for
	// why depth is not a valid proxy once resume exists.
	seedKey string

	// visit performs one page visit. It is a field, defaulting to visitPage, purely
	// so worker's budget and requeue logic is reachable without a browser.
	//
	// Without this seam the entire worker loop — both budgetReached calls, the
	// requeue-on-budget path, and MaxRequests enforcement on the DEFAULT backend —
	// was testable only through the //go:build integration suite, which no CI job
	// runs. The request budget's only non-tagged coverage exercised the net/http
	// backend, where one page is one request so it degenerates to a page cap.
	// Removing `maxRequests := e.opts.MaxRequests` would have left --max-requests
	// silently inert on the backend Guard actually uses, with every test still green
	// (LAB-4678 review).
	visit func(ctx context.Context, target urlEntry) ([]ObservedRequest, []string, error)
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
	if opts.NetworkIdleFloor <= 0 {
		opts.NetworkIdleFloor = DefaultNetworkIdleFloor
	}
	if opts.NetworkQuietPeriod <= 0 {
		opts.NetworkQuietPeriod = DefaultNetworkQuietPeriod
	}
	if opts.PerRequestTimeout <= 0 {
		opts.PerRequestTimeout = DefaultPerRequestTimeout
	}

	browser := rod.New().ControlURL(wsURL)
	if err := browser.Connect(); err != nil {
		return nil, fmt.Errorf("connect to browser: %w", err)
	}

	frontier := newURLFrontier(opts.MaxDepth, opts.ScopeCheck)

	e := &rodEngine{
		browser:  browser,
		opts:     opts,
		frontier: frontier,
	}
	e.visit = e.visitPage
	return e, nil
}

// Crawl blocks until the frontier is exhausted, maxPages is hit, or ctx is
// canceled, passing each captured request to onResult.
func (e *rodEngine) Crawl(ctx context.Context, seedURL string, onResult func(ObservedRequest)) error {
	// Which frontier entry IS the seed, written once before any worker starts and
	// only read afterwards, so no synchronization is needed. The full canonical URL,
	// not the query-stripped frontier key: the frontier admits several query variants
	// of one path, so the stripped form no longer identifies a single entry and a
	// variant of the seed's path would be mistaken for the seed itself.
	e.seedKey = seenKey(seedURL)

	// Resume state is restored BEFORE seeding so already-covered pages are not
	// re-crawled (LAB-4678).
	resumed := resumeFrontier(e.frontier, e.opts.Resume, time.Now(), e.opts.Stderr)

	// Push returns 0 when the seed is rejected: malformed, out of scope, or —
	// usually — a private host the SSRF check refuses without
	// flagDangerousAllowPrivate. Erroring is what stops that looking like a
	// successful crawl of nothing (LAB-2438). A resumed frontier has already seen the
	// seed, so a 0 there is expected rather than a rejection, which is why the failure
	// also requires an empty queue.
	if e.frontier.Push([]urlEntry{{URL: seedURL, Depth: 0}}) == 0 && e.frontier.Len() == 0 {
		// redactSeedURL strips userinfo before echoing the seed: this message lands in
		// shell history, CI logs and scrollback, so a credentialed URL pasted without
		// flagDangerousAllowPrivate must not leak in cleartext. A url.Parse error
		// returns the raw string so the message stays actionable.
		if resumed {
			return fmt.Errorf("resumed checkpoint has no pending pages and seed URL %s "+
				"was already covered; nothing to crawl", redactSeedURL(seedURL))
		}
		return fmt.Errorf("seed URL rejected by frontier (scope, SSRF, or parse): %s; "+
			"if crawling a private host (localhost, 127.0.0.1, RFC1918, link-local), "+
			"pass %s", redactSeedURL(seedURL), flagDangerousAllowPrivate)
	}

	// MaxPages counts pages, not requests — one SPA page fires dozens of XHR calls
	// (LAB-4678). Hitting it does NOT cancel ctx: in-flight pages finalize and emit
	// everything they captured rather than being cut off mid-page. Which pages land
	// inside the budget still varies run to run.
	//
	// MaxRequests is a second, independent budget over captured requests, distinct
	// from the crawl-breadth MaxPages. It is ADMISSION control, not a cap on what
	// reaches the target: crawlBudget reserves an estimated cost before a page starts
	// and reconciles afterwards, so a page that fires more than the estimate
	// overshoots. See that type.
	budget := newCrawlBudget(e.opts.MaxPages, e.opts.MaxRequests)

	var wg sync.WaitGroup
	for i := range e.opts.Concurrency {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			e.worker(ctx, id, onResult, budget)
		}(i)
	}

	wg.Wait()
	e.frontier.Close()

	// Capture resume state after the workers have stopped, on every exit path
	// (frontier exhausted, budget reached, or ctx canceled) — a truncated crawl
	// is exactly what the next run needs to continue from (LAB-4678 Phase 4).
	captureCheckpoint(e.frontier, e.opts.Resume, time.Now())

	return ctx.Err()
}

// Close disconnects only. BrowserManager owns the Chrome lifecycle.
func (e *rodEngine) Close() error {
	return e.browser.Close()
}

// initialRequestsPerPageEstimate is what crawlBudget assumes a page will cost before
// it has measured one. Deliberately pessimistic: over-estimating costs a little
// parallelism at the start of a crawl and is corrected within one page, while
// under-estimating spends budget that cannot be taken back, because the requests have
// already been sent to the target.
const initialRequestsPerPageEstimate = 8

// crawlBudget enforces the page and request budgets together.
//
// The request budget RESERVES an estimated cost before a page starts and reconciles
// against the actual count when it finishes. That is the difference between a bound
// and a running total: consulting the budget before a visit and updating it after lets
// every worker clear the check inside the same window, making the real bound
//
//	MaxRequests + (Concurrency x requests-per-page)
//
// Measured that way, --max-requests 10 at the default --concurrency 10 against pages
// firing 4 requests each emitted 44, and it could not bound below a single page's
// request count at all. An operator who needs a politeness control against a fragile
// target is not served by a number four times what they asked for.
//
// The estimate is the running mean of requests per completed page, so it adapts to the
// target rather than to a guess. As the budget fills the reservation naturally reduces
// concurrency: with 2 units left and an 8-unit estimate, no new page starts.
// Serializing near the limit is the correct trade for a bound that exists to protect
// the target.
//
// Residual overshoot is bounded by how far a page exceeds the current mean, summed
// over in-flight pages, rather than by concurrency. It cannot be zero without cutting
// a page mid-capture, which is the partial-page truncation MaxPages avoids.
//
// Nothing caps one page's captured-request count, so that overshoot has no per-page
// ceiling: with MaxRequests 10 and an 8-request estimate, a single admitted page that
// fires 10,000 requests emits all of them. So this bounds how many pages are ADMITTED
// against a request budget; it is not a guarantee about how many requests reach the
// target. MaxPages is the hard ceiling.
type crawlBudget struct {
	mu          sync.Mutex
	maxPages    int
	maxRequests int

	pageCount int // pages started (slots consumed)
	reqCount  int // requests emitted by completed pages
	reserved  int // estimated cost of pages currently in flight

	pagesMeasured   int // completed pages contributing to the mean
	requestsMeasure int // their total request count
}

func newCrawlBudget(maxPages, maxRequests int) *crawlBudget {
	return &crawlBudget{maxPages: maxPages, maxRequests: maxRequests}
}

// estimate returns the expected request cost of one page. Caller holds mu.
func (b *crawlBudget) estimate() int {
	if b.pagesMeasured == 0 {
		return initialRequestsPerPageEstimate
	}
	// Round up so the estimate never understates a fractional mean.
	est := (b.requestsMeasure + b.pagesMeasured - 1) / b.pagesMeasured
	if est < 1 {
		return 1
	}
	return est
}

// exhausted reports whether no further page may START. Caller holds mu.
func (b *crawlBudget) exhausted() bool {
	if b.maxPages > 0 && b.pageCount >= b.maxPages {
		return true
	}
	return b.maxRequests > 0 && b.reqCount+b.reserved >= b.maxRequests
}

// Reached is the check-only pre-Pop early-out. It consumes nothing, so a worker
// that is about to block on Pop can bail without holding a slot.
func (b *crawlBudget) Reached() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.exhausted()
}

// TryReserve consumes one page slot plus this page's estimated request cost, and
// reports whether the page may proceed. Compare and consume happen in one
// critical section, so concurrent workers cannot both pass a check that only one
// of them fits through.
//
// The returned reservation must be passed to Release when the page finishes.
func (b *crawlBudget) TryReserve() (reservation int, ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.exhausted() {
		return 0, false
	}
	est := b.estimate()
	// Admit the page only if its ESTIMATED cost also fits. Without this the
	// budget is only ever checked against already-spent requests, which is what
	// let every worker start a page against a nearly-full budget.
	if b.maxRequests > 0 && b.reqCount+b.reserved+est > b.maxRequests {
		// One exception: if nothing is in flight and nothing has been spent, allow
		// a single page through. Otherwise a budget smaller than one page's
		// estimated cost would crawl nothing at all and report an empty capture,
		// which reads as "the target has no API" rather than "the budget was too
		// small". This is the one case where the bound can be exceeded, it is
		// bounded by one page, and it only arises when the operator asked for less
		// than one page's worth.
		if b.reqCount > 0 || b.reserved > 0 {
			return 0, false
		}
	}
	b.pageCount++
	b.reserved += est
	return est, true
}

// Release reconciles a COMPLETED page: it returns the reservation, records the
// page's actual request count, and folds that count into the estimate for later
// pages.
func (b *crawlBudget) Release(reservation, actual int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.releaseLocked(reservation)
	b.reqCount += actual
	b.pagesMeasured++
	b.requestsMeasure += actual
}

// Cancel returns the reservation for a page that did NOT complete — a failed
// visit, or one abandoned on context cancellation.
//
// It is separate from Release rather than Release(reservation, 0) because a page
// that never finished is not evidence that pages cost zero requests. Feeding it
// to the mean would drag the estimate toward zero, and a too-low estimate is
// exactly what lets too many pages start against a nearly-full budget — the
// failure this type exists to prevent. The page slot itself is deliberately NOT
// returned, matching the pre-existing treatment of pageCount on abandoned pages.
func (b *crawlBudget) Cancel(reservation int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.releaseLocked(reservation)
}

// Abandon reconciles a page that was cut off PART-WAY through emitting: it
// returns the reservation and charges the requests already emitted against the
// budget, but does NOT fold them into the mean.
//
// Both halves matter and they pull in opposite directions. The emitted requests
// were really sent to the target, so they must count against a budget that exists
// to protect it — Cancel alone would forget them. But a partial count is not a
// sample of what a page costs, and feeding it to the mean is the exact drag
// Cancel's doc warns about; the worker's cancellation path used Release, so it
// did both correctly and incorrectly at once.
//
// TestCrawlBudget_AbandonChargesRequestsWithoutSkewingEstimate pins the pair.
func (b *crawlBudget) Abandon(reservation, emitted int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.releaseLocked(reservation)
	b.reqCount += emitted
}

// releaseLocked returns a reservation to the pool. Caller holds mu.
func (b *crawlBudget) releaseLocked(reservation int) {
	b.reserved -= reservation
	if b.reserved < 0 {
		b.reserved = 0
	}
}

// Pages reports how many page slots have been consumed. Test-facing.
func (b *crawlBudget) Pages() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.pageCount
}

// Requests reports how many requests completed pages have emitted. Test-facing.
func (b *crawlBudget) Requests() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.reqCount
}

// worker is the per-tab goroutine: pop, visit, capture, push discovered links.
func (e *rodEngine) worker(ctx context.Context, id int, onResult func(ObservedRequest), budget *crawlBudget) {
	for {
		if ctx.Err() != nil {
			return
		}

		// Check-only: nothing popped yet, so no slot to reserve. Pages other workers
		// are already visiting still finalize below.
		if budget.Reached() {
			return
		}

		entry, ok := e.frontier.Pop()
		if !ok {
			return // frontier exhausted
		}
		// MarkActive is NOT called: Pop already incremented the active counter
		// inside its own critical section, making dequeue+activate atomic. Only
		// MarkIdle() is needed after processing.

		// Another worker may have filled a budget while this one blocked in Pop, so
		// release the entry without visiting. Reserving before the visit rather than
		// counting after is what avoids overshooting by up to Concurrency pages.
		//
		// The cancellation paths further down requeue their entry as uncovered WITHOUT
		// releasing the slot this call consumed, so pageCount can transiently exceed
		// the number of pages actually covered. That is deliberate: releasing it would
		// add a lock acquisition on a terminating path for no observable gain, since
		// the count is local to Crawl, is never persisted into the checkpoint, and
		// every path that requeues has ctx already canceled, so a worker that reads
		// the inflated count exits on its own ctx check first.
		reservation, admitted := budget.TryReserve()
		if !admitted {
			// Return the entry to the queue: it was dequeued but never visited, so it
			// must survive into resume state instead of being dropped.
			e.frontier.Requeue(entry)
			e.frontier.MarkIdle()
			return
		}

		requests, links, err := e.visit(ctx, entry)
		if err != nil {
			if ctx.Err() != nil {
				// Canceled mid-visit: the page was not covered, so requeue it.
				budget.Cancel(reservation)
				e.frontier.Requeue(entry)
				e.frontier.MarkIdle()
				return
			}
			budget.Cancel(reservation)
			if e.opts.Stderr != nil {
				fmt.Fprintf(e.opts.Stderr, "worker %d: error visiting %s: %v\n", id, redactSeedURL(entry.URL), err) //nolint:errcheck // best-effort
			}
			// The visit failed for a plausibly transient reason (navigation error,
			// DNS blip, connection reset) with the crawl still healthy. Do not retry
			// it in this run, but keep it out of the persisted seen-set so a resumed
			// run can: seen is cumulative, so leaving it in would blacklist the page
			// permanently after one bad response.
			e.frontier.MarkFailed(entry)
			e.frontier.MarkIdle()
			continue
		}

		// Charged after the fact: e.visit captured the whole page before this loop, so
		// every request here has already been sent. Counting them is what separates
		// MaxRequests from MaxPages, but it also means this page's overshoot is
		// (emitted - reservation) and nothing at this point can prevent it.
		emitted := 0
		for _, req := range requests {
			if ctx.Err() != nil {
				// Canceled part-way through emitting this page's requests, so
				// its surface is incomplete. Requeue it for the next run. The
				// requests already emitted still count against the budget: they
				// were sent to the target, which is what the budget bounds.
				// Abandon, not Release: a partial count is not a sample of what a
				// page costs, and feeding it to the running mean is the drag
				// Cancel's doc comment warns about.
				budget.Abandon(reservation, emitted)
				e.frontier.Requeue(entry)
				e.frontier.MarkIdle()
				return
			}
			onResult(req)
			emitted++
		}
		budget.Release(reservation, emitted)

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
		// #nosec G104
		page.Close() //nolint:errcheck // best-effort close; page may already be closed
	}()

	// pageDeadline mirrors the per-page timeout as a wall-clock bound for the
	// completion-driven waits below, which poll local capture state and so never trip
	// the rod page timeout themselves. Every network-idle wait for this page, baseline
	// and per-click, shares it, so the page's total wait cannot scale with the number
	// of interactions.
	page = page.Context(ctx).Timeout(e.opts.PageTimeout)
	pageDeadline := time.Now().Add(e.opts.PageTimeout)

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

	e.learnSeedOrigin(page, target)

	// These waits overlap across workers rather than serializing.
	if err := page.WaitStable(e.opts.StableTimeout); err != nil {
		if ctx.Err() != nil {
			return capture.Results(), nil, nil
		}
	}

	// Wait for the network to go quiet instead of a fixed settle window, so late and
	// dynamic XHR/fetch calls (mutation and intersection observers, delayed data
	// loads) are captured rather than dropped (LAB-4678). Bounded by a floor, a quiet
	// period, a per-request timeout and the page ceiling; see waitForNetworkIdle.
	e.waitForNetworkIdle(ctx, capture, pageDeadline)

	// Optionally exercise the page (clicks, client-side route changes) to surface
	// endpoints that only fire on interaction, then snapshot everything captured,
	// baseline plus interaction-triggered (LAB-4678). Opt-in, off by default. Shares
	// the page deadline, so interaction cannot extend the page past its budget.
	navigated := false
	if e.opts.Interact {
		navigated = e.interactPage(ctx, page, capture, pageDeadline)
	}
	capturedResults := capture.Results()

	results, links := enrichFromPage(e.enrichTarget(page, navigated, target.URL), capturedResults, target.URL, e.opts.Stderr, e.opts.ScopeCheck)
	return results, links, nil
}

// learnSeedOrigin hands the SEED's post-redirect URL to the scope predicate.
// Redirects have been followed by the time the load event fires, so page.Info()
// reports the document the seed actually resolved to.
//
// Only the SEED itself may widen scope, and the widening is one-shot inside the
// predicate (see [seedScope]). It must run before the scope filter in enrichFromPage,
// or a cross-origin seed redirect discards every captured request and the crawl
// returns an empty capture with no diagnostic.
//
// The gate is IDENTITY with the seed, not Depth == 0. Depth is not a proxy for the
// seed once resume is in play: resumeFrontier runs BEFORE the seed is pushed and
// urlFrontier.Restore honors whatever Depth the checkpoint claims, so a restored
// entry carrying "Depth": 0 with a different URL is popped from the FIFO queue ahead
// of the seed and would become the page whose post-redirect origin is learned. A
// checkpoint is unauthenticated by design — its fingerprint is derived from
// non-secret crawl config — so a depth gate would let anyone able to write to
// checkpoint storage choose which page decided the scope widening (LAB-4678).
func (e *rodEngine) learnSeedOrigin(page *rod.Page, target urlEntry) {
	if e.opts.LearnEffectiveOrigin == nil || seenKey(target.URL) != e.seedKey {
		return
	}
	info, err := page.Info()
	if err != nil || info.URL == "" {
		return
	}
	e.opts.LearnEffectiveOrigin(info.URL)
}

// enrichTarget returns the page enrichFromPage should read the DOM from: the page
// itself normally, or nil when an interaction click navigated away and could not be
// undone.
//
// In that case the live DOM is a document this worker was never assigned:
// page.Info() reports the navigated-to URL, so reading it would extract that page's
// links and forms, resolve them against its base URL, and push them into the frontier
// without the intermediate page counting against --max-pages — while the synthetic
// form requests would still be tagged with this page's URL. A nil page limits
// enrichment to what was actually captured for the assigned page.
func (e *rodEngine) enrichTarget(page *rod.Page, navigated bool, pageURL string) *rod.Page {
	if !navigated {
		return page
	}
	if e.opts.Stderr != nil {
		// redactSeedURL, not the raw URL: for the depth-0 visit pageURL is the seed
		// exactly as the operator typed it, so `vespasian crawl --interact
		// https://admin:s3cret@target/` would write cleartext credentials to stderr,
		// which lands in CI job logs, shell scrollback, and any wrapper capturing the
		// capability's stderr.
		fmt.Fprintf(e.opts.Stderr, "interact: a click navigated away from %s and the page could not be restored; skipping DOM enrichment for it\n", redactSeedURL(pageURL)) //nolint:errcheck // best-effort
	}
	return nil
}

// waitForNetworkIdle blocks until the page's network goes quiet or a bound is hit
// (LAB-4678). It stops at the page deadline; or, once past the floor, when no
// requests are in flight and the network has been quiet for the quiet period; or when
// ctx is canceled.
//
// It deliberately returns nothing. capture.Results() takes the capture mutex and
// rebuilds every captured request, re-parsing each URL and re-deriving its query
// params, so returning a snapshot here would cost O(total captured bytes) per call —
// and interactPage calls this once per click plus once per returnToPage, up to 16
// times a page, across Concurrency tabs, scaled by attacker-controlled page content.
// visitPage takes the one snapshot that is actually read.
//
// deadline is the WHOLE PAGE's ceiling, shared by the baseline wait and every
// interaction wait, so a page cannot exceed its budget by calling this repeatedly.
// The floor still applies per call, which is deliberate: each click needs a minimum
// window for its requests to start, and the shared deadline caps the total regardless.
func (e *rodEngine) waitForNetworkIdle(ctx context.Context, capture *pageNetworkCapture, deadline time.Time) {
	start := time.Now()
	ticker := time.NewTicker(networkIdlePollInterval)
	defer ticker.Stop()
	for {
		now := time.Now()
		inFlight, sinceActivity := capture.networkState(e.opts.PerRequestTimeout, now)
		if networkIdleReached(inFlight, sinceActivity, now.Sub(start),
			e.opts.NetworkIdleFloor, e.opts.NetworkQuietPeriod, !now.Before(deadline)) {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// networkIdleReached is the pure stop decision for waitForNetworkIdle, split out so
// it is unit-testable without a browser. deadlineReached is passed in rather than
// derived so this stays a pure function of durations.
func networkIdleReached(inFlight int, sinceActivity, elapsed, floor, quiet time.Duration, deadlineReached bool) bool {
	if deadlineReached {
		return true
	}
	if elapsed < floor {
		return false
	}
	return inFlight == 0 && sinceActivity >= quiet
}

// isRetainedForStaticAnalysis reports whether an out-of-scope captured request must
// survive the scope filter anyway because a later stage reads its BODY rather than
// treating it as an endpoint.
//
// Today that is exactly one case: a JavaScript bundle. pkg/analyze/jsstatic runs over
// the capture after the crawl and it is the only input jsstatic has, so scope-
// filtering the capture also decides what static analysis can see. A Next.js or SPA
// bundle served from a separate asset host (assetPrefix, a CDN, a static. subdomain)
// is out of scope under the default same-origin policy, so without this the filter
// silently removes both SPA bundle extraction and App Router route recovery for every
// target deployed that way — the normal Next.js deployment, not an edge case — and
// the operator sees a smaller spec rather than an error.
//
// Retaining the bundle is not a scope escape. The browser had already fetched it as a
// subresource of an in-scope page, so no new request is issued, and nothing downstream
// treats it as an endpoint: pkg/classify's isStaticAssetRequest excludes on the same
// mediatype.IsJavaScript predicate this filter retains on, plus .js/.mjs/.cjs by
// extension, so it cannot reach the spec or the `servers` list;
// TestScopeExemptionCannotBecomeAnEndpoint pins that. What it can do
// is contribute the paths inside it, which jsstatic resolves against the PAGE url,
// keeping recovered endpoints on the in-scope origin. Third-party XHR/fetch to
// analytics and external APIs — the traffic the filter exists for — is JSON, not
// JavaScript, and is unaffected.
//
// It shares isJavaScriptContentType with the jsluice extraction path rather than
// applying its own test, so "what counts as a JS body" is decided in one place for
// both the stage that reads bodies and the filter that decides which bodies survive
// to be read.
func isRetainedForStaticAnalysis(r ObservedRequest) bool {
	if isJavaScriptContentType(strings.ToLower(mediatype.Base(r.Response.ContentType))) {
		return true
	}
	// Fall back to the URL extension when the content-type is missing or wrong,
	// which is common for CDN-served assets.
	u, err := url.Parse(r.URL)
	if err != nil {
		return false
	}
	p := strings.ToLower(u.Path)
	return strings.HasSuffix(p, ".js") || strings.HasSuffix(p, ".mjs")
}

// enrichFromPage does the DOM-reading half — links, jsluice, forms — then hands
// the pure combining logic to [mergeEnrichedLinks], which is unit tested. Errors
// are non-fatal; captured network results are always returned.
//
// pageURL is where the worker navigated, used for form PageURL tagging and as the
// resolution fallback when there is no <base href> and page.Info() errors.
func enrichFromPage(page *rod.Page, captured []ObservedRequest, pageURL string, stderr io.Writer, scopeFn func(string) bool) ([]ObservedRequest, []string) {
	// A nil page means the DOM must not (or cannot) be read. visitPage passes nil when
	// an interaction click navigated away, so the live DOM belongs to a document this
	// worker was never assigned; the merger-threading contract is also tested through
	// this path without standing up a real rod.Page. jsluice over the captured RESPONSE
	// bodies is a pure function of `captured` and stays valid either way, so it still
	// runs — only the DOM-sourced inputs (hrefs, inline scripts, forms) are dropped.
	if page == nil {
		captured, links := mergeEnrichedLinksFn(captured, nil, extractURLsFromResponses(captured), nil, nil, pageURL, pageURL, scopeFn)
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
			fmt.Fprintf(stderr, "link extraction failed for %s: %v\n", redactSeedURL(pageURL), err) //nolint:errcheck // best-effort
		}
		domLinks = nil
	}

	jsFromResponses := extractURLsFromResponses(captured)
	jsFromInline := extractURLsFromInlineScripts(page)

	// resolvedPageURL for no-action forms per the HTML spec, baseURL for explicit
	// action refs per browser behavior. A DOM error means no forms.
	forms, ferr := extractForms(page, resolvedPageURL, baseURL)
	if ferr != nil && stderr != nil {
		fmt.Fprintf(stderr, "form extraction failed for %s: %v\n", redactSeedURL(pageURL), ferr) //nolint:errcheck // best-effort
	}

	captured, links := mergeEnrichedLinksFn(captured, domLinks, jsFromResponses, jsFromInline, forms, resolvedPageURL, baseURL, scopeFn)
	return captured, links
}

// mergeEnrichedLinksFn is a var so tests can check scopeFn is threaded from
// e.opts.ScopeCheck through to mergeEnrichedLinks without a browser — that one-line
// call was otherwise integration-only coverage (LAB-2221). Production callers always
// see the real mergeEnrichedLinks.
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
	// Scope-filter passively captured network requests (LAB-4678 Phase 1). The
	// browser fires requests to third-party hosts (analytics, CDNs, external
	// APIs) that are out of the crawl scope; without this they flow into the
	// capture and surface as endpoints and OpenAPI `servers`. Frontier links and
	// form actions are already scope-checked (Push, and the form loop below);
	// this closes the corresponding gap on the passively-captured requests. A
	// nil scopeFn means no filtering, matching the form-action convention.
	if scopeFn != nil {
		inScope := make([]ObservedRequest, 0, len(captured))
		for _, r := range captured {
			if scopeFn(r.URL) || isRetainedForStaticAnalysis(r) {
				inScope = append(inScope, r)
			}
		}
		captured = inScope
	}

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
		// is same-origin, so keep those. Everything else is absolute per
		// resolveFormAction, which is what lets scopeFn judge it — a relative action
		// would fail parseHTTPURL and be dropped rather than admitted.
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
