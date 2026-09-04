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

package jsstatic

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/praetorian-inc/vespasian/pkg/crawl"
	"github.com/praetorian-inc/vespasian/pkg/httpx"
)

// Aliased to the crawl constants so producer and consumer share one definition.
const (
	SourceJS        = crawl.SourceStaticJS
	SourceSourcemap = crawl.SourceStaticJSSourcemap
	SourceJSConcat  = crawl.SourceStaticJSConcat
)

// Applied by withDefaults when the Options field is non-positive.
const (
	DefaultPerBundleTimeout      = 5 * time.Second
	DefaultMaxBundleSize         = 5 * 1024 * 1024 // 5 MB
	DefaultMaxEndpointsPerBundle = 500
	DefaultConcurrency           = 4
)

// concatMinReserve is the number of MaxEndpointsPerBundle slots capBundleEndpoints
// guarantees to concat/service-prefix reconstructions when the cap binds, so
// AST-recovered endpoints cannot starve them entirely (LAB-4992).
//
// A small fixed reserve rather than a proportional share: concat candidates are
// speculative and never probed, so they must not displace directly AST-recovered
// literals one-for-one. capBundleEndpoints additionally clamps the reserve to
// budget/2 so it cannot invert and starve AST on small budgets, and concat still
// reclaims any budget AST leaves unused — the reserve is a floor, not a quota.
const concatMinReserve = 16

// Options configures Analyze; zero values resolve to the Default* constants.
//
// With HTTPClient nil and FetchSourcemaps true, Analyze builds a default client with
// a 10s timeout and probe.SSRFSafeDialContext (a permissive dialer when AllowPrivate),
// mirroring the probe stage's posture.
type Options struct {
	// Sourcemap fetches only. Analyze wraps a caller-supplied client in a shallow
	// copy overlaying httpx.NoFollowRedirects — a .js.map URL must not 302 past the
	// sameHost pre-flight — and an SSRF-safe DialContext. The caller's client is
	// never mutated, and a custom Transport (mTLS, proxy, TLS config) is replaced by
	// that overlay at fetch time.
	HTTPClient *http.Client

	// Fetch .js.map remotely when the sourceMappingURL was not captured. False
	// leaves only inline data URIs and already-captured bodies.
	FetchSourcemaps bool

	// Disables SSRF protection on sourcemap fetches. Mirrors
	// --dangerous-allow-private.
	AllowPrivate bool

	// Proxy routes sourcemap fetches through an intercepting proxy when set, and is
	// honored ONLY when HTTPClient is nil (the production path — pipeline never sets
	// HTTPClient): an injected client has its Transport overwritten with
	// ssrfSafeTransport (see recoverSourcemap), which would clobber a proxied dialer,
	// so that case warns that fetches will BYPASS the proxy. The proxied client
	// installs no dial-time SSRF pin, since it dials the proxy rather than the target;
	// the same-host URL check is unchanged.
	Proxy httpx.ProxyConfig

	PerBundleTimeout time.Duration // per input, not per Analyze call
	MaxBundleSize    int           // larger bundles are skipped and counted

	// jsluice on a minified loader bundle can yield thousands.
	MaxEndpointsPerBundle int

	Concurrency int
	Logger      *slog.Logger // nil -> slog.Default()
}

// withDefaults tests `<= 0`, not `== 0`: a negative Concurrency spawns no workers,
// which would report every bundle as abandoned on a run that was never canceled.
func (o Options) withDefaults() Options {
	if o.PerBundleTimeout <= 0 {
		o.PerBundleTimeout = DefaultPerBundleTimeout
	}
	if o.MaxBundleSize <= 0 {
		o.MaxBundleSize = DefaultMaxBundleSize
	}
	if o.MaxEndpointsPerBundle <= 0 {
		o.MaxEndpointsPerBundle = DefaultMaxEndpointsPerBundle
	}
	if o.Concurrency <= 0 {
		o.Concurrency = DefaultConcurrency
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	return o
}

// Result carries the input Requests with synthesized entries appended, ready for
// classify.RunClassifiers.
type Result struct {
	Requests []crawl.ObservedRequest
	Stats    Stats
}

// Stats counts what the analyser saw and emitted, for verbose output and tests.
type Stats struct {
	BundlesAnalyzed     int // handed to jsluice, post-filter and size-cap
	BundlesSkipped      int // oversized, or a parse timeout or panic; NOT empty bodies
	SourcemapsRecovered int // decoded via sourcesContent
	SourcemapFetchFails int // sourceMappingURL seen, fetch failed
	EndpointsFound      int // before the cap and toRequests synthesis
	EndpointsKept       int // survived both, in Requests

	SourcemapSourceTimeouts   int // one per "parse timeout" warn with kind=sourcemap-source
	SourcemapSourcesOversized int // over MaxBundleSize, never reach jsluice
	SourcemapSourcePanics     int // one per "jsluice panic" error with kind=sourcemap-source

	// Bundles that produced no result before cancellation — still queued, or
	// dequeued by a worker that then saw ctx.Done(). 0 on a clean run.
	BundlesAbandonedOnCancel int

	// Panic inside analyzeOne but OUTSIDE the extraction goroutine. 0 on a clean
	// run. Surfaced so a panic in toRequests or the accounting cannot silently
	// understate bundle counts.
	AnalyzeOnePanics int
}

// ExtractedEndpoint is the pre-synthesis shape tests assert on directly.
type ExtractedEndpoint struct {
	Method       string   // canonical upper-case HTTP method (default GET).
	URL          string   // OpenAPI-friendly form, e.g., /api/users/{userId}.
	BodyFields   []string // top-level keys of the request body object literal.
	ContentType  string   // parsed from headers when present, else "".
	SourceTag    string   // SourceJS or SourceSourcemap.
	PageURL      string   // URL of the page that loaded this bundle.
	OriginBundle string   // URL of the JS bundle the endpoint was extracted from.
}

type perBundleResult struct {
	requests []crawl.ObservedRequest
	stats    Stats
}

func isJSContentType(ct string) bool {
	lower := strings.ToLower(ct)
	return strings.Contains(lower, "javascript") ||
		strings.Contains(lower, "ecmascript") ||
		lower == "text/js" ||
		lower == "application/x-js"
}

// extractStatus: OK means jsluice returned, possibly having logged an error.
type extractStatus int

const (
	extractOK extractStatus = iota
	extractTimeout
	extractPanic
)

// extractWithTimeout runs ExtractFromBundle in a goroutine under
// PerBundleTimeout with panic recovery. kind ("bundle" or "sourcemap-source")
// tags log records so an operator can tell the phases apart.
//
// On timeout the orchestrator returns but the goroutine runs until jsluice
// finishes, since jsluice is not context-aware. The channel is buffered to
// capacity 1 so that late send cannot block.
//
// Concurrency does NOT bound the leak. It bounds how many extractions are awaited
// at once; a worker that times out moves on to the next bundle, so leaked
// goroutines accumulate one per timed-out extraction over the whole run — worst
// case one for every bundle plus every sourcemap source in the input.
//
// If tree-sitter ever genuinely deadlocks, the goroutine blocks for the lifetime
// of the call. Only pkg/probe-style process isolation fixes that.
func extractWithTimeout(ctx context.Context, source []byte, sourceURL, kind string, opts Options) (eps []ExtractedEndpoint, status extractStatus) {
	type result struct {
		eps      []ExtractedEndpoint
		panicked bool
	}
	// Read on the calling goroutine: after a timeout, a test's defer may nil these
	// while the closure is still running.
	panicHook := testInjectPanic
	delayHook := testInjectDelay
	ch := make(chan result, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				opts.Logger.Error("jsluice panic", "kind", kind, "source", sourceURL, "panic", r)
				ch <- result{nil, true}
			}
		}()
		if panicHook != nil {
			panicHook(kind)
		}
		if delayHook != nil {
			delayHook(kind)
		}
		eps, err := ExtractFromBundle(source, sourceURL)
		if err != nil {
			opts.Logger.Warn("extract error", "kind", kind, "source", sourceURL, "err", err)
		}
		ch <- result{eps, false}
	}()
	timeoutCtx, cancel := context.WithTimeout(ctx, opts.PerBundleTimeout)
	defer cancel()
	select {
	case r := <-ch:
		if r.panicked {
			return nil, extractPanic
		}
		return r.eps, extractOK
	case <-timeoutCtx.Done():
		opts.Logger.Warn("parse timeout", "kind", kind, "source", sourceURL)
		return nil, extractTimeout
	}
}

// These two test seams live in a production file because the paths that consult
// them (safeAnalyzeOne, and the extraction goroutine in extractWithTimeout)
// compile into non-test binaries, where a _test.go variable is not visible. Both
// are nil in production, so each site costs one nil check. They are package-level
// variables rather than Options fields to keep fault injection out of the API
// callers configure.

// testInjectPanic fires at exactly two sites: the top of safeAnalyzeOne
// (loc="analyzeOne") and inside the extraction goroutine (loc="bundle" or
// "sourcemap-source"). Neither has a naturally-panicking path a test can trigger
// from outside, so the recover/counter contracts need an injected fault. All three
// loc values are driven today: TestSafeAnalyzeOne_PanicRecovery ("analyzeOne"),
// TestAnalyze_BundlePanic_IncrementsBundlesSkipped and
// TestAnalyze_NextRouteSurvivesFailedBodyExtraction ("bundle"), and
// TestAnalyze_SourcemapSourcePanic_IncrementsPanicCounter ("sourcemap-source").
var testInjectPanic func(loc string)

// testInjectDelay fires in the extraction goroutine after the panic hook, so
// TestAnalyze_SourcemapSourcePerSourceTimeout can force a deterministic per-kind
// timeout without large inputs or timing assumptions.
var testInjectDelay func(loc string)

// safeAnalyzeOne recovers panics from outside the extraction goroutines, which
// would otherwise leave resultCh without a value: workerProcessed would understate
// the bundle count and the bug would look like a context-cancel partial result.
func safeAnalyzeOne(ctx context.Context, req crawl.ObservedRequest, opts Options) (result perBundleResult) {
	defer func() {
		if r := recover(); r != nil {
			opts.Logger.Error("analyzeOne panic", "bundle", req.URL, "panic", r)
			result = perBundleResult{stats: Stats{AnalyzeOnePanics: 1}}
		}
	}()
	if testInjectPanic != nil {
		testInjectPanic("analyzeOne")
	}
	return analyzeOne(ctx, req, opts)
}

// capBundleEndpoints truncates eps to budget entries WITHOUT letting AST-recovered
// endpoints starve concat/service-prefix candidates (LAB-4992). ExtractFromBundle
// appends concat reconstructions (SourceJSConcat) after all AST-recovered endpoints,
// so a naive `eps[:budget]` prefix truncation drops every concat candidate whenever
// the AST portion alone reaches budget.
//
// Instead concat gets a small floor, AST takes whatever budget remains after it, and
// concat then reclaims any budget AST did not use. The total kept is therefore always
// min(len(ast)+len(concat), budget), never under-filled the way a hard budget/2 split
// on concat alone leaves it when AST is small.
//
// The floor is deliberately small (concatMinReserve, additionally capped at budget/2
// so it can never invert and starve AST — the split is pinned per budget by
// TestCapBundleEndpoints_SmallBudgetDoesNotStarveAST) rather than a proportional
// reservation, which would tax AST even when concat is abundant and low-value. Concat
// is abundant in practice: ExtractStaticConcatPaths composes two independently capped
// producers (up to 512 candidates from one bundle) and servicePrefixPlusHeadPattern
// matches any short quoted slash-terminated literal followed by `+`, which is dense in
// minified output. Trading a directly AST-recovered literal for an unprobed
// sentinel-substituted guess 1:1 is the wrong direction, so concat gets a guaranteed
// toehold, not parity.
func capBundleEndpoints(eps []ExtractedEndpoint, budget int) []ExtractedEndpoint {
	var ast, concat []ExtractedEndpoint
	for _, ep := range eps {
		if ep.SourceTag == SourceJSConcat {
			concat = append(concat, ep)
		} else {
			ast = append(ast, ep)
		}
	}

	// A floor, kept well below budget so abundant concat cannot displace
	// high-fidelity AST literals. The budget/2 clamp keeps the floor from exceeding
	// the budget on small budgets, which would zero out AST.
	concatFloor := len(concat)
	if concatFloor > concatMinReserve {
		concatFloor = concatMinReserve
	}
	if concatFloor > budget/2 {
		concatFloor = budget / 2
	}

	// AST gets everything but the floor...
	astBudget := budget - concatFloor
	if len(ast) > astBudget {
		ast = ast[:astBudget]
	}

	// ...and concat reclaims whatever AST did not use, so the cap stays fully
	// utilized when AST is scarce.
	concatBudget := budget - len(ast)
	if len(concat) > concatBudget {
		concat = concat[:concatBudget]
	}

	return append(ast, concat...)
}

// analyzeOne handles one bundle. No shared mutable state, so it is
// goroutine-safe.
func analyzeOne(ctx context.Context, req crawl.ObservedRequest, opts Options) perBundleResult {
	var result perBundleResult
	body := req.Response.Body

	// Next.js App Router route recovery (LAB-4678). Derived from the bundle URL, not
	// its body, so it runs before body extraction and still applies to bundles whose
	// parse times out or panics below. See nextroute.go for why the URL carries the
	// route.
	if ep := extractNextRoute(req.URL, req.PageURL); ep != nil {
		result.stats.EndpointsFound++
		synth := toRequests([]ExtractedEndpoint{*ep}, req.URL)
		result.requests = append(result.requests, synth...)
		result.stats.EndpointsKept += len(synth)
	}

	// ctx carries through for remote-fetch cancellation.
	smSources, smStats := recoverSourcemap(ctx, body, req.URL, opts)
	result.stats.SourcemapFetchFails += smStats.SourcemapFetchFails
	result.stats.SourcemapsRecovered += smStats.SourcemapsRecovered

	bundleEps, status := extractWithTimeout(ctx, body, req.URL, "bundle", opts)
	if status != extractOK {
		// BundlesSkipped does not distinguish timeout from panic; the log record
		// carries the cause.
		result.stats.BundlesSkipped++
		return result
	}

	result.stats.BundlesAnalyzed++
	result.stats.EndpointsFound += len(bundleEps)
	// The cap is TOTAL across the body and every sourcemap source, re-evaluated as
	// remaining budget below. capBundleEndpoints rather than a prefix truncation
	// because ExtractFromBundle appends concat reconstructions after every
	// AST-recovered endpoint, so a prefix cut drops all of them once AST alone reaches
	// the cap — which is the acceptance criterion that offline generate surfaces
	// concat endpoints (LAB-4992). The body's budget is the cap MINUS what the Next.js
	// chunk-URL recovery above already kept; using the full cap let a Next.js chunk
	// bundle keep cap+1.
	bodyBudget := opts.MaxEndpointsPerBundle - result.stats.EndpointsKept
	if bodyBudget < 0 {
		bodyBudget = 0
	}
	if len(bundleEps) > bodyBudget {
		bundleEps = capBundleEndpoints(bundleEps, bodyBudget)
	}
	for i := range bundleEps {
		// Preserve the distinct concat reconstruction tag; force everything else
		// from the bundle body to the plain JS-bundle source.
		if bundleEps[i].SourceTag != SourceJSConcat {
			bundleEps[i].SourceTag = SourceJS
		}
	}
	synth := toRequests(bundleEps, req.URL)
	result.requests = append(result.requests, synth...)
	result.stats.EndpointsKept += len(synth)

	for _, src := range smSources {
		// Stop entirely once the cap is hit: one pathological sourcemap would
		// otherwise push the total far past MaxEndpointsPerBundle.
		remaining := opts.MaxEndpointsPerBundle - result.stats.EndpointsKept
		if remaining <= 0 {
			break
		}
		if len(src) > opts.MaxBundleSize {
			result.stats.SourcemapSourcesOversized++
			opts.Logger.Warn("sourcemap source oversized, skipping", "bundle", req.URL, "size", len(src))
			continue
		}
		smEps, status := extractWithTimeout(ctx, []byte(src), req.URL, "sourcemap-source", opts)
		switch status {
		case extractTimeout:
			result.stats.SourcemapSourceTimeouts++
			continue
		case extractPanic:
			result.stats.SourcemapSourcePanics++
			continue
		}
		result.stats.EndpointsFound += len(smEps)
		// QUAL-011 (LAB-4992): route this through capBundleEndpoints, exactly
		// like the bundle-body truncation above, rather than taking a bare
		// prefix slice. ExtractFromBundle runs the same step-5 concat
		// extraction on each sourcemap source and appends those
		// reconstructions AFTER all AST-recovered endpoints, so a prefix slice
		// silently drops every concat candidate from any sourcemap source
		// whose AST endpoints alone consume the remaining budget — the precise
		// failure mode capBundleEndpoints exists to prevent.
		if len(smEps) > remaining {
			smEps = capBundleEndpoints(smEps, remaining)
		}
		for i := range smEps {
			// Preserve the distinct concat reconstruction tag; force everything
			// else recovered from the sourcemap to the sourcemap source.
			if smEps[i].SourceTag != SourceJSConcat {
				smEps[i].SourceTag = SourceSourcemap
			}
		}
		smSynth := toRequests(smEps, req.URL)
		result.requests = append(result.requests, smSynth...)
		result.stats.EndpointsKept += len(smSynth)
	}

	return result
}

// synthesizedLess is the deterministic ordering for synthesized static:js entries
// (LAB-4678): URL, then method, then source tag, then request body, then page URL,
// then headers. Kept as a named helper so Analyze stays under the cyclomatic gate.
//
// The keys are exactly the fields [toRequests] populates, which is what makes this a
// total order over synthesized entries: any two distinct entries differ in at least
// one of them. The final tiebreakers are load-bearing — entries equal on the earlier
// keys compare equal, and sort.SliceStable then preserves their worker-completion
// order, which is the nondeterminism this sort exists to remove. QueryParams is not a
// usable key here: toRequests never sets it.
func synthesizedLess(a, b crawl.ObservedRequest) bool {
	if a.URL != b.URL {
		return a.URL < b.URL
	}
	if a.Method != b.Method {
		return a.Method < b.Method
	}
	if a.Source != b.Source {
		return a.Source < b.Source
	}
	if c := bytes.Compare(a.Body, b.Body); c != 0 {
		return c < 0
	}
	if a.PageURL != b.PageURL {
		return a.PageURL < b.PageURL
	}
	return headerKey(a.Headers) < headerKey(b.Headers)
}

// headerKey renders a header map as a canonical, comparable string: entries sorted
// by name, joined as "name:value". Used only as a sort tiebreaker, so it needs to
// be stable and total, not parseable.
func headerKey(h map[string]string) string {
	if len(h) == 0 {
		return ""
	}
	names := make([]string, 0, len(h))
	for k := range h {
		names = append(names, k)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, k := range names {
		b.WriteString(k)
		b.WriteByte(':')
		b.WriteString(h[k])
		b.WriteByte('\n')
	}
	return b.String()
}

// Analyze runs static analysis over every JS body in captured. On the normal path
// Result.Requests is a new slice with synthesized entries APPENDED — the order
// matters, because classify.Deduplicate keeps dynamic entries on ties. The input is
// never mutated; when there is nothing to analyze it returns captured itself.
//
// The error is ctx.Err() on cancellation, with the partial result alongside it.
// Per-bundle parse failures are logged and counted, not returned.
func Analyze(ctx context.Context, captured []crawl.ObservedRequest, opts Options) (Result, error) {
	if ctx.Err() != nil {
		return Result{Requests: captured}, ctx.Err()
	}

	opts = opts.withDefaults()

	var bundles []crawl.ObservedRequest
	var stats Stats
	for _, req := range captured {
		ct := req.Response.ContentType
		body := req.Response.Body
		if !isJSContentType(ct) || len(body) == 0 {
			continue
		}
		if len(body) > opts.MaxBundleSize {
			stats.BundlesSkipped++
			continue
		}
		bundles = append(bundles, req)
	}

	if len(bundles) == 0 {
		return Result{Requests: captured, Stats: stats}, nil
	}

	workCh := make(chan crawl.ObservedRequest, len(bundles))
	resultCh := make(chan perBundleResult, len(bundles))

	var wg sync.WaitGroup
	for i := 0; i < opts.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for req := range workCh {
				select {
				case <-ctx.Done():
					return
				default:
				}
				resultCh <- safeAnalyzeOne(ctx, req, opts)
			}
		}()
	}

	for _, req := range bundles {
		workCh <- req
	}
	close(workCh)

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	// workerProcessed counts bundles that produced a result; the shortfall against
	// len(bundles) is BundlesAbandonedOnCancel, which therefore also covers a
	// bundle a worker dequeued and abandoned on ctx.Done().
	var synthesized []crawl.ObservedRequest
	workerProcessed := 0
	for r := range resultCh {
		stats.BundlesAnalyzed += r.stats.BundlesAnalyzed
		stats.BundlesSkipped += r.stats.BundlesSkipped
		stats.SourcemapsRecovered += r.stats.SourcemapsRecovered
		stats.SourcemapFetchFails += r.stats.SourcemapFetchFails
		stats.SourcemapSourceTimeouts += r.stats.SourcemapSourceTimeouts
		stats.SourcemapSourcesOversized += r.stats.SourcemapSourcesOversized
		stats.SourcemapSourcePanics += r.stats.SourcemapSourcePanics
		stats.AnalyzeOnePanics += r.stats.AnalyzeOnePanics
		stats.EndpointsFound += r.stats.EndpointsFound
		stats.EndpointsKept += r.stats.EndpointsKept
		synthesized = append(synthesized, r.requests...)
		// Each bundle contributes 1 to exactly one of these three.
		// SourcemapSourcePanics is deliberately NOT among them: those happen inside
		// the sourcemap loop, after BundlesAnalyzed++ already counted the bundle,
		// so adding them double-counts it.
		workerProcessed += r.stats.BundlesAnalyzed + r.stats.BundlesSkipped + r.stats.AnalyzeOnePanics
	}
	if abandoned := len(bundles) - workerProcessed; abandoned > 0 {
		stats.BundlesAbandonedOnCancel = abandoned
	}

	// The worker pool fans results into resultCh in completion order, which is
	// nondeterministic across runs, so sort the synthesized block here (LAB-4678).
	// Downstream dedup/generate are order-independent for the retained data; sorting
	// here makes jsstatic's own output a deterministic function of the capture rather
	// than depending on those downstream sorts.
	sort.SliceStable(synthesized, func(i, j int) bool {
		return synthesizedLess(synthesized[i], synthesized[j])
	})

	out := make([]crawl.ObservedRequest, len(captured), len(captured)+len(synthesized))
	copy(out, captured)
	out = append(out, synthesized...)

	// A mid-run cancel returns the partial result alongside the error.
	if err := ctx.Err(); err != nil {
		return Result{Requests: out, Stats: stats}, err
	}

	return Result{Requests: out, Stats: stats}, nil
}
