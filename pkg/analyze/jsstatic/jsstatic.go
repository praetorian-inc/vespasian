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
)

// Source values that this package writes to crawl.ObservedRequest.Source.
// Aliased to the canonical crawl constants so the producer (here) and the
// consumer (pkg/generate/rest) share one definition.
const (
	SourceJS        = crawl.SourceStaticJS
	SourceSourcemap = crawl.SourceStaticJSSourcemap
)

// Default tuning bounds. Mirrored on Options when zero.
const (
	DefaultPerBundleTimeout      = 5 * time.Second
	DefaultMaxBundleSize         = 5 * 1024 * 1024 // 5 MB
	DefaultMaxEndpointsPerBundle = 500
	DefaultConcurrency           = 4
)

// Options configures Analyze. Zero values resolve to the Default* constants.
//
// HTTPClient is used only for sourcemap fetches (FetchSourcemaps must be true).
// When HTTPClient is nil and FetchSourcemaps is true, Analyze constructs a
// default *http.Client with a 10s timeout and pkg/probe.SSRFSafeDialContext
// (or a permissive dialer when AllowPrivate is true), mirroring the probe
// stage's posture.
type Options struct {
	// HTTPClient is the client used for sourcemap fetches.
	//
	// When set, Analyze wraps the caller's client in a shallow copy that overlays
	// both noFollowRedirects (so a .js.map URL cannot 302 to an attacker host and
	// bypass the sameHost pre-flight check) and an SSRF-safe DialContext matching
	// the posture of the default client (probe.SSRFSafeDialContext, or a
	// permissive dialer when AllowPrivate is true). The caller's original client
	// is not mutated. The caller may supply additional Transport settings (e.g.
	// mTLS, proxy, custom TLS config) via a custom Transport; those are replaced
	// by the safe transport overlay at fetch time.
	HTTPClient *http.Client

	// FetchSourcemaps enables remote .js.map fetching when a sourceMappingURL
	// comment is present and the .js.map response was not captured. When false,
	// only inlined sourceMappingURL data URIs and already-captured .js.map
	// bodies are used.
	FetchSourcemaps bool

	// AllowPrivate disables SSRF protection on sourcemap fetches. Mirrors the
	// --dangerous-allow-private flag on the parent command.
	AllowPrivate bool

	// PerBundleTimeout caps jsluice parsing time per bundle. Default: 5s.
	PerBundleTimeout time.Duration

	// MaxBundleSize caps the input size handed to jsluice. Bundles larger than
	// this are skipped and counted in Stats.Skipped. Default: 5 MB.
	MaxBundleSize int

	// MaxEndpointsPerBundle bounds the number of synthesized endpoints per
	// bundle (jsluice on minified loader bundles can yield thousands). Default: 500.
	MaxEndpointsPerBundle int

	// Concurrency is the size of the worker pool processing bundles. Default: 4.
	Concurrency int

	// Logger receives debug/warn events. Nil means slog.Default().
	Logger *slog.Logger
}

// withDefaults returns a copy of o with zero-or-negative numeric values replaced
// by their Default* constants. The `<= 0` guards (rather than `== 0`) close a
// gap CodeRabbit caught: a caller passing Concurrency: -1 would previously have
// kept the negative value, which spawns no workers and silently classifies all
// bundles as BundlesAbandonedOnCancel on a non-canceled run. Treating
// non-positive values as "use the default" matches what callers mean.
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
	// Logger is an interface, so == nil is the correct zero-value check here
	// (not <= 0 as used for the numeric fields above).
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	return o
}

// Result is the output of Analyze. Requests is the input slice with
// synthesized entries appended (so callers can hand it straight to
// classify.RunClassifiers).
type Result struct {
	Requests []crawl.ObservedRequest
	Stats    Stats
}

// Stats counts what the analyser saw and emitted. Useful for verbose output
// and for tests.
type Stats struct {
	BundlesAnalyzed     int // JS bodies passed to jsluice (post-filter, post-size-cap).
	BundlesSkipped      int // JS bodies skipped (oversized, empty, parse timeout).
	SourcemapsRecovered int // .js.map sources successfully decoded via sourcesContent.
	SourcemapFetchFails int // sourceMappingURL comments seen but fetch failed.
	EndpointsFound      int // endpoints emitted by ExtractFromBundle, before MaxEndpointsPerBundle cap and toRequests synthesis.
	EndpointsKept       int // endpoints that survived the cap and synthesis and made it into Requests.
	// SourcemapSourceTimeouts counts sourcemap source extractions that hit
	// PerBundleTimeout. Each increment corresponds to a "parse timeout"
	// logger.Warn record. Sourcemap sources skipped for OTHER reasons
	// (oversized, panic) get their own counters below.
	SourcemapSourceTimeouts int
	// SourcemapSourcesOversized counts sourcemap source entries skipped
	// because their sourcesContent string is larger than Options.MaxBundleSize.
	// Such sources are never handed to jsluice.
	SourcemapSourcesOversized int
	// SourcemapSourcePanics counts sourcemap source extractions where the
	// goroutine recovered a panic (typically from jsluice on malformed input).
	// Each increment corresponds to a "jsluice panic" logger.Error record.
	SourcemapSourcePanics int
	// BundlesAbandonedOnCancel counts bundles that were still in workCh when
	// Analyze observed ctx cancellation. They are not analyzed and not counted
	// in BundlesAnalyzed or BundlesSkipped. Always 0 on a clean run.
	BundlesAbandonedOnCancel int
	// AnalyzeOnePanics counts cases where a worker recovered a panic from
	// inside analyzeOne (i.e. NOT inside the per-extraction goroutine, but
	// elsewhere in the bundle pipeline). Always 0 on a clean run. Surfacing
	// this prevents a panic in toRequests / synthesize / accounting code from
	// silently understating bundle counts.
	AnalyzeOnePanics int
}

// ExtractedEndpoint is the analyser's intermediate representation. It is the
// pre-synthesis shape: tests assert on this directly without reaching into
// crawl.ObservedRequest construction.
type ExtractedEndpoint struct {
	Method       string   // canonical upper-case HTTP method (default GET).
	URL          string   // OpenAPI-friendly form, e.g., /api/users/{userId}.
	BodyFields   []string // top-level keys of the request body object literal.
	ContentType  string   // parsed from headers when present, else "".
	SourceTag    string   // SourceJS or SourceSourcemap.
	PageURL      string   // URL of the page that loaded this bundle.
	OriginBundle string   // URL of the JS bundle the endpoint was extracted from.
}

// perBundleResult holds results from analyzing a single JS bundle.
type perBundleResult struct {
	requests []crawl.ObservedRequest
	stats    Stats
}

// isJSContentType returns true when ct indicates a JavaScript body.
func isJSContentType(ct string) bool {
	lower := strings.ToLower(ct)
	return strings.Contains(lower, "javascript") ||
		strings.Contains(lower, "ecmascript") ||
		lower == "text/js" ||
		lower == "application/x-js"
}

// extractStatus is the outcome of one extractWithTimeout call. extractOK means
// jsluice returned (possibly with an error that was logged); extractTimeout
// means PerBundleTimeout fired before jsluice returned; extractPanic means the
// extraction goroutine panicked and was recovered.
type extractStatus int

const (
	extractOK extractStatus = iota
	extractTimeout
	extractPanic
)

// extractWithTimeout runs ExtractFromBundle in a goroutine with a per-source
// PerBundleTimeout, panic recovery, and a status signal so the caller can
// account for each outcome separately. The kind argument ("bundle" or
// "sourcemap-source") tags log records so an operator reading logs can tell
// which extraction phase produced an event.
//
// Goroutine-leak bound on extractTimeout: when PerBundleTimeout fires, the
// orchestrator returns and the goroutine keeps running until jsluice finishes
// (jsluice is not context-aware). The channel is buffered to capacity 1 so the
// late send never blocks and the goroutine exits when ExtractFromBundle returns.
// Worst-case in-flight goroutines per Analyze call: Concurrency × (1 + N),
// where N is the number of sourcesContent entries in a recovered sourcemap
// (each entry is dispatched to a separate extractWithTimeout call). In the
// common case N is small; for a pathological sourcemap with many sources,
// all N per-source goroutines may be in-flight simultaneously.
//
// Known, bounded limitation: if jsluice's underlying tree-sitter parser ever
// genuinely deadlocks on adversarial input, the goroutine would remain blocked
// indefinitely (for the lifetime of the Analyze call). The complete fix is
// pkg/probe-style process isolation; that is intentionally out of scope here
// because it requires a subprocess harness comparable in size to the entire
// jsstatic package.
func extractWithTimeout(ctx context.Context, source []byte, sourceURL, kind string, opts Options) (eps []ExtractedEndpoint, status extractStatus) {
	type result struct {
		eps      []ExtractedEndpoint
		panicked bool
	}
	// Capture hook values on the calling goroutine before spawning, so the
	// goroutine closure does not race against a test's defer that sets the
	// package-level hook variables to nil after the timeout fires.
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

// testInjectPanic and testInjectDelay are unexported test-only seams that
// live in this production file because the production code paths that consult
// them (safeAnalyzeOne and the extraction goroutine in extractWithTimeout)
// must compile in non-test binaries. Variables declared in *_test.go files
// are not visible to production code, so they cannot be used here.
//
// Both are nil by default (zero value for a func type), which means each
// call site is a single nil-check with no allocation and no side effects in
// production builds.
//
// Dependency-injecting these hooks through Options would expose test seams as
// part of the public API surface, which violates KISS for what amounts to two
// conditional nil-checks. The package-level variable pattern is the accepted
// Go idiom for this pattern and predates this PR.

// testInjectPanic is a panic-fault-injection point used by jsstatic's
// panic-recovery regression tests. The hook is consulted at exactly two
// call sites — the top of safeAnalyzeOne (loc="analyzeOne") and inside the
// extraction goroutine in extractWithTimeout (loc="bundle" or
// loc="sourcemap-source"). The hook exists because neither safeAnalyzeOne's
// body nor the goroutine's body has a naturally-panicking path that an
// external test can reliably trigger, and we want positive regression
// coverage of the recover/counter contracts.
var testInjectPanic func(loc string)

// testInjectDelay is a delay-fault-injection point used by jsstatic's
// per-source timeout regression tests. When non-nil, the hook is called
// inside the extraction goroutine in extractWithTimeout (after the panic
// hook) with the same loc string ("bundle" or "sourcemap-source"). A test
// can sleep for longer than PerBundleTimeout to force a deterministic
// timeout on a specific extraction kind without relying on large JS inputs
// or timing assumptions.
var testInjectDelay func(loc string)

// safeAnalyzeOne wraps analyzeOne with a recover() so that a panic outside the
// per-extraction goroutines (e.g. in toRequests, normalize, or the accounting
// logic) cannot leave the worker pool's resultCh without a value. Without this
// shield, a panic in analyzeOne would unwind through the worker goroutine and
// the orchestrator's workerProcessed count would understate the actual bundle
// count, masking the bug as a context-cancel partial result.
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

// analyzeOne analyzes a single captured JS bundle. It runs sourcemap recovery
// and extractor extraction, then synthesizes requests. The function is safe to
// call from goroutines; it has no shared mutable state.
func analyzeOne(ctx context.Context, req crawl.ObservedRequest, opts Options) perBundleResult {
	var result perBundleResult
	body := req.Response.Body

	// Sourcemap recovery (ctx propagated for remote fetch cancellation).
	smSources, smStats := recoverSourcemap(ctx, body, req.URL, opts)
	result.stats.SourcemapFetchFails += smStats.SourcemapFetchFails
	result.stats.SourcemapsRecovered += smStats.SourcemapsRecovered

	// Extract endpoints from the bundle body with per-bundle timeout.
	bundleEps, status := extractWithTimeout(ctx, body, req.URL, "bundle", opts)
	if status != extractOK {
		// Timeout OR panic: skip this bundle. The bundle pipeline does not
		// distinguish timeout vs panic at the BundlesSkipped granularity;
		// the logger.Warn / Error record carries the cause.
		result.stats.BundlesSkipped++
		return result
	}

	result.stats.BundlesAnalyzed++
	result.stats.EndpointsFound += len(bundleEps)
	// MaxEndpointsPerBundle caps the TOTAL endpoints we keep from one
	// bundle, counting both the bundle body and any recovered sourcemap
	// sources. The cap is applied first to the bundle body and then
	// re-evaluated as remaining-budget on each sourcemap source below.
	if len(bundleEps) > opts.MaxEndpointsPerBundle {
		bundleEps = bundleEps[:opts.MaxEndpointsPerBundle]
	}
	for i := range bundleEps {
		bundleEps[i].SourceTag = SourceJS
	}
	synth := toRequests(bundleEps, req.URL)
	result.requests = append(result.requests, synth...)
	result.stats.EndpointsKept += len(synth)

	// Process each recovered sourcemap source. Each uses the same timeout +
	// recover pattern; oversized sources are skipped without extraction.
	for _, src := range smSources {
		// Budget check: once the cap is hit, stop processing further
		// sourcemap sources for this bundle entirely. Without this, one
		// pathological sourcemap could push the bundle's total kept
		// endpoints far past MaxEndpointsPerBundle (CodeRabbit CR-1).
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
		if len(smEps) > remaining {
			smEps = smEps[:remaining]
		}
		for i := range smEps {
			smEps[i].SourceTag = SourceSourcemap
		}
		smSynth := toRequests(smEps, req.URL)
		result.requests = append(result.requests, smSynth...)
		result.stats.EndpointsKept += len(smSynth)
	}

	return result
}

// synthesizedLess is the deterministic ordering for synthesized static:js
// entries (LAB-4678 Phase 2): URL, then method, then source tag, then request
// body. Kept as a named helper so Analyze stays under the cyclomatic gate.
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
	return bytes.Compare(a.Body, b.Body) < 0
}

// Analyze runs static analysis on every JS body in captured. It returns a
// Result whose Requests slice is captured with synthesized [crawl.ObservedRequest]
// entries APPENDED at the end (so classify.Deduplicate keeps dynamic entries
// on ties).
//
// Analyze never modifies the input slice in place; it returns a new slice.
//
// The error return is reserved for catastrophic failures (e.g., context
// canceled). Per-bundle parse failures are logged and counted in Stats but
// do not abort the analysis.
//
// Length rationale: this function's body is the orchestration shape of the
// package — pre-loop classification, worker-pool fan-out, fan-in with Stats
// merge, output slice build, and post-run cancellation check. These phases
// are cohesive: each step reads the output of the previous one and the
// control flow is sequential. Splitting the merge or fan-out into helpers
// would force them to expose Stats, work channels, and the
// abandoned-on-cancel accounting as parameters, which would obscure rather
// than clarify the orchestration.
func Analyze(ctx context.Context, captured []crawl.ObservedRequest, opts Options) (Result, error) {
	// Check context before any work.
	if ctx.Err() != nil {
		return Result{Requests: captured}, ctx.Err()
	}

	opts = opts.withDefaults()

	// Single-pass: classify each captured request as a bundle to analyze,
	// an oversized bundle to skip (counted), or a non-JS entry to ignore.
	var bundles []crawl.ObservedRequest
	var stats Stats
	for _, req := range captured {
		ct := req.Response.ContentType
		body := req.Response.Body
		if !isJSContentType(ct) || len(body) == 0 {
			continue
		}
		if len(body) > opts.MaxBundleSize {
			// Oversized: skip and count in one pass.
			stats.BundlesSkipped++
			continue
		}
		bundles = append(bundles, req)
	}

	if len(bundles) == 0 {
		return Result{Requests: captured, Stats: stats}, nil
	}

	// Worker pool for parallel bundle analysis.
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

	// Wait for workers then close resultCh.
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	// Collect results. workerProcessed tracks bundles a worker actually picked
	// up (analyzed OR per-bundle-skipped). The difference vs len(bundles) on a
	// canceled run is the BundlesAbandonedOnCancel count below.
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
		// Each bundle a worker picks up contributes exactly 1 to exactly one
		// of: BundlesAnalyzed (successfully extracted), BundlesSkipped
		// (oversized at pre-loop, OR timeout/panic on the bundle-body
		// extractWithTimeout call), or AnalyzeOnePanics (panic outside
		// extractWithTimeout, e.g. in toRequests or accounting code).
		//
		// SourcemapSourcePanics are NOT included here because they are
		// sub-events that occur inside the sourcemap-source loop AFTER the
		// bundle has already been counted in BundlesAnalyzed (line
		// `result.stats.BundlesAnalyzed++` in analyzeOne runs before the
		// sourcemap loop). Including SourcemapSourcePanics would double-count
		// the containing bundle.
		workerProcessed += r.stats.BundlesAnalyzed + r.stats.BundlesSkipped + r.stats.AnalyzeOnePanics
	}
	if abandoned := len(bundles) - workerProcessed; abandoned > 0 {
		stats.BundlesAbandonedOnCancel = abandoned
	}

	// Sort the synthesized entries into a deterministic order (LAB-4678 Phase 2).
	// The worker pool fans results into resultCh in completion order, which is
	// non-deterministic across runs, so without this the appended static:js
	// entries would be ordered by worker scheduling. Downstream dedup/generate
	// are order-independent for the retained data, but ordering the synthesized
	// block here makes jsstatic's own output a deterministic function of the
	// capture rather than relying on those downstream sorts. Key: URL, method,
	// source tag, then request body.
	sort.SliceStable(synthesized, func(i, j int) bool {
		return synthesizedLess(synthesized[i], synthesized[j])
	})

	// Build result: original captured first, synthesized appended after.
	out := make([]crawl.ObservedRequest, len(captured), len(captured)+len(synthesized))
	copy(out, captured)
	out = append(out, synthesized...)

	// Check whether context was canceled during the run. A mid-run cancel
	// returns the partial result alongside the error so callers can decide
	// whether to use partial output.
	if err := ctx.Err(); err != nil {
		return Result{Requests: out, Stats: stats}, err
	}

	return Result{Requests: out, Stats: stats}, nil
}
