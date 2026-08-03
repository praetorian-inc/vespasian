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
	"context"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/praetorian-inc/vespasian/pkg/crawl"
)

// Aliased to the crawl constants so producer and consumer share one definition.
const (
	SourceJS        = crawl.SourceStaticJS
	SourceSourcemap = crawl.SourceStaticJSSourcemap
)

// Applied by withDefaults when the Options field is non-positive.
const (
	DefaultPerBundleTimeout      = 5 * time.Second
	DefaultMaxBundleSize         = 5 * 1024 * 1024 // 5 MB
	DefaultMaxEndpointsPerBundle = 500
	DefaultConcurrency           = 4
)

// Options configures Analyze; zero values resolve to the Default* constants.
type Options struct {
	// Sourcemap fetches only. Analyze wraps a caller-supplied client in a shallow
	// copy overlaying noFollowRedirects — a .js.map URL must not 302 past the
	// sameHost pre-flight — and an SSRF-safe DialContext. The caller's client is
	// never mutated, and a custom Transport is replaced by that overlay.
	HTTPClient *http.Client

	// Fetch .js.map remotely when the sourceMappingURL was not captured. False
	// leaves only inline data URIs and already-captured bodies.
	FetchSourcemaps bool

	// Disables SSRF protection on sourcemap fetches. Mirrors
	// --dangerous-allow-private.
	AllowPrivate bool

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
	BundlesSkipped      int // oversized, or a parse timeout; NOT empty bodies
	SourcemapsRecovered int // decoded via sourcesContent
	SourcemapFetchFails int // sourceMappingURL seen, fetch failed
	EndpointsFound      int // before the cap and toRequests synthesis
	EndpointsKept       int // survived both, in Requests

	SourcemapSourceTimeouts   int // one per "parse timeout" warn
	SourcemapSourcesOversized int // over MaxBundleSize, never reach jsluice
	SourcemapSourcePanics     int // one per "jsluice panic" error

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
// are nil in production, so each site costs one nil check.

// testInjectPanic fires at exactly two sites: the top of safeAnalyzeOne
// (loc="analyzeOne") and inside the extraction goroutine (loc="bundle" or
// "sourcemap-source"). Neither has a naturally-panicking path a test can trigger
// from outside, so the recover/counter contracts need an injected fault.
var testInjectPanic func(loc string)

// testInjectDelay fires in the extraction goroutine after the panic hook, so a
// test can force a deterministic per-kind timeout without large inputs or timing
// assumptions.
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

// analyzeOne handles one bundle. No shared mutable state, so it is
// goroutine-safe.
func analyzeOne(ctx context.Context, req crawl.ObservedRequest, opts Options) perBundleResult {
	var result perBundleResult
	body := req.Response.Body

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
	// remaining budget below.
	if len(bundleEps) > opts.MaxEndpointsPerBundle {
		bundleEps = bundleEps[:opts.MaxEndpointsPerBundle]
	}
	for i := range bundleEps {
		bundleEps[i].SourceTag = SourceJS
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

// Analyze runs static analysis over every JS body in captured. On the normal path
// it returns a new slice with synthesized entries APPENDED — the order matters,
// because classify.Deduplicate keeps dynamic entries on ties. The input is never
// mutated; when there is nothing to analyze it returns captured itself.
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

	out := make([]crawl.ObservedRequest, len(captured), len(captured)+len(synthesized))
	copy(out, captured)
	out = append(out, synthesized...)

	// A mid-run cancel returns the partial result alongside the error.
	if err := ctx.Err(); err != nil {
		return Result{Requests: out, Stats: stats}, err
	}

	return Result{Requests: out, Stats: stats}, nil
}
