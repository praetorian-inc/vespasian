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

// Source values that this package writes to crawl.ObservedRequest.Source.
const (
	SourceJS        = "static:js"
	SourceSourcemap = "static:js-sourcemap"
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
	// When set, the caller is responsible for configuring an SSRF-safe Transport
	// (typically by using probe.SSRFSafeDialContext on the DialContext) and any
	// proxy/TLS/mTLS settings. Analyze overlays a noFollowRedirects CheckRedirect
	// on a shallow copy of the supplied client at fetch time so a same-host
	// .js.map URL cannot 302 to a different host and bypass the sameHost
	// pre-flight check; this overlay does not mutate the caller's client.
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
	// SourcemapSourceTimeouts counts individual sourcemap source extractions
	// that were skipped. Increments on per-source PerBundleTimeout, on a
	// goroutine panic recovered during extraction, AND when an individual
	// sourcesContent string exceeds MaxBundleSize (an oversize is treated as
	// "this source would have to be skipped anyway"). Despite the name,
	// "timeouts" here means "skipped extractions" — readers that need to
	// distinguish causes should inspect the logger output, which records the
	// reason for every increment.
	SourcemapSourceTimeouts int
	// BundlesAbandonedOnCancel counts bundles that were still in workCh when
	// Analyze observed ctx cancellation. They are not analyzed and not counted
	// in BundlesAnalyzed or BundlesSkipped. Always 0 on a clean run.
	BundlesAbandonedOnCancel int
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

// extractWithTimeout runs ExtractFromBundle in a goroutine with a per-source
// PerBundleTimeout and panic recovery. Returns (endpoints, timedOut). On a
// recovered panic the goroutine logs and treats the result as empty. The kind
// argument ("bundle" or "sourcemap-source") tags log records so an operator
// reading logs can tell which extraction phase produced an event.
func extractWithTimeout(ctx context.Context, source []byte, sourceURL, kind string, opts Options) ([]ExtractedEndpoint, bool) {
	ch := make(chan []ExtractedEndpoint, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				opts.Logger.Error("jsluice panic", "kind", kind, "source", sourceURL, "panic", r)
				ch <- nil
			}
		}()
		eps, err := ExtractFromBundle(source, sourceURL)
		if err != nil {
			opts.Logger.Warn("extract error", "kind", kind, "source", sourceURL, "err", err)
		}
		ch <- eps
	}()
	timeoutCtx, cancel := context.WithTimeout(ctx, opts.PerBundleTimeout)
	defer cancel()
	select {
	case eps := <-ch:
		return eps, false
	case <-timeoutCtx.Done():
		opts.Logger.Warn("parse timeout", "kind", kind, "source", sourceURL)
		return nil, true
	}
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
	bundleEps, timedOut := extractWithTimeout(ctx, body, req.URL, "bundle", opts)
	if timedOut {
		result.stats.BundlesSkipped++
		return result
	}

	result.stats.BundlesAnalyzed++
	result.stats.EndpointsFound += len(bundleEps)
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
		if len(src) > opts.MaxBundleSize {
			result.stats.SourcemapSourceTimeouts++
			opts.Logger.Warn("sourcemap source oversized, skipping", "bundle", req.URL, "size", len(src))
			continue
		}
		smEps, timedOut := extractWithTimeout(ctx, []byte(src), req.URL, "sourcemap-source", opts)
		if timedOut {
			result.stats.SourcemapSourceTimeouts++
			continue
		}
		result.stats.EndpointsFound += len(smEps)
		for i := range smEps {
			smEps[i].SourceTag = SourceSourcemap
		}
		smSynth := toRequests(smEps, req.URL)
		result.requests = append(result.requests, smSynth...)
		result.stats.EndpointsKept += len(smSynth)
	}

	return result
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
// Length rationale: this function intentionally exceeds the project's ~60-line
// guideline. Its body is the orchestration shape of the package — pre-loop
// classification, worker-pool fan-out, fan-in with Stats merge, output slice
// build, and post-run cancellation check. Splitting the merge or fan-out
// into helpers would force them to expose Stats, work channels, and the
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
				r := analyzeOne(ctx, req, opts)
				resultCh <- r
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
		stats.EndpointsFound += r.stats.EndpointsFound
		stats.EndpointsKept += r.stats.EndpointsKept
		synthesized = append(synthesized, r.requests...)
		workerProcessed += r.stats.BundlesAnalyzed + r.stats.BundlesSkipped
	}
	if abandoned := len(bundles) - workerProcessed; abandoned > 0 {
		stats.BundlesAbandonedOnCancel = abandoned
	}

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
