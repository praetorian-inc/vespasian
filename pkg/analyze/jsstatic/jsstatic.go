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

// withDefaults returns a copy of o with zero values replaced by defaults.
func (o Options) withDefaults() Options {
	if o.PerBundleTimeout == 0 {
		o.PerBundleTimeout = DefaultPerBundleTimeout
	}
	if o.MaxBundleSize == 0 {
		o.MaxBundleSize = DefaultMaxBundleSize
	}
	if o.MaxEndpointsPerBundle == 0 {
		o.MaxEndpointsPerBundle = DefaultMaxEndpointsPerBundle
	}
	if o.Concurrency == 0 {
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
	EndpointsFound      int // raw extractedEndpoint count, pre-filter.
	EndpointsKept       int // endpoints that survived filtering and made it into Requests.
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

// analyzeOne analyzes a single captured JS bundle. It runs sourcemap recovery
// and extractor extraction, then synthesizes requests. The function is safe to
// call from goroutines; it has no shared mutable state.
func analyzeOne(ctx context.Context, req crawl.ObservedRequest, opts Options) perBundleResult {
	var result perBundleResult
	body := req.Response.Body

	// Run sourcemap recovery (ctx propagated for remote fetch cancellation).
	smSources, smStats := recoverSourcemap(ctx, body, req.URL, opts)
	result.stats.SourcemapFetchFails += smStats.SourcemapFetchFails
	result.stats.SourcemapsRecovered += smStats.SourcemapsRecovered

	// Extract endpoints from the bundle body.
	bundleCh := make(chan []ExtractedEndpoint, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				opts.Logger.Error("jsluice panic", "bundle", req.URL, "panic", r)
				bundleCh <- nil
			}
		}()
		eps, extractErr := ExtractFromBundle(body, req.URL, opts)
		if extractErr != nil {
			opts.Logger.Warn("bundle extract error", "url", req.URL, "err", extractErr)
		}
		bundleCh <- eps
	}()

	var bundleEps []ExtractedEndpoint
	bundleCtx, cancel := context.WithTimeout(ctx, opts.PerBundleTimeout)
	defer cancel()
	select {
	case eps := <-bundleCh:
		bundleEps = eps
	case <-bundleCtx.Done():
		result.stats.BundlesSkipped++
		opts.Logger.Warn("bundle parse timeout", "url", req.URL)
		return result
	}

	result.stats.BundlesAnalyzed++
	result.stats.EndpointsFound += len(bundleEps)

	// Cap endpoints per bundle.
	if len(bundleEps) > opts.MaxEndpointsPerBundle {
		bundleEps = bundleEps[:opts.MaxEndpointsPerBundle]
	}

	// Tag bundle endpoints as static:js.
	for i := range bundleEps {
		bundleEps[i].SourceTag = SourceJS
	}

	// Synthesize requests from bundle endpoints.
	synth := toRequests(bundleEps, req.URL)
	result.requests = append(result.requests, synth...)
	result.stats.EndpointsKept += len(synth)

	// Process each recovered sourcemap source. Per-source extraction errors
	// are best-effort (one bad sourcesContent entry should not abort the rest).
	for _, src := range smSources {
		smEps, smErr := ExtractFromBundle([]byte(src), req.URL, opts)
		if smErr != nil && opts.Logger != nil {
			opts.Logger.Debug("jsstatic: sourcemap source extraction failed",
				"bundle", req.URL, "error", smErr)
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
func Analyze(ctx context.Context, captured []crawl.ObservedRequest, opts Options) (Result, error) {
	// Check context before any work.
	if ctx.Err() != nil {
		return Result{Requests: captured}, ctx.Err()
	}

	opts = opts.withDefaults()

	// Identify JS bundles to analyze.
	var bundles []crawl.ObservedRequest
	for _, req := range captured {
		ct := req.Response.ContentType
		body := req.Response.Body
		if !isJSContentType(ct) || len(body) == 0 {
			continue
		}
		if len(body) > opts.MaxBundleSize {
			// Oversized: skip and count.
			continue
		}
		bundles = append(bundles, req)
	}

	// Count oversized bundles separately for Stats.
	var stats Stats
	for _, req := range captured {
		ct := req.Response.ContentType
		body := req.Response.Body
		if isJSContentType(ct) && len(body) > opts.MaxBundleSize {
			stats.BundlesSkipped++
		}
	}

	if len(bundles) == 0 {
		return Result{Requests: captured, Stats: stats}, nil
	}

	// Worker pool for parallel bundle analysis.
	type work struct {
		idx int
		req crawl.ObservedRequest
	}
	workCh := make(chan work, len(bundles))
	resultCh := make(chan perBundleResult, len(bundles))

	var wg sync.WaitGroup
	for i := 0; i < opts.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for w := range workCh {
				select {
				case <-ctx.Done():
					return
				default:
				}
				r := analyzeOne(ctx, w.req, opts)
				resultCh <- r
			}
		}()
	}

	for i, req := range bundles {
		workCh <- work{i, req}
	}
	close(workCh)

	// Wait for workers then close resultCh.
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	// Collect results.
	var synthesized []crawl.ObservedRequest
	for r := range resultCh {
		stats.BundlesAnalyzed += r.stats.BundlesAnalyzed
		stats.BundlesSkipped += r.stats.BundlesSkipped
		stats.SourcemapsRecovered += r.stats.SourcemapsRecovered
		stats.SourcemapFetchFails += r.stats.SourcemapFetchFails
		stats.EndpointsFound += r.stats.EndpointsFound
		stats.EndpointsKept += r.stats.EndpointsKept
		synthesized = append(synthesized, r.requests...)
	}

	// Build result: original captured first, synthesized appended after.
	out := make([]crawl.ObservedRequest, len(captured), len(captured)+len(synthesized))
	copy(out, captured)
	out = append(out, synthesized...)

	return Result{Requests: out, Stats: stats}, nil
}
