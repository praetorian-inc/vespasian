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

package pipeline

import (
	"context"
	"io"

	"github.com/praetorian-inc/vespasian/pkg/analyze"
	"github.com/praetorian-inc/vespasian/pkg/analyze/jsstatic"
	"github.com/praetorian-inc/vespasian/pkg/crawl"
)

// AugmentOptions configures Augment.
type AugmentOptions struct {
	// AnalyzeJS enables the JS-bundle static-analysis stage. When false the
	// JS stage is skipped; the static-HTML forms stage always runs.
	AnalyzeJS bool

	// FetchSourcemaps, when AnalyzeJS is true, fetches .js.map sourcemaps
	// referenced via //# sourceMappingURL= comments to recover original sources.
	FetchSourcemaps bool

	// AllowPrivate disables SSRF protection during JS-static sourcemap fetching
	// (allow private/internal IPs).
	AllowPrivate bool

	// Status is an optional io.Writer for the verbose js-static stats line.
	// Pass nil to suppress.
	Status io.Writer
}

// Augment runs the captured-request augmentation stages in the canonical order:
// static-HTML forms first, then JS-bundle static analysis. The forms stage
// always runs; the JS stage runs only when opts.AnalyzeJS is true and the
// capture does not already carry a JS-static source (the idempotency guard).
//
// The order matters for downstream determinism: static:html entries appear
// before static:js entries in the result, so classify.Deduplicate
// first-write-wins keeps the form-derived signals when they collide with
// bundle-derived ones on the same endpoint key.
//
// JS-analysis errors are non-fatal — best-effort enrichment must never fail the
// surrounding pipeline; on error the (forms-augmented) input is returned
// unchanged with respect to the JS stage.
//
// Augment is the single source of truth for the forms-then-jsstatic contract
// shared by ScanCmd.Run / GenerateCmd.Run (cmd/vespasian) and Capability.Invoke
// (pkg/sdk).
func Augment(ctx context.Context, requests []crawl.ObservedRequest, opts AugmentOptions) []crawl.ObservedRequest {
	requests = append(requests, analyze.ExtractForms(requests)...)
	return AnalyzeJS(ctx, requests, opts)
}

// AnalyzeJS runs the JS-bundle static-analysis stage on requests and returns the
// (possibly enriched) slice. When opts.AnalyzeJS is false, returns requests
// unchanged. When the capture already carries a JS-static source, the analysis
// is skipped (idempotency guard) so running crawl | generate is byte-identical
// to running scan directly. Analysis errors are logged to opts.Status and
// treated as a no-op (best-effort enrichment must never fail the pipeline).
//
// This is exposed separately from Augment because CrawlCmd runs only the JS
// stage at crawl time, deferring static-HTML form extraction to generate time.
func AnalyzeJS(ctx context.Context, requests []crawl.ObservedRequest, opts AugmentOptions) []crawl.ObservedRequest {
	if !opts.AnalyzeJS {
		return requests
	}
	// Skip if any request already carries a JS-static source — this capture was
	// produced by a stage that already ran jsstatic.Analyze.
	if crawl.AnyStaticSource(requests) {
		return requests
	}
	res, err := jsstatic.Analyze(ctx, requests, jsstatic.Options{
		FetchSourcemaps: opts.FetchSourcemaps,
		AllowPrivate:    opts.AllowPrivate,
	})
	if err != nil {
		writeStatus(opts.Status, "warning: js-static analysis failed: %v\n", err)
		return requests
	}
	writeStatus(opts.Status, "js-static: bundles=%d skipped=%d panics=%d, sourcemaps=%d, endpoints=%d\n",
		res.Stats.BundlesAnalyzed, res.Stats.BundlesSkipped, res.Stats.AnalyzeOnePanics,
		res.Stats.SourcemapsRecovered, res.Stats.EndpointsKept)
	return res.Requests
}
