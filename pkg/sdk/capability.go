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

package sdk

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/url"
	"strings"
	"time"

	"github.com/praetorian-inc/capability-sdk/pkg/capability"
	"github.com/praetorian-inc/capability-sdk/pkg/capmodel"

	"github.com/praetorian-inc/vespasian/internal/pipeline"
	"github.com/praetorian-inc/vespasian/pkg/analyze"
	"github.com/praetorian-inc/vespasian/pkg/crawl"
)

// Compile-time interface satisfaction check.
var _ capability.Capability[capmodel.WebApplication] = (*Capability)(nil)

// crawlFunc is a package-level seam that tests can swap to avoid launching a
// real browser. Signature matches defaultCrawl; tests replace it with a stub.
var crawlFunc func(ctx context.Context, opts crawl.CrawlerOptions, target string) ([]crawl.ObservedRequest, error) = defaultCrawl

// wsdlProbeFunc is a package-level seam that tests can swap to avoid making a
// real network call when exercising the WSDL-discovery branch in runScan.
var wsdlProbeFunc func(ctx context.Context, targetURL string, requests []crawl.ObservedRequest, allowPrivate bool, status io.Writer) ([]crawl.ObservedRequest, bool, string) = pipeline.ProbeAndAppendWSDLRequest

// Capability implements capability.Capability[capmodel.WebApplication] and
// exposes the vespasian crawl → classify → probe → generate pipeline through
// the standard capability-sdk interface.
type Capability struct{}

// Name returns the capability identifier.
func (c *Capability) Name() string { return "vespasian" }

// Description returns a human-readable summary.
func (c *Capability) Description() string {
	return "discovers API endpoints via headless browser crawling and generates OpenAPI / GraphQL SDL / WSDL specs"
}

// Input returns the zero value of the input type used for JSON unmarshalling.
func (c *Capability) Input() any { return capmodel.WebApplication{} }

// Full implements capability.PeriodicCapability — run a full scan every 5 days.
func (c *Capability) Full() time.Duration { return 5 * 24 * time.Hour }

// Timeout implements capability.TimeoutCapability — 30 minutes worst-case.
func (c *Capability) Timeout() int { return 30 }

// Parameters declares the configurable parameters for this capability.
func (c *Capability) Parameters() []capability.Parameter {
	return []capability.Parameter{
		capability.String("mode", "Operating mode: scan or crawl").WithDefault("scan").WithOptions("scan", "crawl"),
		capability.String("api_type", "API type: auto, rest, graphql, wsdl").WithDefault("auto").WithOptions("auto", "rest", "graphql", "wsdl"),
		capability.Int("timeout", "Total crawl duration in seconds").WithDefault("600"),
		capability.Int("max_pages", "Maximum pages to crawl").WithDefault("100"),
		capability.Int("depth", "Maximum crawl depth").WithDefault("3"),
		capability.String("scope", "Crawl scope: same-origin or same-domain").WithDefault("same-origin").WithOptions("same-origin", "same-domain"),
		capability.String("headers", "Comma-separated auth headers (e.g. 'Authorization: Bearer tok, X-Key: abc'). Header values containing commas are not supported."),
		capability.String("confidence", "Minimum classification confidence 0-1").WithDefault("0.5"),
		capability.Bool("probe", "Enable endpoint probing").WithDefault("true"),
	}
}

// Match validates the input before Invoke is called.
func (c *Capability) Match(_ capability.ExecutionContext, input capmodel.WebApplication) error {
	if input.PrimaryURL == "" {
		return fmt.Errorf("primary_url is required")
	}
	u, err := url.Parse(input.PrimaryURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("vespasian requires HTTP/HTTPS URL, got %q", input.PrimaryURL)
	}
	if !input.Seed {
		return fmt.Errorf("vespasian only runs on web application seeds")
	}
	return nil
}

// Invoke runs the pipeline (crawl, and optionally classify → probe → generate).
func (c *Capability) Invoke(ctx capability.ExecutionContext, input capmodel.WebApplication, output capability.Emitter) error {
	mode, _ := ctx.Parameters.GetString("mode")
	if mode == "" {
		mode = "scan"
	}

	opts, err := crawlOptsFromCtx(ctx)
	if err != nil {
		return err
	}

	start := time.Now()

	requests, err := crawlFunc(context.Background(), opts, input.PrimaryURL)
	if err != nil {
		return fmt.Errorf("vespasian: crawl failed: %w", err)
	}

	// Augment with static HTML form analysis (mirrors CLI pipeline).
	requests = append(requests, analyze.ExtractForms(requests)...)

	// Group requests by page URL and emit Webpage entries (filter static assets).
	parent := capmodel.WebApplication{PrimaryURL: input.PrimaryURL, Name: input.Name}
	emittedPages := emitWebpages(requests, parent, output)

	if mode == "crawl" {
		slog.Info("vespasian crawl completed",
			"target", input.PrimaryURL,
			"mode", "crawl",
			"duration_ms", time.Since(start).Milliseconds(),
			"crawled_pages", len(requests),
			"emitted_webpages", emittedPages,
		)
		return nil
	}

	hasSpec, apiType := c.runScan(ctx, requests, input, output)

	slog.Info("vespasian scan completed",
		"target", input.PrimaryURL,
		"mode", "scan",
		"duration_ms", time.Since(start).Milliseconds(),
		"crawled_pages", len(requests),
		"emitted_webpages", emittedPages,
		"has_spec", hasSpec,
		"api_type", apiType,
	)
	return nil
}

// runScan runs the classify → probe → generate phase and emits a WebApplication
// with the spec if one is produced. Returns (hasSpec, resolvedAPIType).
func (c *Capability) runScan(ctx capability.ExecutionContext, requests []crawl.ObservedRequest, input capmodel.WebApplication, output capability.Emitter) (bool, string) {
	confidence := parseConfidence(ctx.Parameters)
	probeEnabled := parseProbeEnabled(ctx.Parameters)

	apiType, _ := ctx.Parameters.GetString("api_type")
	if apiType == "" || apiType == pipeline.APITypeAuto {
		apiType = pipeline.DetectAPIType(requests, confidence)
	}

	// When the resolved API type is WSDL or REST, try fetching a WSDL document
	// from <primaryURL>?wsdl. SOAP services often return HTML for browser GETs,
	// so active probing is the reliable discovery method.
	if apiType == pipeline.APITypeWSDL || apiType == pipeline.APITypeREST {
		var foundWSDL bool
		requests, foundWSDL, _ = wsdlProbeFunc(context.Background(), input.PrimaryURL, requests, false, nil)
		if foundWSDL {
			apiType = pipeline.APITypeWSDL
		}
	}

	spec, err := pipeline.ClassifyProbeGenerate(context.Background(), requests, pipeline.Options{
		APIType:      apiType,
		Confidence:   confidence,
		Probe:        probeEnabled,
		Deduplicate:  true,
		AllowPrivate: false,
		Status:       nil,
	})
	if err != nil {
		slog.Warn("vespasian: classify/generate failed", "target", input.PrimaryURL, "error", err)
		return false, apiType
	}

	if len(bytes.TrimSpace(spec)) == 0 {
		return false, apiType
	}

	webApp := input
	webApp.Spec = string(spec)
	webApp.SpecFormat = specFormatForType(apiType)
	_ = output.Emit(webApp) //nolint:errcheck // emitter errors are non-fatal; logged by host
	return true, apiType
}

// ---------------------------------------------------------------------------
// Crawl seam
// ---------------------------------------------------------------------------

func defaultCrawl(ctx context.Context, opts crawl.CrawlerOptions, target string) ([]crawl.ObservedRequest, error) {
	c := crawl.NewCrawler(opts)
	return c.Crawl(ctx, target)
}

// crawlOptsFromCtx extracts and validates crawl options from the execution context.
func crawlOptsFromCtx(ctx capability.ExecutionContext) (crawl.CrawlerOptions, error) {
	scope, _ := ctx.Parameters.GetString("scope")
	if scope == "" {
		scope = "same-origin"
	}
	if scope != "same-origin" && scope != "same-domain" {
		return crawl.CrawlerOptions{}, fmt.Errorf("vespasian: invalid scope %q, must be 'same-origin' or 'same-domain'", scope)
	}

	opts := crawl.CrawlerOptions{
		Timeout:  600 * time.Second,
		MaxPages: 100,
		Depth:    3,
		Scope:    scope,
		Headless: true,
	}
	if t, ok := ctx.Parameters.GetInt("timeout"); ok {
		opts.Timeout = time.Duration(t) * time.Second
	}
	if m, ok := ctx.Parameters.GetInt("max_pages"); ok {
		opts.MaxPages = m
	}
	if d, ok := ctx.Parameters.GetInt("depth"); ok {
		opts.Depth = d
	}
	if h, ok := ctx.Parameters.GetString("headers"); ok && h != "" {
		parsed, err := parseHeaders(h)
		if err != nil {
			return crawl.CrawlerOptions{}, fmt.Errorf("vespasian: %w", err)
		}
		opts.Headers = parsed
	}
	return opts, nil
}

func parseConfidence(params capability.Parameters) float64 {
	cf, ok := params.GetString("confidence")
	if !ok || cf == "" {
		return 0.5
	}
	var v float64
	if _, err := fmt.Sscanf(cf, "%f", &v); err != nil {
		return 0.5
	}
	if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 || v > 1 {
		return 0.5
	}
	return v
}

func parseProbeEnabled(params capability.Parameters) bool {
	p, ok := params.GetBool("probe")
	if !ok {
		return true
	}
	return p
}

func specFormatForType(apiType string) string {
	switch apiType {
	case pipeline.APITypeGraphQL:
		return capmodel.SpecFormatGraphQL
	case pipeline.APITypeWSDL:
		return capmodel.SpecFormatWSDL
	default:
		return capmodel.SpecFormatOpenAPI
	}
}

// ---------------------------------------------------------------------------
// Emit helpers
// ---------------------------------------------------------------------------

// emitWebpages groups requests by page URL, filters static assets, and emits
// one capmodel.Webpage per unique non-static URL. Returns the number emitted.
func emitWebpages(requests []crawl.ObservedRequest, parent capmodel.WebApplication, output capability.Emitter) int {
	byURL := make(map[string][]capmodel.WebpageRequest)
	var order []string
	for _, req := range requests {
		if req.URL == "" {
			continue
		}
		if pipeline.IsStaticAssetURL(req.URL) {
			continue
		}
		pageKey := req.PageURL
		if pageKey == "" {
			pageKey = req.URL
		}
		if pipeline.IsStaticAssetURL(pageKey) {
			continue
		}
		if _, seen := byURL[pageKey]; !seen {
			order = append(order, pageKey)
		}
		byURL[pageKey] = append(byURL[pageKey], toWebpageRequest(req))
	}

	for _, u := range order {
		_ = output.Emit(capmodel.Webpage{ //nolint:errcheck // emitter errors are non-fatal; logged by host
			URL:      u,
			Requests: byURL[u],
			Parent:   parent,
		})
	}
	return len(order)
}

// toWebpageRequest converts a crawl.ObservedRequest to capmodel.WebpageRequest,
// converting single-value headers to multi-value form.
func toWebpageRequest(req crawl.ObservedRequest) capmodel.WebpageRequest {
	wpReq := capmodel.WebpageRequest{
		RequestedURL: req.URL,
		Method:       req.Method,
		Headers:      toMultiValueHeaders(req.Headers),
		Body:         string(req.Body),
	}
	resp := req.Response
	if resp.StatusCode != 0 || len(resp.Body) > 0 || len(resp.Headers) > 0 {
		wpReq.Response = &capmodel.WebpageResponse{
			StatusCode: resp.StatusCode,
			Headers:    toMultiValueHeaders(resp.Headers),
			Body:       string(resp.Body),
		}
	}
	return wpReq
}

func toMultiValueHeaders(headers map[string]string) map[string][]string {
	if len(headers) == 0 {
		return nil
	}
	result := make(map[string][]string, len(headers))
	for k, v := range headers {
		result[k] = []string{v}
	}
	return result
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

// parseHeaders parses a comma-separated "Key: Value, K2: V2" string. Whitespace
// around keys and values is trimmed. Each entry is validated via crawl.ParseHeader
// (RFC 7230 names; no CR/LF/NUL in values). Header values containing commas are
// not supported — the value will be split at the first comma.
func parseHeaders(raw string) (map[string]string, error) {
	if raw == "" {
		return nil, nil
	}
	headers := make(map[string]string)
	for _, hdr := range strings.Split(raw, ",") {
		hdr = strings.TrimSpace(hdr)
		if hdr == "" {
			continue
		}
		name, value, err := crawl.ParseHeader(hdr)
		if err != nil {
			return nil, err
		}
		headers[name] = value
	}
	return headers, nil
}
