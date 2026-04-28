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
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/praetorian-inc/capability-sdk/pkg/capability"
	"github.com/praetorian-inc/capability-sdk/pkg/capmodel"

	"github.com/praetorian-inc/vespasian/pkg/classify"
	"github.com/praetorian-inc/vespasian/pkg/crawl"
	"github.com/praetorian-inc/vespasian/pkg/generate"
	wsdlgen "github.com/praetorian-inc/vespasian/pkg/generate/wsdl"
	"github.com/praetorian-inc/vespasian/pkg/probe"
)

// validateProbeURLFunc is the SSRF guard used by probeWSDLDocument. Stored as
// a package var so tests can swap in a permissive validator when exercising
// the HTTP integration against an httptest server on loopback. Production
// code paths leave this untouched.
var validateProbeURLFunc = probe.ValidateProbeURL

// dialContextForWSDLProbe is the dialer used by the probeWSDLDocument
// http.Transport. Stored as a package var so tests can swap in a vanilla
// dialer to reach an httptest loopback server. Production callers leave
// this untouched.
var dialContextForWSDLProbe = probe.SSRFSafeDialContext

// Capability implements capability.Capability[capmodel.WebApplication] for
// running Vespasian's API discovery pipeline as a Chariot platform capability.
//
// All unexported fields are test seams — callers in production leave them nil
// and the zero-value Capability uses the real browser-backed crawler and
// real HTTP-backed WSDL probe. Tests set these fields to stub the pipeline
// and assert Invoke's end-to-end wiring (emit shape, context lifecycle,
// WSDL synthesis). Keep the fields unexported so this is strictly an
// in-package test seam, not part of the public API.
type Capability struct {
	// crawlFn, when non-nil, replaces the real browser-backed crawl step.
	// Takes the crawl-phase context, target URL, and resolved Invoke
	// parameters; returns the observed requests the generate phase will
	// consume. A nil value means "use the real browser-backed crawler".
	crawlFn func(ctx context.Context, targetURL string, p invokeParams) ([]crawl.ObservedRequest, error)

	// wsdlProbeFn, when non-nil, replaces the real HTTP-backed WSDL probe.
	// Takes the generate-phase context and target URL; returns raw WSDL bytes
	// when the endpoint serves a valid WSDL document, or nil otherwise. A nil
	// value means "use probeWSDLDocument".
	wsdlProbeFn func(ctx context.Context, targetURL string) []byte
}

// Name returns the capability name.
func (c *Capability) Name() string {
	return "vespasian"
}

// Description returns a human-readable description of the capability.
func (c *Capability) Description() string {
	return "Discovers API endpoints via headless browser crawling and generates API specifications (OpenAPI 3.0, GraphQL SDL, WSDL)"
}

// Input returns the input type for the capability.
func (c *Capability) Input() any {
	return capmodel.WebApplication{}
}

// Parameters declares the configurable parameters for the capability.
func (c *Capability) Parameters() []capability.Parameter {
	return []capability.Parameter{
		capability.String("api_type", "API type to generate").
			WithDefault("auto").
			WithOptions("auto", "rest", "wsdl", "graphql"),
		capability.Int("depth", "Max crawl depth").
			WithDefault("3"),
		capability.Int("max_pages", "Max pages to crawl").
			WithDefault("100"),
		capability.Int("timeout", "Crawl timeout in seconds").
			WithDefault("600"),
		capability.Float("confidence", "Min classification confidence").
			WithDefault("0.5"),
		capability.Bool("headless", "Use headless browser").
			WithDefault("true"),
		capability.Bool("probe", "Enable endpoint probing").
			WithDefault("true"),
		capability.String("scope", "Crawl scope").
			WithDefault("same-origin").
			WithOptions("same-origin", "same-domain"),
		capability.String("headers", "Additional request headers as comma-separated 'Key: Value' pairs").
			WithDefault(""),
		capability.String("proxy", "Proxy address for the headless browser (e.g. http://127.0.0.1:8080)").
			WithDefault(""),
		capability.Bool("deduplicate", "Deduplicate classified endpoints before spec generation").
			WithDefault("true"),
	}
}

// Match validates that the input WebApplication is suitable for this capability.
// Returns an error if PrimaryURL is empty or does not have a valid http/https scheme and host.
//
// NOTE: Match does not block private/loopback hosts. Chariot seeds are customer-approved
// targets, so PrimaryURL is treated as a trusted input. The crawl pipeline enforces
// SSRF protection via probe.SSRFSafeDialContext for active probing calls.
func (c *Capability) Match(_ capability.ExecutionContext, input capmodel.WebApplication) error {
	if input.PrimaryURL == "" {
		return fmt.Errorf("primary_url is required")
	}

	u, err := url.Parse(input.PrimaryURL)
	if err != nil {
		return fmt.Errorf("invalid primary_url %q: %w", input.PrimaryURL, err)
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("invalid primary_url %q: scheme must be http or https", input.PrimaryURL)
	}

	if u.Host == "" {
		return fmt.Errorf("invalid primary_url %q: missing host", input.PrimaryURL)
	}

	return nil
}

// invokeParams holds the resolved parameter values for an Invoke call.
type invokeParams struct {
	apiType     string
	depth       int
	maxPages    int
	timeoutSecs int
	confidence  float64
	headless    bool
	enableProbe bool
	scope       string
	headers     map[string]string
	proxy       string
	deduplicate bool
}

// resolveParams extracts and defaults all Invoke parameters from the execution context.
//
// NOTE: Parse failures in GetInt/GetFloat/GetBool return (zero-value, false), so the
// hardcoded defaults are retained. This is intentional — defensive defaults match the
// behavior of Kong's CLI flag defaults and avoid surfacing parse errors to callers.
//
// NOTE: The high parameter count is expected — it mirrors the full set of tunable
// knobs the capability exposes, and complexity scales linearly with that count.
func resolveParams(ctx capability.ExecutionContext) invokeParams {
	p := invokeParams{
		apiType:     "auto",
		depth:       3,
		maxPages:    100,
		timeoutSecs: 600,
		confidence:  0.5,
		headless:    true,
		enableProbe: true,
		scope:       "same-origin",
		headers:     nil,
		proxy:       "",
		deduplicate: true,
	}

	if v, _ := ctx.Parameters.GetString("api_type"); v != "" {
		p.apiType = v
	}
	if v, ok := ctx.Parameters.GetInt("depth"); ok {
		p.depth = v
	}
	if v, ok := ctx.Parameters.GetInt("max_pages"); ok {
		p.maxPages = v
	}
	if v, ok := ctx.Parameters.GetInt("timeout"); ok {
		p.timeoutSecs = v
	}
	if v, ok := ctx.Parameters.GetFloat("confidence"); ok {
		p.confidence = v
	}
	if v, ok := ctx.Parameters.GetBool("headless"); ok {
		p.headless = v
	}
	if v, ok := ctx.Parameters.GetBool("probe"); ok {
		p.enableProbe = v
	}
	if v, _ := ctx.Parameters.GetString("scope"); v != "" {
		p.scope = v
	}
	if v, _ := ctx.Parameters.GetString("headers"); v != "" {
		p.headers = parseHeaderString(v)
	}
	if v, _ := ctx.Parameters.GetString("proxy"); v != "" {
		p.proxy = v
	}
	if v, ok := ctx.Parameters.GetBool("deduplicate"); ok {
		p.deduplicate = v
	}

	return p
}

// validate checks that all numeric and range-bounded invokeParams fields hold
// meaningful values. It is called by Invoke immediately after resolveParams so
// that garbage inputs (negative timeout, zero max_pages, out-of-range confidence)
// are rejected before any context or browser is created.
func (p invokeParams) validate() error {
	if p.depth < 1 {
		return fmt.Errorf("invalid depth %v: must be >= 1", p.depth)
	}
	if p.maxPages < 1 {
		return fmt.Errorf("invalid max_pages %v: must be >= 1", p.maxPages)
	}
	if p.timeoutSecs < 1 {
		return fmt.Errorf("invalid timeout %v: must be >= 1", p.timeoutSecs)
	}
	if p.confidence < 0.0 || p.confidence > 1.0 {
		return fmt.Errorf("invalid confidence %v: must be between 0.0 and 1.0", p.confidence)
	}
	return nil
}

// buildCrawlerOptions translates the resolved invokeParams (and an optional
// caller-owned browser) into the crawl.CrawlerOptions used by runRealCrawl.
// Extracted so the parameter wiring can be unit-tested without launching a
// real browser or making network calls.
func buildCrawlerOptions(p invokeParams, browserMgr *crawl.BrowserManager) crawl.CrawlerOptions {
	return crawl.CrawlerOptions{
		Depth:      p.depth,
		MaxPages:   p.maxPages,
		Timeout:    time.Duration(p.timeoutSecs) * time.Second,
		Headless:   p.headless,
		Scope:      p.scope,
		Headers:    p.headers,
		Proxy:      p.proxy,
		BrowserMgr: browserMgr,
		Stderr:     io.Discard,
	}
}

// runRealCrawl launches the headless browser (when enabled) and runs the
// Katana-backed crawler against targetURL. This is the default crawlFn used
// when Capability.crawlFn is nil. It owns its browser lifecycle and closes
// the browser before returning.
func runRealCrawl(ctx context.Context, targetURL string, p invokeParams) ([]crawl.ObservedRequest, error) {
	var browserMgr *crawl.BrowserManager
	if p.headless {
		var err error
		browserMgr, err = crawl.NewBrowserManager(crawl.BrowserOptions{
			Headless: true,
			Proxy:    p.proxy,
		})
		if err != nil {
			return nil, fmt.Errorf("launch browser: %w", err)
		}
		defer browserMgr.Close()
	}

	crawler := crawl.NewCrawler(buildCrawlerOptions(p, browserMgr))

	return crawler.Crawl(ctx, targetURL)
}

// Invoke runs the Vespasian pipeline against the input WebApplication and emits
// a capmodel.WebApplication with the generated API specification. The spec format
// depends on the detected API type: OpenAPI 3.0 for REST, GraphQL SDL for GraphQL,
// or WSDL for SOAP services.
func (c *Capability) Invoke(ctx capability.ExecutionContext, input capmodel.WebApplication, output capability.Emitter) error {
	p := resolveParams(ctx)

	if p.scope != "same-origin" && p.scope != "same-domain" {
		return fmt.Errorf("invalid scope %q: must be same-origin or same-domain", p.scope)
	}

	if err := p.validate(); err != nil {
		return err
	}

	phaseBudget := time.Duration(p.timeoutSecs) * time.Second
	// NOTE: capability.ExecutionContext does not carry a context.Context,
	// so we create a standalone context with timeout. If the SDK adds
	// context support in the future, this should thread the parent context.
	crawlCtx, crawlCancel := context.WithTimeout(context.Background(), phaseBudget)
	defer crawlCancel()

	crawlFn := c.crawlFn
	if crawlFn == nil {
		crawlFn = runRealCrawl
	}

	requests, err := crawlFn(crawlCtx, input.PrimaryURL, p)
	// Cancel crawl context as soon as the crawl completes so that the generate
	// phase gets a fresh budget. If the crawl consumed the full timeout the
	// canceled context would cause probing to bail out immediately — mirroring
	// the pattern used in cmd/vespasian/main.go.
	crawlCancel()

	if err != nil {
		return fmt.Errorf("crawl %q: %w", input.PrimaryURL, err)
	}

	// NOTE: capability.ExecutionContext does not carry a context.Context,
	// so we create a fresh standalone context for the generate phase. Using
	// a separate context ensures the crawl budget does not starve probing.
	genCtx, genCancel := context.WithTimeout(context.Background(), phaseBudget)
	defer genCancel()

	wsdlProbeFn := c.wsdlProbeFn
	if wsdlProbeFn == nil {
		wsdlProbeFn = probeWSDLDocument
	}

	resolvedAPIType, syntheticReq := resolveAPITypeWithWSDLProbe(genCtx, p.apiType, input.PrimaryURL, wsdlProbeFn)
	if syntheticReq != nil {
		requests = append(requests, *syntheticReq)
	}

	spec, err := ClassifyProbeGenerate(genCtx, requests, resolvedAPIType, p.confidence, p.deduplicate, p.enableProbe)
	if err != nil {
		return fmt.Errorf("generate spec: %w", err)
	}

	// Preserve all input fields and overlay only the generated spec field.
	// The capmodel.WebApplication model has a single spec field (OpenAPI).
	// For non-REST types (GraphQL SDL, WSDL), the spec is stored in this
	// field as the model does not have type-specific spec fields.
	webApp := input
	webApp.OpenAPI = string(spec)
	return output.Emit(webApp)
}

// resolveAPITypeWithWSDLProbe runs the WSDL probe only when api_type is "auto"
// (operator already chose a specific type — don't let the server override it).
// Returns the resolved API type and a synthetic ObservedRequest carrying the WSDL
// body when the probe succeeds, or (apiType, nil) when no probe is needed or fails.
func resolveAPITypeWithWSDLProbe(ctx context.Context, apiType, primaryURL string, probeFn func(context.Context, string) []byte) (string, *crawl.ObservedRequest) {
	if apiType != "auto" {
		return apiType, nil
	}
	wsdlDoc := probeFn(ctx, primaryURL)
	if wsdlDoc == nil {
		return apiType, nil
	}
	wsdlURL, err := buildWSDLProbeURL(primaryURL)
	if err != nil {
		return apiType, nil
	}
	syntheticReq := &crawl.ObservedRequest{
		Method: "GET",
		URL:    wsdlURL,
		Response: crawl.ObservedResponse{
			StatusCode:  200,
			ContentType: "text/xml",
			Body:        wsdlDoc,
		},
	}
	return "wsdl", syntheticReq
}

// buildWSDLProbeURL constructs the URL used to probe for a WSDL document by
// adding "wsdl" as a query parameter while preserving any existing query string.
// Both probeWSDLDocument and resolveAPITypeWithWSDLProbe use this helper so that
// the synthetic ObservedRequest URL always matches the URL actually probed.
func buildWSDLProbeURL(targetURL string) (string, error) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return "", err
	}
	q := parsedURL.Query()
	q.Set("wsdl", "")
	parsedURL.RawQuery = q.Encode()
	return parsedURL.String(), nil
}

// ClassifyProbeGenerate runs the classification, probing, and generation pipeline
// on pre-crawled requests. This is the shared pipeline used by both the standalone
// CLI and the Chariot platform wrapper. It handles API type auto-detection,
// deduplication, and spec generation.
//
// Parameters:
//   - ctx: context for cancellation/timeout during probing
//   - requests: observed HTTP requests from a crawl
//   - apiType: "rest", "wsdl", "graphql", or "auto" for auto-detection
//   - confidence: minimum classification confidence threshold (0.0-1.0)
//   - deduplicate: whether to deduplicate classified endpoints before generation
//   - probeEnabled: whether to run active endpoint probing
//
// Returns the generated spec bytes (OpenAPI YAML, GraphQL SDL, or WSDL XML) or an error.
func ClassifyProbeGenerate(ctx context.Context, requests []crawl.ObservedRequest, apiType string, confidence float64, deduplicate bool, probeEnabled bool) ([]byte, error) {
	resolvedAPIType := apiType
	if resolvedAPIType == "auto" {
		resolvedAPIType = DetectAPIType(requests, confidence)
	}

	classifiers := classifiersForType(resolvedAPIType)
	if classifiers == nil {
		return nil, fmt.Errorf("unsupported API type: %q", resolvedAPIType)
	}

	classified := classify.RunClassifiers(classifiers, requests, confidence)
	if deduplicate {
		classified = classify.Deduplicate(classified)
	}

	if probeEnabled {
		cfg := probe.DefaultConfig()
		strategies := probeStrategiesForType(resolvedAPIType, cfg)
		enriched, probeErrs := probe.RunStrategies(ctx, strategies, classified)
		if len(enriched) == 0 && len(probeErrs) > 0 {
			return nil, fmt.Errorf("all probes failed: %v", probeErrs[0])
		}
		classified = enriched
	}

	gen, err := generate.Get(resolvedAPIType)
	if err != nil {
		return nil, fmt.Errorf("get generator for %q: %w", resolvedAPIType, err)
	}

	return gen.Generate(classified)
}

// DetectAPIType runs all three classifiers and returns the winning API type.
// GraphQL wins when it has the most (or tied-most) matches. WSDL wins when it
// has matches and is >= REST. Otherwise REST is returned.
func DetectAPIType(requests []crawl.ObservedRequest, threshold float64) string {
	wsdlClassifier := &classify.WSDLClassifier{}
	restClassifier := &classify.RESTClassifier{}
	graphqlClassifier := &classify.GraphQLClassifier{}

	var wsdlCount, restCount, graphqlCount int
	for _, req := range requests {
		if isAPI, confidence := wsdlClassifier.Classify(req); isAPI && confidence >= threshold {
			wsdlCount++
		}
		if isAPI, confidence := restClassifier.Classify(req); isAPI && confidence >= threshold {
			restCount++
		}
		if isAPI, confidence := graphqlClassifier.Classify(req); isAPI && confidence >= threshold {
			graphqlCount++
		}
	}

	if graphqlCount > 0 && graphqlCount >= wsdlCount && graphqlCount >= restCount {
		return "graphql"
	}
	if wsdlCount > 0 && wsdlCount >= restCount {
		return "wsdl"
	}
	return "rest"
}

// ClassifiersForType returns the appropriate classifiers for the given API type,
// or nil if the API type is not recognized.
func ClassifiersForType(apiType string) []classify.APIClassifier {
	return classifiersForType(apiType)
}

// classifiersForType is the internal implementation of ClassifiersForType.
func classifiersForType(apiType string) []classify.APIClassifier {
	switch apiType {
	case "rest":
		return []classify.APIClassifier{&classify.RESTClassifier{}}
	case "wsdl":
		return []classify.APIClassifier{&classify.WSDLClassifier{}}
	case "graphql":
		return []classify.APIClassifier{&classify.GraphQLClassifier{}}
	default:
		return nil
	}
}

// probeStrategiesForType returns the appropriate probe strategies for the given API type,
// or nil if the API type is not recognized.
func probeStrategiesForType(apiType string, cfg probe.Config) []probe.ProbeStrategy {
	switch apiType {
	case "rest":
		return []probe.ProbeStrategy{
			probe.NewOptionsProbe(cfg),
			probe.NewSchemaProbe(cfg),
		}
	case "wsdl":
		return []probe.ProbeStrategy{probe.NewWSDLProbe(cfg)}
	case "graphql":
		return []probe.ProbeStrategy{probe.NewGraphQLProbe(cfg)}
	default:
		return nil
	}
}

// isRejectedWSDLStatus reports whether the HTTP status code should cause
// probeWSDLDocument to reject the response without attempting to parse.
// Anything ≥300 is rejected: 3xx responses reach us because CheckRedirect
// returns ErrUseLastResponse (not a final WSDL response), and 4xx/5xx
// indicate the endpoint does not serve WSDL.
func isRejectedWSDLStatus(status int) bool {
	return status >= 300
}

// isAcceptableWSDLContentType reports whether a response's Content-Type
// header value is one the WSDL probe will accept. An empty content type is
// allowed because some WSDL endpoints omit it; the parser is then the
// authority. Any other value short-circuits the probe.
func isAcceptableWSDLContentType(header string) bool {
	ct := strings.ToLower(strings.TrimSpace(strings.Split(header, ";")[0]))
	switch ct {
	case "", "text/xml", "application/xml", "application/wsdl+xml":
		return true
	default:
		return false
	}
}

// probeWSDLDocument attempts to fetch a WSDL document from targetURL with ?wsdl
// appended. Existing query parameters are preserved. Returns the raw WSDL bytes
// if the response is a valid WSDL document, or nil if the probe fails, is blocked
// by SSRF protection, or returns non-WSDL content.
//
// NOTE: Silent failures are intentional — this is a best-effort probe.
func probeWSDLDocument(ctx context.Context, targetURL string) []byte {
	if ctx == nil {
		ctx = context.Background()
	}

	wsdlURL, err := buildWSDLProbeURL(targetURL)
	if err != nil {
		return nil
	}

	if err := validateProbeURLFunc(wsdlURL); err != nil {
		return nil
	}

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			DialContext:           dialContextForWSDLProbe,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wsdlURL, nil)
	if err != nil {
		return nil
	}

	resp, err := client.Do(req) //nolint:gosec // URL validated by ValidateProbeURL above
	if err != nil {
		return nil
	}
	defer func() {
		// Drain up to 2 MiB so the connection can return to the keep-alive
		// pool, then close. Both errors are unrecoverable here — the return
		// value is already decided by decodeWSDLResponse below — so they are
		// intentionally discarded via explicit _ assignment.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 2<<20)) //nolint:errcheck
		_ = resp.Body.Close()                                        //nolint:errcheck
	}()

	return decodeWSDLResponse(resp)
}

// decodeWSDLResponse inspects an HTTP response and returns the WSDL body bytes
// when the response is a parseable WSDL document, or nil otherwise. It applies
// the same status, content-type, size, and parse gates used by the live probe
// so that the two code paths stay in sync.
//
// The caller owns resp.Body and must close it.
func decodeWSDLResponse(resp *http.Response) []byte {
	if isRejectedWSDLStatus(resp.StatusCode) {
		return nil
	}
	if !isAcceptableWSDLContentType(resp.Header.Get("Content-Type")) {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil
	}
	if _, parseErr := wsdlgen.ParseWSDL(body); parseErr != nil {
		return nil
	}
	return body
}

// headerValueIsSafe reports whether s is safe to use as an HTTP header key or
// value. It rejects any string containing CR, LF, or NUL characters that could
// be used to smuggle additional headers through CDP/katana paths that bypass
// net/http's own validation.
func headerValueIsSafe(s string) bool {
	return !strings.ContainsAny(s, "\r\n\x00")
}

// parseHeaderString parses a comma-separated list of "Key: Value" header pairs
// into a map. Entries that do not contain a colon are silently ignored. Entries
// whose trimmed key or value contain CR, LF, or NUL are also silently dropped
// to prevent header injection.
func parseHeaderString(raw string) map[string]string {
	headers := make(map[string]string)
	for _, hdr := range strings.Split(raw, ",") {
		hdr = strings.TrimSpace(hdr)
		if hdr == "" {
			continue
		}
		parts := strings.SplitN(hdr, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			if !headerValueIsSafe(key) || !headerValueIsSafe(val) {
				continue
			}
			headers[key] = val
		}
	}
	return headers
}
