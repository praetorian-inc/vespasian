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
	"time"

	"github.com/praetorian-inc/capability-sdk/pkg/capability"
	"github.com/praetorian-inc/capability-sdk/pkg/capmodel"

	"github.com/praetorian-inc/vespasian/pkg/classify"
	"github.com/praetorian-inc/vespasian/pkg/crawl"
	"github.com/praetorian-inc/vespasian/pkg/generate"
	wsdlgen "github.com/praetorian-inc/vespasian/pkg/generate/wsdl"
	"github.com/praetorian-inc/vespasian/pkg/probe"
)

// Capability implements capability.Capability[capmodel.WebApplication] for
// running Vespasian's API discovery pipeline as a Chariot platform capability.
type Capability struct{}

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
	}
}

// Match validates that the input WebApplication is suitable for this capability.
// Returns an error if PrimaryURL is empty or does not have a valid http/https scheme and host.
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
}

// resolveParams extracts and defaults all Invoke parameters from the execution context.
func resolveParams(ctx capability.ExecutionContext) invokeParams {
	p := invokeParams{
		apiType:     "auto",
		depth:       3,
		maxPages:    100,
		timeoutSecs: 600,
		confidence:  0.5,
		headless:    true,
		enableProbe: true,
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

	return p
}

// Invoke runs the Vespasian pipeline against the input WebApplication and emits
// a capmodel.WebApplication with the generated API specification. The spec format
// depends on the detected API type: OpenAPI 3.0 for REST, GraphQL SDL for GraphQL,
// or WSDL for SOAP services.
func (c *Capability) Invoke(ctx capability.ExecutionContext, input capmodel.WebApplication, output capability.Emitter) error {
	p := resolveParams(ctx)

	crawlTimeout := time.Duration(p.timeoutSecs) * time.Second
	// NOTE: capability.ExecutionContext does not carry a context.Context,
	// so we create a standalone context with timeout. If the SDK adds
	// context support in the future, this should thread the parent context.
	crawlCtx, cancel := context.WithTimeout(context.Background(), crawlTimeout)
	defer cancel()

	var browserMgr *crawl.BrowserManager
	if p.headless {
		var err error
		browserMgr, err = crawl.NewBrowserManager(crawl.BrowserOptions{Headless: true})
		if err != nil {
			return fmt.Errorf("launch browser: %w", err)
		}
		defer browserMgr.Close()
	}

	crawler := crawl.NewCrawler(crawl.CrawlerOptions{
		Depth:      p.depth,
		MaxPages:   p.maxPages,
		Timeout:    crawlTimeout,
		Headless:   p.headless,
		BrowserMgr: browserMgr,
		Stderr:     io.Discard,
	})

	requests, err := crawler.Crawl(crawlCtx, input.PrimaryURL)
	if err != nil {
		return fmt.Errorf("crawl %q: %w", input.PrimaryURL, err)
	}

	resolvedAPIType := p.apiType

	if resolvedAPIType == "auto" || resolvedAPIType == "wsdl" || resolvedAPIType == "rest" {
		if wsdlDoc := probeWSDLDocument(input.PrimaryURL); wsdlDoc != nil {
			resolvedAPIType = "wsdl"
			requests = append(requests, crawl.ObservedRequest{
				Method: "GET",
				URL:    input.PrimaryURL + "?wsdl",
				Response: crawl.ObservedResponse{
					StatusCode:  200,
					ContentType: "text/xml",
					Body:        wsdlDoc,
				},
			})
		}
	}

	if resolvedAPIType == "auto" {
		resolvedAPIType = detectAPIType(requests, p.confidence)
	}

	classifiers := classifiersForType(resolvedAPIType)
	if classifiers == nil {
		return fmt.Errorf("unsupported API type: %q", resolvedAPIType)
	}
	classified := classify.RunClassifiers(classifiers, requests, p.confidence)
	// Deduplication is always enabled in the SDK (the CLI exposes it as a
	// flag for debugging, but disabling it is not useful in production).
	classified = classify.Deduplicate(classified)

	if p.enableProbe {
		cfg := probe.DefaultConfig()
		strategies := probeStrategiesForType(resolvedAPIType, cfg)
		enriched, probeErrs := probe.RunStrategies(crawlCtx, strategies, classified)
		if len(enriched) == 0 && len(probeErrs) > 0 {
			return fmt.Errorf("all probes failed: %v", probeErrs[0])
		}
		classified = enriched
	}

	gen, err := generate.Get(resolvedAPIType)
	if err != nil {
		return fmt.Errorf("get generator for %q: %w", resolvedAPIType, err)
	}

	spec, err := gen.Generate(classified)
	if err != nil {
		return fmt.Errorf("generate spec: %w", err)
	}

	// The capmodel.WebApplication model has a single spec field (OpenAPI).
	// For non-REST types (GraphQL SDL, WSDL), the spec is stored in this
	// field as the model does not have type-specific spec fields.
	return output.Emit(capmodel.WebApplication{
		PrimaryURL: input.PrimaryURL,
		OpenAPI:    string(spec),
	})
}

// detectAPIType runs all three classifiers and returns the winning API type.
// GraphQL wins when it has the most (or tied-most) matches. WSDL wins when it
// has matches and is >= REST. Otherwise REST is returned.
func detectAPIType(requests []crawl.ObservedRequest, threshold float64) string {
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

// classifiersForType returns the appropriate classifiers for the given API type,
// or nil if the API type is not recognized.
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

// probeWSDLDocument attempts to fetch a WSDL document from targetURL?wsdl.
// Returns the raw WSDL bytes if the response is a valid WSDL document, or nil
// if the probe fails, is blocked by SSRF protection, or returns non-WSDL content.
func probeWSDLDocument(targetURL string) []byte {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil
	}
	parsedURL.RawQuery = "wsdl"
	wsdlURL := parsedURL.String()

	if err := probe.ValidateProbeURL(wsdlURL); err != nil {
		return nil
	}

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			DialContext: probe.SSRFSafeDialContext,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(wsdlURL) //nolint:gosec // URL validated by ValidateProbeURL above
	if err != nil {
		return nil
	}
	defer func() {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)) //nolint:errcheck,gosec // best-effort drain
		resp.Body.Close()                                    //nolint:errcheck,gosec // best-effort close
	}()

	if resp.StatusCode >= 400 {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20)) // 2MB limit
	if err != nil {
		return nil
	}

	if _, parseErr := wsdlgen.ParseWSDL(body); parseErr != nil {
		return nil
	}

	return body
}
