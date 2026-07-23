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
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/praetorian-inc/vespasian/pkg/classify"
	"github.com/praetorian-inc/vespasian/pkg/crawl"
	"github.com/praetorian-inc/vespasian/pkg/generate"
	"github.com/praetorian-inc/vespasian/pkg/probe"
)

// Options configures ClassifyProbeGenerate.
type Options struct {
	// APIType is one of APITypeREST, APITypeWSDL, APITypeGraphQL, APITypeGRPC.
	APIType string

	// Confidence is the classifier match threshold (0.0-1.0).
	Confidence float64

	// Probe enables active endpoint probing.
	Probe bool

	// Deduplicate enables endpoint deduplication after classification.
	Deduplicate bool

	// AllowPrivate disables SSRF protection on probes (allow private/internal IPs).
	AllowPrivate bool

	// GRPCInsecureSkipVerify skips TLS certificate verification when probing
	// gRPC server reflection over TLS (for self-signed/internal-CA targets).
	// SSRF protection is still enforced by the dialer regardless.
	GRPCInsecureSkipVerify bool

	// MergeSlugs enables observation-based slug merging in REST path
	// normalization. Ignored by the wsdl/graphql generators.
	MergeSlugs bool

	// SlugThreshold is the minimum distinct values at a path position before
	// --merge-slugs collapses it. Must be >=2 when MergeSlugs is set (enforced
	// by ValidateSlugThreshold). Ignored unless MergeSlugs is set.
	SlugThreshold int

	// Status is an optional io.Writer for verbose status messages.
	// Pass nil or io.Discard to suppress.
	Status io.Writer
}

// ValidateSlugThreshold rejects a --slug-threshold < 2 when --merge-slugs is
// on. wsdl/graphql ignore slug options, so they are exempt to avoid a
// misleading error. It is the single source of truth shared by the CLI
// (cmd/vespasian), the SDK (pkg/sdk), and ClassifyProbeGenerate itself so a
// bad flag combination is rejected consistently regardless of entry point.
func ValidateSlugThreshold(apiType string, mergeSlugs bool, slugThreshold int) error {
	if apiType == APITypeWSDL || apiType == APITypeGraphQL {
		return nil
	}
	if mergeSlugs && slugThreshold < 2 {
		return fmt.Errorf("--slug-threshold must be >= 2")
	}
	return nil
}

// ClassifyProbeGenerate runs the classify → probe → generate pipeline and
// returns the produced spec bytes.
func ClassifyProbeGenerate(ctx context.Context, requests []crawl.ObservedRequest, opts Options) ([]byte, error) {
	classifiers := ClassifiersForType(opts.APIType)
	if classifiers == nil {
		return nil, fmt.Errorf("unsupported API type: %q", opts.APIType)
	}

	// REST-scoped: wsdl/graphql ignore slug options (see ValidateSlugThreshold).
	// The rest generator additionally clamps SlugThreshold <2 to 2, but we reject
	// it here so direct callers (SDK, tests) get the same explicit error the CLI
	// surfaces early, rather than silent clamping.
	if err := ValidateSlugThreshold(opts.APIType, opts.MergeSlugs, opts.SlugThreshold); err != nil {
		return nil, err
	}

	classified := classify.RunClassifiers(classifiers, requests, opts.Confidence)
	if opts.Deduplicate {
		classified = classify.Deduplicate(classified)
	}

	writeStatus(opts.Status, "classified %d API requests (threshold=%.2f)\n", len(classified), opts.Confidence)
	logClassificationReasons(opts.Status, classified)

	if opts.Probe {
		cfg := probe.DefaultConfig()
		cfg.GRPCInsecureSkipVerify = opts.GRPCInsecureSkipVerify
		if opts.AllowPrivate {
			// allow-private disables ONLY SSRF protection (URLValidator +
			// DialContext re-resolution). Clone probe's default transport and
			// override just DialContext with a plain net.Dialer so every other
			// default (TLS/idle timeouts, and any future proxy/CA settings) is
			// preserved rather than dropped by a hand-rolled bare transport. The
			// client otherwise mirrors probe's default client (CheckRedirect only).
			cfg.URLValidator = func(string) error { return nil }
			transport := probe.DefaultTransport()
			transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, addr)
			}
			cfg.Client = &http.Client{
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
				Transport: transport,
			}
			cfg.Dialer = func(ctx context.Context, network, addr string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, addr)
			}
		}
		// Pure grpc-gateway traffic is REST/JSON, so the gRPC classifier never
		// marks it APIType=="grpc" and the gRPC/gateway probes (which only
		// iterate grpc endpoints) get no targets. Seed one synthetic grpc
		// endpoint per distinct host so reflection and the gateway probe have
		// something to reach. SSRF protection still applies via the probes'
		// URLValidator/Dialer.
		if opts.APIType == APITypeGRPC {
			classified = seedGRPCHostEndpoints(requests, classified, probe.DefaultMaxEndpoints)
		}
		strategies := StrategiesForType(opts.APIType, cfg)
		enriched, probeErrs := probe.RunStrategies(ctx, strategies, classified)
		for _, e := range probeErrs {
			writeStatus(opts.Status, "probe warning: %v\n", e)
		}
		classified = enriched
	}

	// Lowest-priority gRPC-Web JS binding recovery from the capture. This is a
	// static pass over the captured JS bodies (no network), so it runs for
	// --api-type grpc whether or not probing was enabled. When probing ran,
	// classified holds the probed result and bindings fill only the endpoints
	// reflection/gateway did not cover; reflection results are never
	// overwritten (reflection > gateway > bindings). When probing did not run,
	// classified holds the raw classified set and bindings enrich that.
	if opts.APIType == APITypeGRPC {
		classified = enrichGRPCFromBindings(requests, classified, opts.Status)
	}

	gen, err := generate.GetWithOptions(opts.APIType, generate.Options{
		MergeSlugs:    opts.MergeSlugs,
		SlugThreshold: opts.SlugThreshold,
	})
	if err != nil {
		return nil, err
	}

	spec, err := gen.Generate(classified)
	if err != nil {
		return nil, fmt.Errorf("generate failed: %w", err)
	}

	return spec, nil
}
