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

	// TargetURL is the scan's intended target, used together with requests to
	// derive the origin for the probe-stage cross-origin gate (SEC-BE-001) via
	// crawl.ResolveTargetOrigin. Should be the same value handed to the
	// JS-replay stage's JSReplayConfig.TargetURL so both stages agree on what
	// "the target origin" means for this scan. If empty, the origin is
	// derived from requests the same way JS-replay does.
	TargetURL string

	// AllowCrossOriginProbe disables the probe-stage cross-origin gate,
	// permitting probe requests to targets whose origin does not match the
	// origin resolved from TargetURL/requests. Internal-only — mirrors
	// crawl.JSReplayConfig.AllowCrossOrigin: defaults to false and has no CLI
	// flag. Enabling this lets a classified candidate (including a hostile
	// JS-static literal promoted by classify Rule 7) direct probe traffic at
	// an attacker-chosen public host; appropriate only for trusted
	// multi-host/tenant scans.
	AllowCrossOriginProbe bool

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

	// Warnings is an optional io.Writer for operator-facing warnings that
	// must be visible regardless of --verbose: the SEC-BE-001 cross-origin
	// probe-skip warning and the one-time "origin was derived, not chosen"
	// warning. Mirrors crawl.JSReplayConfig.Stderr / AugmentOptions.WarnError
	// — separate from Status so these are never accidentally silenced by a
	// non-verbose CLI invocation. Pass nil to stay fully quiet (e.g. the SDK).
	Warnings io.Writer
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

	// Resolved once and shared by the probe-stage cross-origin gate below and
	// the REST generator's servers/info.title derivation (SEC-BE-001/
	// SEC-BE-002), so the two stages never independently derive "the target
	// origin" and risk disagreeing. See crawl.ResolveTargetOrigin's doc
	// comment.
	targetOrigin := crawl.ResolveTargetOrigin(opts.TargetURL, requests)

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

		// Cross-origin probe gate (SEC-BE-001). Applied AFTER the AllowPrivate
		// branch above — and wrapping whatever validator is in place at this
		// point, nil or the no-op set above — so --dangerous-allow-private
		// disables SSRF checking only and never this gate. Without it, a
		// hostile JS-static literal (e.g. fetch("https://attacker.example/api/x"))
		// promoted by classify Rule 7's StaticJSConfidence floor reaches probe
		// with no origin check at all; the same gap applies to any
		// cross-origin candidate regardless of producer, since probe is the
		// only unscoped egress path in the pipeline (crawl is scope-guarded,
		// JS-replay is same-origin by default). See newCrossOriginValidator
		// and warnDerivedProbeOrigin for the gate/warning construction.
		//
		// The unconditional parse-time gate (newFullURLValidator, SEC-BE-001)
		// is wrapped here, BEFORE the AllowCrossOriginProbe branch below, for
		// two load-bearing reasons -- see newFullURLValidator's and
		// newCrossOriginValidator's own doc comments for the mechanics each
		// summarizes below:
		//
		// 1. AllowCrossOriginProbe must disable only the cross-origin check,
		// never this independent gate, and applying it here also puts it
		// INSIDE the cross-origin wrapper rather than inside
		// newCrossOriginValidator's same-origin arm: a same-origin candidate
		// carrying embedded userinfo credentials must still reach it, even
		// though crawl.SameOrigin (which ignores u.User) would let such a
		// candidate through.
		//
		// 2. This wrap is also what resolves a nil cfg.URLValidator to
		// probe.ValidateProbeURL before newCrossOriginValidator ever sees it,
		// so that function no longer carries its own nil-base fallback.
		// Swapping the two wraps below would therefore panic the first time a
		// SAME-ORIGIN, parse-time-valid candidate is probed -- not for a
		// cross-origin candidate, which the outer newCrossOriginValidator
		// rejects in its own cross-origin arm, before base is ever consulted.
		//
		// Placed at the pipeline level (not composed into
		// probe.ValidateProbeURL) because that function is also the exported
		// default for pkg/probe, which pkg/sdk consumes directly; changing its
		// behavior would affect every caller of pkg/probe -- a low-severity
		// finding does not warrant that blast radius.
		cfg.URLValidator = newFullURLValidator(cfg.URLValidator)

		if !opts.AllowCrossOriginProbe {
			// originIsDerived keys the (lazy) derived-origin warning on
			// whether opts.TargetURL actually pinned targetOrigin
			// (SEC-BE-002), not merely on opts.TargetURL being non-empty: an
			// unparseable or hostless TargetURL (e.g. "not a url", "://") is
			// non-empty but unusable, so crawl.ResolveTargetOrigin silently
			// falls through to deriving the origin from the capture -- the
			// exact case this warning exists to surface. crawl.SameOrigin("",
			// targetOrigin) is always false (it requires a non-empty
			// left-hand origin), so an empty TargetURL counts as derived too;
			// this one predicate covers both "not set" and "set but
			// unusable". The warning itself is NOT emitted here -- it fires
			// lazily, inside newCrossOriginValidator, only on the first
			// candidate actually rejected as cross-origin (SEC-BE-001 nit
			// review finding: emitting it here, unconditionally, printed
			// "endpoints will be skipped" even on an all-same-origin capture
			// where nothing ever was).
			originIsDerived := !crawl.SameOrigin(opts.TargetURL, targetOrigin)
			cfg.URLValidator = newCrossOriginValidator(cfg.URLValidator, targetOrigin, originIsDerived, opts.Warnings)
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
		TargetOrigin:  targetOrigin,
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
