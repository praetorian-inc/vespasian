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

	"github.com/praetorian-inc/vespasian/pkg/crawl"
)

// ScanOptions configures ResolveAndGenerate.
type ScanOptions struct {
	// TargetURL is the scan target. ResolveWSDLType probes TargetURL?wsdl.
	TargetURL string

	// APIType is the requested API type. An empty string or APITypeAuto triggers
	// auto-detection via DetectAPIType; otherwise the value is used as-is.
	APIType string

	// Confidence is the classifier match threshold (0.0-1.0).
	Confidence float64

	// Probe enables active endpoint probing (and gates WSDL discovery).
	Probe bool

	// Deduplicate enables endpoint deduplication after classification.
	Deduplicate bool

	// AllowPrivate disables SSRF protection on probes (allow private/internal IPs).
	AllowPrivate bool

	// GRPCInsecureSkipVerify skips TLS certificate verification when probing
	// gRPC server reflection over TLS. Forwarded to ClassifyProbeGenerate.
	GRPCInsecureSkipVerify bool

	// MergeSlugs enables observation-based slug merging in REST path
	// normalization. Ignored by the wsdl/graphql generators.
	MergeSlugs bool

	// SlugThreshold is the minimum distinct values at a path position before
	// --merge-slugs collapses it. Must be >=2 when MergeSlugs is set. Ignored
	// unless MergeSlugs is set.
	SlugThreshold int

	// Status is an optional io.Writer for verbose status messages.
	// Pass nil to suppress.
	Status io.Writer

	// AfterWSDL, when non-nil, runs after WSDL resolution and before
	// classification, receiving the (post-WSDL-resolve) request slice and
	// returning the slice to classify. The CLI uses this to keep its JS-replay
	// step in its current pipeline position; the SDK passes nil.
	AfterWSDL func(ctx context.Context, requests []crawl.ObservedRequest) []crawl.ObservedRequest
}

// ResolveAndGenerate runs the detect → wsdl-resolve → (AfterWSDL hook) →
// classify/probe/generate sequence shared by ScanCmd.Run (cmd/vespasian) and
// Capability.runScan (pkg/sdk).
//
// When opts.APIType is empty or APITypeAuto it is resolved via DetectAPIType.
// ResolveWSDLType then probes targetURL?wsdl (gated on opts.Probe and honoring
// opts.AllowPrivate); on success the API type is promoted to WSDL. The optional
// opts.AfterWSDL hook then runs against the resolved request slice. Finally
// ClassifyProbeGenerate produces the spec.
//
// It returns the produced spec, the resolved API type, whether a WSDL document
// was found, the augmented request slice fed to classification, and any error.
func ResolveAndGenerate(ctx context.Context, requests []crawl.ObservedRequest, opts ScanOptions) (spec []byte, apiType string, foundWSDL bool, augmented []crawl.ObservedRequest, err error) {
	apiType = opts.APIType
	if apiType == "" || apiType == APITypeAuto {
		apiType = DetectAPIType(requests, opts.Confidence)
	}

	requests, apiType, foundWSDL = ResolveWSDLType(ctx, opts.TargetURL, apiType, requests, opts.Probe, opts.AllowPrivate, opts.Status)

	if opts.AfterWSDL != nil {
		requests = opts.AfterWSDL(ctx, requests)
	}

	spec, err = ClassifyProbeGenerate(ctx, requests, Options{
		APIType:                apiType,
		Confidence:             opts.Confidence,
		Probe:                  opts.Probe,
		Deduplicate:            opts.Deduplicate,
		AllowPrivate:           opts.AllowPrivate,
		GRPCInsecureSkipVerify: opts.GRPCInsecureSkipVerify,
		MergeSlugs:             opts.MergeSlugs,
		SlugThreshold:          opts.SlugThreshold,
		Status:                 opts.Status,
	})
	return spec, apiType, foundWSDL, requests, err
}
