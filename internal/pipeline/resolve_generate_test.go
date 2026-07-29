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

package pipeline_test

import (
	"bytes"
	"context"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/vespasian/internal/pipeline"
	"github.com/praetorian-inc/vespasian/pkg/crawl"
)

// TestResolveAndGenerate_AutoDetectsREST verifies that an empty APIType triggers
// DetectAPIType, which resolves REST traffic to the REST generator and produces
// a non-empty OpenAPI spec.
func TestResolveAndGenerate_AutoDetectsREST(t *testing.T) {
	spec, apiType, foundWSDL, augmented, err := pipeline.ResolveAndGenerate(
		context.Background(),
		restRequests(),
		pipeline.ScanOptions{
			APIType:     "", // empty → auto-detect
			Confidence:  0.5,
			Probe:       false,
			Deduplicate: true,
		},
	)
	require.NoError(t, err)
	assert.Equal(t, pipeline.APITypeREST, apiType)
	assert.False(t, foundWSDL)
	assert.NotEmpty(t, spec, "expected a non-empty REST spec")
	assert.Equal(t, restRequests(), augmented, "no probe → requests returned unchanged")
}

// TestResolveAndGenerate_AutoKeyword verifies that the literal "auto" APIType is
// treated the same as empty (auto-detected).
func TestResolveAndGenerate_AutoKeyword(t *testing.T) {
	_, apiType, _, _, err := pipeline.ResolveAndGenerate(
		context.Background(),
		restRequests(),
		pipeline.ScanOptions{
			APIType:    pipeline.APITypeAuto,
			Confidence: 0.5,
			Probe:      false,
		},
	)
	require.NoError(t, err)
	assert.Equal(t, pipeline.APITypeREST, apiType)
}

// TestResolveAndGenerate_ExplicitTypeSkipsDetection verifies that an explicit
// APIType is honored without auto-detection (graphql traffic with explicit
// graphql produces a GraphQL spec).
func TestResolveAndGenerate_ExplicitTypeSkipsDetection(t *testing.T) {
	requests := []crawl.ObservedRequest{
		{
			Method:  "POST",
			URL:     "https://x.com/graphql",
			Headers: map[string]string{"Content-Type": "application/json"},
			Body:    []byte(`{"query":"{ user(id: 1) { id name } }"}`),
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "application/json",
				Headers:     map[string]string{"Content-Type": "application/json"},
				Body:        []byte(`{"data":{"user":{"id":"1","name":"Alice"}}}`),
			},
		},
	}
	spec, apiType, _, _, err := pipeline.ResolveAndGenerate(
		context.Background(),
		requests,
		pipeline.ScanOptions{
			APIType:    pipeline.APITypeGraphQL,
			Confidence: 0.5,
			Probe:      false,
		},
	)
	require.NoError(t, err)
	assert.Equal(t, pipeline.APITypeGraphQL, apiType)
	assert.NotEmpty(t, spec)
}

// TestResolveAndGenerate_AfterWSDLRunsBetweenResolveAndClassify verifies the
// ordering contract: the AfterWSDL hook fires after WSDL resolution and before
// classification, receiving the (post-WSDL-resolve) request slice and feeding
// its return value into ClassifyProbeGenerate.
func TestResolveAndGenerate_AfterWSDLRunsBetweenResolveAndClassify(t *testing.T) {
	hookCalled := false
	var hookInput []crawl.ObservedRequest

	// REST traffic with probe disabled: ResolveWSDLType is a no-op, so the hook
	// receives exactly the input requests. The hook appends a sentinel REST
	// request that classification picks up.
	in := restRequests()

	_, apiType, _, augmented, err := pipeline.ResolveAndGenerate(
		context.Background(),
		in,
		pipeline.ScanOptions{
			APIType:     pipeline.APITypeREST,
			Confidence:  0.5,
			Probe:       false,
			Deduplicate: true,
			AfterWSDL: func(_ context.Context, requests []crawl.ObservedRequest) []crawl.ObservedRequest {
				hookCalled = true
				hookInput = requests
				return append(requests, crawl.ObservedRequest{
					Method:  "GET",
					URL:     "https://x.com/api/v1/orders",
					Headers: map[string]string{"Content-Type": "application/json"},
					Response: crawl.ObservedResponse{
						StatusCode:  200,
						ContentType: "application/json",
						Headers:     map[string]string{"Content-Type": "application/json"},
						Body:        []byte(`[{"id":1}]`),
					},
				})
			},
		},
	)
	require.NoError(t, err)
	assert.True(t, hookCalled, "AfterWSDL hook must be invoked")
	assert.Equal(t, in, hookInput, "hook must receive the post-WSDL-resolve requests (unchanged when probe disabled)")
	assert.Equal(t, pipeline.APITypeREST, apiType)
	require.Len(t, augmented, len(in)+1, "augmented slice must include the hook's appended request")
}

// TestResolveAndGenerate_NilAfterWSDLIsSkipped verifies that a nil AfterWSDL
// hook is simply not called and the requests flow straight to classification.
func TestResolveAndGenerate_NilAfterWSDLIsSkipped(t *testing.T) {
	in := restRequests()
	spec, _, _, augmented, err := pipeline.ResolveAndGenerate(
		context.Background(),
		in,
		pipeline.ScanOptions{
			APIType:    pipeline.APITypeREST,
			Confidence: 0.5,
			Probe:      false,
			AfterWSDL:  nil,
		},
	)
	require.NoError(t, err)
	assert.NotEmpty(t, spec)
	assert.Equal(t, in, augmented, "nil hook + no probe → requests unchanged")
}

// TestResolveAndGenerate_WSDLPromotionFromREST verifies that with probing on and
// a server serving a valid WSDL document, the REST input type is promoted to
// WSDL, foundWSDL is true, and the synthetic WSDL request is appended.
func TestResolveAndGenerate_WSDLPromotionFromREST(t *testing.T) {
	ts := wsdlServer(t)

	in := []crawl.ObservedRequest{
		{Method: "GET", URL: ts.URL + "/", Response: crawl.ObservedResponse{StatusCode: 200}},
	}

	spec, apiType, foundWSDL, augmented, err := pipeline.ResolveAndGenerate(
		context.Background(),
		in,
		pipeline.ScanOptions{
			TargetURL:    ts.URL,
			APIType:      pipeline.APITypeREST,
			Confidence:   0.5,
			Probe:        true,
			Deduplicate:  true,
			AllowPrivate: true,
		},
	)
	require.NoError(t, err)
	assert.True(t, foundWSDL, "valid WSDL document must be discovered")
	assert.Equal(t, pipeline.APITypeWSDL, apiType, "REST must be promoted to WSDL")
	require.Len(t, augmented, 2, "the synthetic WSDL request must be appended")
	assert.NotEmpty(t, spec)
}

// TestResolveAndGenerate_UnknownTypeErrors verifies that an unsupported explicit
// API type surfaces an error from ClassifyProbeGenerate.
func TestResolveAndGenerate_UnknownTypeErrors(t *testing.T) {
	_, _, _, _, err := pipeline.ResolveAndGenerate(
		context.Background(),
		restRequests(),
		pipeline.ScanOptions{
			APIType:    "frobnitz",
			Confidence: 0.5,
			Probe:      false,
		},
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported API type")
}

// TestResolveAndGenerate_ForwardsTargetURLAndWarningsToProbeGate pins TEST-002:
// ResolveAndGenerate must forward ScanOptions.TargetURL and ScanOptions.Warnings
// into the Options it builds for ClassifyProbeGenerate, because those two fields
// are what the SEC-BE-001 probe-stage cross-origin gate runs on. This is the
// `scan` command's path (cmd/vespasian/main.go calls ResolveAndGenerate with
// ScanCmd.scanOptions), and it is a DIFFERENT call site from GenerateCmd.options()
// — which is why the CLI-boundary tests in cmd/vespasian/main_test.go did not
// cover it. Verified by mutation: deleting either forward in resolve_generate.go
// previously left the whole repository green, so `scan --target-url` could have
// silently stopped pinning the gate's origin, and the cross-origin skip warnings
// could have gone silent, with no test noticing.
//
// The capture is the CDN-first / real-API-second shape used in
// probe_origin_gate_test.go: the CDN entry occupies the "first request" slot that
// crawl.ResolveTargetOrigin would fall back to, so pinning TargetURL to the API
// host is the only thing that makes the API — and not the CDN — the probed origin.
func TestResolveAndGenerate_ForwardsTargetURLAndWarningsToProbeGate(t *testing.T) {
	api, apiHits := countingAPIServer(t)
	cdn, cdnHits := thirdPartyAssetServer(t)

	requests := []crawl.ObservedRequest{
		apiRequest(cdn.URL + "/api/v1/analytics"),
		apiRequest(api.URL + "/api/v1/accounts"),
	}

	var warnings bytes.Buffer
	_, apiType, _, _, err := pipeline.ResolveAndGenerate(
		context.Background(),
		requests,
		pipeline.ScanOptions{
			APIType:      pipeline.APITypeREST,
			Confidence:   0.5,
			Probe:        true,
			AllowPrivate: true, // loopback httptest servers must be dial-able
			Deduplicate:  true,
			TargetURL:    api.URL, // forwarded => gate pins the API origin
			Warnings:     &warnings,
		},
	)
	require.NoError(t, err)
	require.Equal(t, pipeline.APITypeREST, apiType)

	// TargetURL forwarded: the pinned origin is probed, the other is not.
	assert.Positive(t, atomic.LoadInt32(apiHits),
		"ScanOptions.TargetURL must reach Options.TargetURL so the gate pins the API origin and probes it")
	assert.Zero(t, atomic.LoadInt32(cdnHits),
		"the non-pinned origin must be rejected by the cross-origin gate, not probed")

	// Warnings forwarded: the skip warning reaches the caller's writer.
	assert.Contains(t, warnings.String(), "skipping cross-origin URL",
		"ScanOptions.Warnings must reach Options.Warnings so the cross-origin skip warning is visible")
	assert.NotContains(t, warnings.String(), "--target-url not set",
		"TargetURL pinned the origin, so the derived-origin warning must NOT fire")
}
