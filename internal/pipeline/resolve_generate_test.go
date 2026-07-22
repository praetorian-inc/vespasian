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
	"context"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/vespasian/internal/pipeline"
	"github.com/praetorian-inc/vespasian/pkg/crawl"
	"github.com/praetorian-inc/vespasian/pkg/httpx"
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

// TestResolveAndGenerate_ForwardsProxy verifies that ScanOptions.Proxy is
// forwarded both to ResolveWSDLType (the WSDL discovery fetch) and to
// Options (the subsequent classify/probe/generate stage) — the recording
// proxy must see traffic from both stages (LAB-4993).
func TestResolveAndGenerate_ForwardsProxy(t *testing.T) {
	ts := wsdlServer(t)

	proxy, hits := newRecordingProxy(t, true)

	proxyURL, err := url.Parse(proxy.URL)
	require.NoError(t, err)

	in := []crawl.ObservedRequest{
		{Method: "GET", URL: ts.URL + "/", Response: crawl.ObservedResponse{StatusCode: 200}},
	}

	spec, apiType, foundWSDL, _, err := pipeline.ResolveAndGenerate(
		context.Background(),
		in,
		pipeline.ScanOptions{
			TargetURL:    ts.URL,
			APIType:      pipeline.APITypeREST,
			Confidence:   0.5,
			Probe:        true,
			Deduplicate:  true,
			AllowPrivate: true,
			Proxy:        httpx.ProxyConfig{URL: proxyURL},
		},
	)
	require.NoError(t, err)
	assert.True(t, foundWSDL, "valid WSDL document must be discovered through the proxy")
	assert.Equal(t, pipeline.APITypeWSDL, apiType)
	assert.NotEmpty(t, spec)

	// The proxy must have seen traffic from BOTH the WSDL discovery fetch
	// (ResolveWSDLType) and the subsequent probe stage (Options); either stage
	// silently skipping the proxy would leave hits unexpectedly low, so this
	// asserts more than one hit rather than merely non-zero.
	assert.GreaterOrEqual(t, hits.Load(), int64(2),
		"proxy must be forwarded to both ResolveWSDLType and the ClassifyProbeGenerate probe stage")
}
