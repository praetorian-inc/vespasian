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

// Package sdk (white-box tests) exercises private helper functions that
// cannot be reached from the black-box test file.
package sdk

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/capability-sdk/pkg/capability"
	"github.com/praetorian-inc/capability-sdk/pkg/capmodel"

	"github.com/praetorian-inc/vespasian/pkg/classify"
	"github.com/praetorian-inc/vespasian/pkg/crawl"
	"github.com/praetorian-inc/vespasian/pkg/probe"
)

// ---------------------------------------------------------------------------
// Match (url.Parse failure branch)
// ---------------------------------------------------------------------------

// TestMatch_URLParseError covers the url.Parse failure branch (capability.go:97-99)
// which is the one branch not covered by the black-box tests in capability_test.go.
// A URL with a space in the host causes url.Parse to return an error on Go 1.12+.
func TestMatch_URLParseError(t *testing.T) {
	c := &Capability{}
	ctx := capability.ExecutionContext{}

	// A URL with a space in the host is unparseable by net/url.
	input := capmodel.WebApplication{PrimaryURL: "http://example .com/"}
	err := c.Match(ctx, input)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid primary_url")
}

// ---------------------------------------------------------------------------
// detectAPIType
// ---------------------------------------------------------------------------

// graphqlRequest returns a minimal ObservedRequest that scores above the
// default 0.5 threshold as a GraphQL call (POST body with GraphQL query).
// It deliberately omits ContentType to avoid triggering the REST classifier's
// content-type heuristic, ensuring detectAPIType sees graphqlCount > restCount.
func graphqlRequest() crawl.ObservedRequest {
	return crawl.ObservedRequest{
		Method: "POST",
		URL:    "http://example.com/graphql",
		Body:   []byte(`{"query":"{ users { id name } }"}`),
		// No ContentType — keeps REST confidence below 0.5 so only GraphQL scores.
	}
}

// soapRequest returns a minimal ObservedRequest that scores above threshold
// as a SOAP/WSDL call (SOAPAction header present).
func soapRequest() crawl.ObservedRequest {
	return crawl.ObservedRequest{
		Method: "POST",
		URL:    "http://example.com/service",
		Headers: map[string]string{
			"SOAPAction": "\"urn:example#DoSomething\"",
		},
		Response: crawl.ObservedResponse{StatusCode: 200},
	}
}

// restRequest returns a minimal ObservedRequest that scores as a REST call
// (JSON response, no SOAP or GraphQL signals).
func restRequest() crawl.ObservedRequest {
	return crawl.ObservedRequest{
		Method: "GET",
		URL:    "http://example.com/api/v1/users",
		Response: crawl.ObservedResponse{
			StatusCode:  200,
			ContentType: "application/json",
			Body:        []byte(`[{"id":1}]`),
		},
	}
}

func TestDetectAPIType_Empty(t *testing.T) {
	result := DetectAPIType([]crawl.ObservedRequest{}, 0.5)
	assert.Equal(t, "rest", result, "empty request list should default to rest")
}

// TestDetectAPIType_GraphQLWins verifies that a traffic mix containing only
// GraphQL requests results in "graphql". The same requests also score on the
// REST classifier (POST method → 0.7), so graphqlCount == restCount and the
// tie-breaking rule (graphqlCount >= restCount) selects graphql.
func TestDetectAPIType_GraphQLWins(t *testing.T) {
	requests := []crawl.ObservedRequest{
		graphqlRequest(),
		graphqlRequest(),
	}
	result := DetectAPIType(requests, 0.5)
	assert.Equal(t, "graphql", result)
}

// TestDetectAPIType_WSDLWins verifies that SOAP-heavy traffic selects "wsdl".
// SOAP requests score high for WSDL (0.95 for SOAPAction header) and also
// score for REST (POST method → 0.7). The WSDL-wins branch fires when
// wsdlCount > 0 && wsdlCount >= restCount, which holds when all requests are
// SOAP-only (both counts equal).
func TestDetectAPIType_WSDLWins(t *testing.T) {
	requests := []crawl.ObservedRequest{
		soapRequest(),
		soapRequest(),
	}
	result := DetectAPIType(requests, 0.5)
	assert.Equal(t, "wsdl", result)
}

func TestDetectAPIType_RESTDefault(t *testing.T) {
	requests := []crawl.ObservedRequest{
		restRequest(),
		restRequest(),
	}
	result := DetectAPIType(requests, 0.5)
	assert.Equal(t, "rest", result)
}

// GraphQL wins when it is tied with another type (graphqlCount >= wsdlCount &&
// graphqlCount >= restCount with graphqlCount > 0).
// The graphql request also fires REST (POST method), so both graphqlCount and
// wsdlCount are 1 and restCount is 2. wsdlCount(1) < restCount(2) so WSDL
// can't win; graphqlCount(1) < restCount(2) so strictly GraphQL also can't win
// via tie-break. This case actually falls through to REST — corrected below.
//
// A true tie that GraphQL wins: only graphql requests with no pure-REST mix.
func TestDetectAPIType_NeitherGraphQLNorWSDLTiesREST(t *testing.T) {
	// Multiple graphql requests so graphqlCount > 0 and graphqlCount >= wsdlCount.
	// wsdlCount stays 0, restCount equals graphqlCount (POST fires REST).
	// Condition: graphqlCount(2) >= wsdlCount(0) && graphqlCount(2) >= restCount(2) → true.
	requests := []crawl.ObservedRequest{
		graphqlRequest(),
		soapRequest(), // wsdlCount=1, restCount=3 after this — graphql can't tie
	}
	// One graphql (fires graphql+rest), one soap (fires wsdl+rest):
	// graphqlCount=1, wsdlCount=1, restCount=2.
	// graphqlCount(1) >= restCount(2)? No.
	// wsdlCount(1) >= restCount(2)? No.
	// Result: REST.
	result := DetectAPIType(requests, 0.5)
	assert.Equal(t, "rest", result)
}

// WSDL wins over REST when wsdlCount >= restCount and graphql has none.
// For this to hold: all requests must be SOAP (wsdlCount == restCount via POST).
func TestDetectAPIType_WSDLTieBeatsREST(t *testing.T) {
	// A pure SOAP request fires both wsdl (0.95) and rest (POST → 0.7).
	// wsdlCount == restCount, graphqlCount == 0.
	// Condition: wsdlCount(1) > 0 && wsdlCount(1) >= restCount(1) → true.
	requests := []crawl.ObservedRequest{
		soapRequest(),
	}
	result := DetectAPIType(requests, 0.5)
	assert.Equal(t, "wsdl", result)
}

// High threshold means no classifier meets confidence — falls through to REST.
func TestDetectAPIType_HighThresholdFallsToREST(t *testing.T) {
	requests := []crawl.ObservedRequest{
		graphqlRequest(), // confidence ~0.70 for path-only match
	}
	// Threshold above the path-only GraphQL confidence of 0.70.
	result := DetectAPIType(requests, 0.99)
	assert.Equal(t, "rest", result)
}

// ---------------------------------------------------------------------------
// classifiersForType
// ---------------------------------------------------------------------------

func TestClassifiersForType_WSDL(t *testing.T) {
	classifiers := classifiersForType("wsdl")
	require.Len(t, classifiers, 1)
	assert.Equal(t, "wsdl", classifiers[0].Name())

	_, ok := classifiers[0].(*classify.WSDLClassifier)
	assert.True(t, ok, "expected *classify.WSDLClassifier")
}

func TestClassifiersForType_GraphQL(t *testing.T) {
	classifiers := classifiersForType("graphql")
	require.Len(t, classifiers, 1)
	assert.Equal(t, "graphql", classifiers[0].Name())

	_, ok := classifiers[0].(*classify.GraphQLClassifier)
	assert.True(t, ok, "expected *classify.GraphQLClassifier")
}

func TestClassifiersForType_REST(t *testing.T) {
	classifiers := classifiersForType("rest")
	require.Len(t, classifiers, 1)
	assert.Equal(t, "rest", classifiers[0].Name())

	_, ok := classifiers[0].(*classify.RESTClassifier)
	assert.True(t, ok, "expected *classify.RESTClassifier")
}

// Unknown type returns nil.
func TestClassifiersForType_UnknownReturnsNil(t *testing.T) {
	classifiers := classifiersForType("unknown")
	assert.Nil(t, classifiers, "expected nil for unknown type")
}

// ---------------------------------------------------------------------------
// probeStrategiesForType
// ---------------------------------------------------------------------------

func TestProbeStrategiesForType_WSDL(t *testing.T) {
	strategies := probeStrategiesForType("wsdl", probe.DefaultConfig())
	require.Len(t, strategies, 1)
	assert.Equal(t, "wsdl", strategies[0].Name())
}

func TestProbeStrategiesForType_GraphQL(t *testing.T) {
	strategies := probeStrategiesForType("graphql", probe.DefaultConfig())
	require.Len(t, strategies, 1)
	assert.Equal(t, "graphql", strategies[0].Name())
}

func TestProbeStrategiesForType_REST(t *testing.T) {
	strategies := probeStrategiesForType("rest", probe.DefaultConfig())
	require.Len(t, strategies, 2)

	names := make([]string, 0, len(strategies))
	for _, s := range strategies {
		names = append(names, s.Name())
	}
	assert.ElementsMatch(t, []string{"options", "schema"}, names)
}

// Unknown type returns nil.
func TestProbeStrategiesForType_UnknownReturnsNil(t *testing.T) {
	strategies := probeStrategiesForType("unknown", probe.DefaultConfig())
	assert.Nil(t, strategies, "expected nil for unknown type")
}

// ---------------------------------------------------------------------------
// resolveParams
// ---------------------------------------------------------------------------

func TestResolveParams_Defaults(t *testing.T) {
	ctx := capability.ExecutionContext{
		Parameters: capability.Parameters{},
	}

	p := resolveParams(ctx)

	assert.Equal(t, "auto", p.apiType)
	assert.Equal(t, 3, p.depth)
	assert.Equal(t, 100, p.maxPages)
	assert.Equal(t, 600, p.timeoutSecs)
	assert.InDelta(t, 0.5, p.confidence, 0.001)
	assert.True(t, p.headless)
	assert.True(t, p.enableProbe)
	assert.Equal(t, "same-origin", p.scope)
	assert.Nil(t, p.headers)
	assert.Equal(t, "", p.proxy)
	assert.True(t, p.deduplicate)
}

func TestResolveParams_AllOverridden(t *testing.T) {
	ctx := capability.ExecutionContext{
		Parameters: capability.Parameters{
			{Name: "api_type", Value: "graphql"},
			{Name: "depth", Value: "5"},
			{Name: "max_pages", Value: "200"},
			{Name: "timeout", Value: "300"},
			{Name: "confidence", Value: "0.8"},
			{Name: "headless", Value: "false"},
			{Name: "probe", Value: "false"},
			{Name: "scope", Value: "same-domain"},
			{Name: "headers", Value: "X-Token: abc, X-Org: test"},
			{Name: "proxy", Value: "http://127.0.0.1:8080"},
			{Name: "deduplicate", Value: "false"},
		},
	}

	p := resolveParams(ctx)

	assert.Equal(t, "graphql", p.apiType)
	assert.Equal(t, 5, p.depth)
	assert.Equal(t, 200, p.maxPages)
	assert.Equal(t, 300, p.timeoutSecs)
	assert.InDelta(t, 0.8, p.confidence, 0.001)
	assert.False(t, p.headless)
	assert.False(t, p.enableProbe)
	assert.Equal(t, "same-domain", p.scope)
	assert.Equal(t, map[string]string{"X-Token": "abc", "X-Org": "test"}, p.headers)
	assert.Equal(t, "http://127.0.0.1:8080", p.proxy)
	assert.False(t, p.deduplicate)
}

func TestResolveParams_PartialOverride(t *testing.T) {
	ctx := capability.ExecutionContext{
		Parameters: capability.Parameters{
			{Name: "api_type", Value: "wsdl"},
			{Name: "depth", Value: "10"},
			// max_pages, timeout, confidence, headless, probe not provided
		},
	}

	p := resolveParams(ctx)

	// Overridden values
	assert.Equal(t, "wsdl", p.apiType)
	assert.Equal(t, 10, p.depth)

	// Defaults retained for unset parameters
	assert.Equal(t, 100, p.maxPages)
	assert.Equal(t, 600, p.timeoutSecs)
	assert.InDelta(t, 0.5, p.confidence, 0.001)
	assert.True(t, p.headless)
	assert.True(t, p.enableProbe)
}

func TestResolveParams_InvalidValues(t *testing.T) {
	ctx := capability.ExecutionContext{
		Parameters: capability.Parameters{
			{Name: "depth", Value: "not-a-number"},
			{Name: "max_pages", Value: "abc"},
			{Name: "timeout", Value: "xyz"},
			{Name: "confidence", Value: "not-float"},
			{Name: "headless", Value: "not-bool"},
			{Name: "probe", Value: "not-bool"},
		},
	}

	p := resolveParams(ctx)

	// When GetInt/GetFloat/GetBool return (0, false) due to parse failure,
	// resolveParams retains the hardcoded defaults because ok==false.
	assert.Equal(t, 3, p.depth)
	assert.Equal(t, 100, p.maxPages)
	assert.Equal(t, 600, p.timeoutSecs)
	assert.InDelta(t, 0.5, p.confidence, 0.001)
	assert.True(t, p.headless)
	assert.True(t, p.enableProbe)
}

func TestResolveParams_EmptyAPIType(t *testing.T) {
	ctx := capability.ExecutionContext{
		Parameters: capability.Parameters{
			{Name: "api_type", Value: ""},
		},
	}

	p := resolveParams(ctx)

	// GetString returns ("", false) when Value is empty and no Default is set
	// on the Parameter in the ctx. resolveParams checks v != "" before overriding.
	assert.Equal(t, "auto", p.apiType)
}

// ---------------------------------------------------------------------------
// resolveParams bound-check tests
// ---------------------------------------------------------------------------

// TestResolveParams_NegativeDepth documents that resolveParams itself does not
// validate: negative depth passes through unmodified. The validate() call in
// Invoke is responsible for rejecting it.
func TestResolveParams_NegativeDepth(t *testing.T) {
	ctx := capability.ExecutionContext{
		Parameters: capability.Parameters{{Name: "depth", Value: "-1"}},
	}
	p := resolveParams(ctx)
	assert.Equal(t, -1, p.depth)
}

// TestInvoke_NegativeDepthIsRejected verifies that Invoke rejects depth < 1
// before creating any context or performing any crawl work.
func TestInvoke_NegativeDepthIsRejected(t *testing.T) {
	cap := &Capability{
		crawlFn: func(_ context.Context, _ string, _ invokeParams) ([]crawl.ObservedRequest, error) {
			t.Fatal("crawlFn must not be called when params are invalid")
			return nil, nil
		},
	}
	ctx := capability.ExecutionContext{
		Parameters: capability.Parameters{
			{Name: "depth", Value: "-1"},
			{Name: "headless", Value: "false"},
		},
	}
	err := cap.Invoke(ctx, capmodel.WebApplication{PrimaryURL: "http://example.com"}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid depth")
}

func TestResolveParams_ZeroMaxPages(t *testing.T) {
	ctx := capability.ExecutionContext{
		Parameters: capability.Parameters{{Name: "max_pages", Value: "0"}},
	}
	p := resolveParams(ctx)
	assert.Equal(t, 0, p.maxPages)
}

// TestInvoke_ZeroMaxPagesIsRejected verifies that Invoke rejects max_pages < 1.
func TestInvoke_ZeroMaxPagesIsRejected(t *testing.T) {
	cap := &Capability{
		crawlFn: func(_ context.Context, _ string, _ invokeParams) ([]crawl.ObservedRequest, error) {
			t.Fatal("crawlFn must not be called when params are invalid")
			return nil, nil
		},
	}
	ctx := capability.ExecutionContext{
		Parameters: capability.Parameters{
			{Name: "max_pages", Value: "0"},
			{Name: "headless", Value: "false"},
		},
	}
	err := cap.Invoke(ctx, capmodel.WebApplication{PrimaryURL: "http://example.com"}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid max_pages")
}

func TestResolveParams_NegativeTimeout(t *testing.T) {
	ctx := capability.ExecutionContext{
		Parameters: capability.Parameters{{Name: "timeout", Value: "-1"}},
	}
	p := resolveParams(ctx)
	assert.Equal(t, -1, p.timeoutSecs)
}

// TestInvoke_NegativeTimeoutIsRejected verifies that Invoke rejects timeout < 1.
func TestInvoke_NegativeTimeoutIsRejected(t *testing.T) {
	cap := &Capability{
		crawlFn: func(_ context.Context, _ string, _ invokeParams) ([]crawl.ObservedRequest, error) {
			t.Fatal("crawlFn must not be called when params are invalid")
			return nil, nil
		},
	}
	ctx := capability.ExecutionContext{
		Parameters: capability.Parameters{
			{Name: "timeout", Value: "-1"},
			{Name: "headless", Value: "false"},
		},
	}
	err := cap.Invoke(ctx, capmodel.WebApplication{PrimaryURL: "http://example.com"}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid timeout")
}

func TestResolveParams_OutOfRangeConfidence(t *testing.T) {
	ctx := capability.ExecutionContext{
		Parameters: capability.Parameters{{Name: "confidence", Value: "2.0"}},
	}
	p := resolveParams(ctx)
	assert.InDelta(t, 2.0, p.confidence, 0.001)
}

// TestInvoke_OutOfRangeConfidenceIsRejected verifies that Invoke rejects
// confidence > 1.0.
func TestInvoke_OutOfRangeConfidenceIsRejected(t *testing.T) {
	cap := &Capability{
		crawlFn: func(_ context.Context, _ string, _ invokeParams) ([]crawl.ObservedRequest, error) {
			t.Fatal("crawlFn must not be called when params are invalid")
			return nil, nil
		},
	}
	ctx := capability.ExecutionContext{
		Parameters: capability.Parameters{
			{Name: "confidence", Value: "2.0"},
			{Name: "headless", Value: "false"},
		},
	}
	err := cap.Invoke(ctx, capmodel.WebApplication{PrimaryURL: "http://example.com"}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid confidence")
}

// ---------------------------------------------------------------------------
// parseHeaderString
// ---------------------------------------------------------------------------

func TestParseHeaderString_SingleHeader(t *testing.T) {
	result := parseHeaderString("Authorization: Bearer token123")
	require.Len(t, result, 1)
	assert.Equal(t, "Bearer token123", result["Authorization"])
}

func TestParseHeaderString_MultipleHeaders(t *testing.T) {
	result := parseHeaderString("X-Token: abc, X-Org: test")
	require.Len(t, result, 2)
	assert.Equal(t, "abc", result["X-Token"])
	assert.Equal(t, "test", result["X-Org"])
}

func TestParseHeaderString_Empty(t *testing.T) {
	result := parseHeaderString("")
	assert.Empty(t, result)
}

func TestParseHeaderString_MalformedEntry(t *testing.T) {
	// Entries without colon are silently ignored.
	result := parseHeaderString("NoColonHere, X-Valid: yes")
	require.Len(t, result, 1)
	assert.Equal(t, "yes", result["X-Valid"])
}

func TestParseHeaderString_ValueWithColon(t *testing.T) {
	// SplitN(..., 2) means the first colon is the separator; rest is the value.
	result := parseHeaderString("Authorization: Bearer foo:bar")
	require.Len(t, result, 1)
	assert.Equal(t, "Bearer foo:bar", result["Authorization"])
}

// ---------------------------------------------------------------------------
// ClassifyProbeGenerate
// ---------------------------------------------------------------------------

func TestClassifyProbeGenerate_EmptyRequests(t *testing.T) {
	ctx := context.Background()
	spec, err := ClassifyProbeGenerate(ctx, nil, "rest", 0.5, true, false)
	require.NoError(t, err)
	// The REST generator returns nil for an empty classified list — this is the
	// documented behavior of OpenAPIGenerator.Generate when no endpoints are
	// present. The pipeline must not error; nil spec is the expected outcome.
	assert.Nil(t, spec)
}

func TestClassifyProbeGenerate_UnsupportedAPIType(t *testing.T) {
	ctx := context.Background()
	_, err := ClassifyProbeGenerate(ctx, nil, "bogus", 0.5, true, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported API type")
}

func TestClassifyProbeGenerate_RespectsDeduplicateFalse(t *testing.T) {
	ctx := context.Background()
	// Duplicate REST requests — with deduplicate=false both should be retained
	// through classification; the generator should still produce a valid spec.
	requests := []crawl.ObservedRequest{
		{Method: "GET", URL: "http://example.com/api/users", Response: crawl.ObservedResponse{StatusCode: 200, ContentType: "application/json", Body: []byte(`[{"id":1}]`)}},
		{Method: "GET", URL: "http://example.com/api/users", Response: crawl.ObservedResponse{StatusCode: 200, ContentType: "application/json", Body: []byte(`[{"id":2}]`)}},
	}
	spec, err := ClassifyProbeGenerate(ctx, requests, "rest", 0.5, false, false)
	require.NoError(t, err)
	require.NotNil(t, spec)
}

func TestClassifyProbeGenerate_DeduplicateTrue(t *testing.T) {
	ctx := context.Background()
	// Same duplicate requests — deduplicate=true should collapse them before
	// generation; result is still a valid spec.
	requests := []crawl.ObservedRequest{
		{Method: "GET", URL: "http://example.com/api/users", Response: crawl.ObservedResponse{StatusCode: 200, ContentType: "application/json", Body: []byte(`[{"id":1}]`)}},
		{Method: "GET", URL: "http://example.com/api/users", Response: crawl.ObservedResponse{StatusCode: 200, ContentType: "application/json", Body: []byte(`[{"id":2}]`)}},
	}
	spec, err := ClassifyProbeGenerate(ctx, requests, "rest", 0.5, true, false)
	require.NoError(t, err)
	require.NotNil(t, spec)
}

// TestClassifyProbeGenerate_AutoDetectsREST exercises the "auto" API type
// detection branch (ClassifyProbeGenerate lines 291-293). With REST-like
// traffic, DetectAPIType should resolve to "rest" and the pipeline should
// produce a non-empty OpenAPI spec.
func TestClassifyProbeGenerate_AutoDetectsREST(t *testing.T) {
	ctx := context.Background()
	requests := []crawl.ObservedRequest{
		{
			Method: "GET",
			URL:    "http://example.com/api/users",
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "application/json",
				Body:        []byte(`[{"id":1,"name":"alice"}]`),
			},
		},
	}
	spec, err := ClassifyProbeGenerate(ctx, requests, "auto", 0.5, true, false)
	require.NoError(t, err)
	assert.NotEmpty(t, spec)
}

// TestClassifyProbeGenerate_GeneratesRESTSpec verifies successful spec generation
// with multiple REST endpoints (exercises the generate.Get + gen.Generate path).
// The spec should contain the "openapi" marker expected for OpenAPI 3.0 output.
func TestClassifyProbeGenerate_GeneratesRESTSpec(t *testing.T) {
	ctx := context.Background()
	requests := []crawl.ObservedRequest{
		{
			Method: "GET",
			URL:    "http://example.com/api/users/42",
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "application/json",
				Body:        []byte(`{"id":42,"name":"alice"}`),
			},
		},
		{
			Method: "POST",
			URL:    "http://example.com/api/users",
			Response: crawl.ObservedResponse{
				StatusCode:  201,
				ContentType: "application/json",
				Body:        []byte(`{"id":43}`),
			},
		},
	}
	spec, err := ClassifyProbeGenerate(ctx, requests, "rest", 0.5, true, false)
	require.NoError(t, err)
	require.NotEmpty(t, spec)
	assert.Contains(t, string(spec), "openapi")
}

// TestClassifyProbeGenerate_ProbeEnabledOnREST exercises the probeEnabled=true
// branch (ClassifyProbeGenerate lines 305-312). A pre-canceled context ensures
// probes fail fast without network calls. probe.RunStrategies preserves the
// original classified endpoints even when strategies error, so the pipeline
// always produces a non-empty spec when classified results are non-empty —
// the canceled context does not cause an early return here.
func TestClassifyProbeGenerate_ProbeEnabledOnREST(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately — probes fail fast, no network calls

	requests := []crawl.ObservedRequest{
		{
			Method: "GET",
			URL:    "http://example.com/api/items",
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "application/json",
				Body:        []byte(`{"id":1}`),
			},
		},
	}
	// probeEnabled=true exercises the probe branch; canceled context keeps the
	// test hermetic. RunStrategies returns classified endpoints even on error, so
	// ClassifyProbeGenerate must succeed and produce a non-empty spec.
	spec, err := ClassifyProbeGenerate(ctx, requests, "rest", 0.5, true, true)
	require.NoError(t, err)
	assert.NotEmpty(t, spec)
}

// TestClassifyProbeGenerate_AllProbesFailed exercises the early-return branch
// (ClassifyProbeGenerate line 310) where enriched is empty and probeErrs is
// non-empty. This requires: no classified endpoints (threshold=1.1 eliminates
// every request) AND probeEnabled=true AND at least one probe error. With an
// empty classified list RunStrategies returns ([], [contextErr]), satisfying
// len(enriched)==0 && len(probeErrs)>0.
func TestClassifyProbeGenerate_AllProbesFailed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-canceled so every probe strategy errors immediately

	requests := []crawl.ObservedRequest{
		{
			Method: "GET",
			URL:    "http://example.com/api/items",
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "application/json",
				Body:        []byte(`{"id":1}`),
			},
		},
	}
	// Threshold above 1.0 means classify.RunClassifiers returns nothing, so
	// classified is empty. probeEnabled=true with canceled ctx → probe errors.
	// Condition: len(enriched)==0 && len(probeErrs)>0 → error returned.
	_, err := ClassifyProbeGenerate(ctx, requests, "rest", 1.1, true, true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "all probes failed")
}

// ---------------------------------------------------------------------------
// probeWSDLDocument
// ---------------------------------------------------------------------------

// TestProbeWSDLDocument_NilContext verifies that passing a nil context does not
// panic. The nil-context guard at capability.go:392-394 replaces nil with
// context.Background() before reaching http.NewRequestWithContext.
// A loopback URL guarantees ValidateProbeURL rejects before any network call.
func TestProbeWSDLDocument_NilContext(t *testing.T) {
	result := probeWSDLDocument(nil, "http://127.0.0.1/service") //nolint:staticcheck // intentionally testing the nil-ctx guard
	assert.Nil(t, result)
}

// TestProbeWSDLDocument_RejectsInvalidOrBlockedURLs verifies that malformed URLs
// and SSRF-dangerous addresses are rejected before any HTTP round-trip.
func TestProbeWSDLDocument_RejectsInvalidOrBlockedURLs(t *testing.T) {
	cases := []struct {
		name string
		url  string
	}{
		{"malformed", "://bad"},
		{"non-http-scheme", "ftp://example.com/service"},
		{"loopback-blocked", "http://127.0.0.1/service"},
		{"link-local-blocked", "http://169.254.169.254/service"},
		{"rfc1918-blocked", "http://10.0.0.1/service"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := probeWSDLDocument(context.Background(), tc.url)
			assert.Nil(t, result)
		})
	}
}

// TestProbeWSDLDocument_CanceledContext verifies that a pre-canceled context
// does not panic and returns nil. A loopback URL short-circuits at
// ValidateProbeURL so this test is hermetic (no network calls required).
func TestProbeWSDLDocument_CanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-canceled

	result := probeWSDLDocument(ctx, "http://127.0.0.1/service")
	assert.Nil(t, result)
}

// TestProbeWSDLDocument_Success exercises the full happy-path through
// probeWSDLDocument using an httptest.Server on loopback. Both SSRF seams
// are replaced for the duration of the test so the loopback dial succeeds.
func TestProbeWSDLDocument_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(validWSDL))
	}))
	t.Cleanup(srv.Close)

	orig := validateProbeURLFunc
	validateProbeURLFunc = func(_ string) error { return nil }
	t.Cleanup(func() { validateProbeURLFunc = orig })

	origDial := dialContextForWSDLProbe
	dialContextForWSDLProbe = (&net.Dialer{}).DialContext
	t.Cleanup(func() { dialContextForWSDLProbe = origDial })

	result := probeWSDLDocument(context.Background(), srv.URL+"/service")
	require.Equal(t, []byte(validWSDL), result)
}

// TestProbeWSDLDocument_3xxRejected verifies that a 302 redirect response is
// rejected. probeWSDLDocument sets CheckRedirect: ErrUseLastResponse so the
// redirect is not followed; isRejectedWSDLStatus(302) then returns true and
// nil is returned — pinning the combination of both behaviors together.
func TestProbeWSDLDocument_3xxRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.com/elsewhere", http.StatusFound)
	}))
	t.Cleanup(srv.Close)

	orig := validateProbeURLFunc
	validateProbeURLFunc = func(_ string) error { return nil }
	t.Cleanup(func() { validateProbeURLFunc = orig })

	origDial := dialContextForWSDLProbe
	dialContextForWSDLProbe = (&net.Dialer{}).DialContext
	t.Cleanup(func() { dialContextForWSDLProbe = origDial })

	result := probeWSDLDocument(context.Background(), srv.URL+"/service")
	assert.Nil(t, result)
}

// ---------------------------------------------------------------------------
// isRejectedWSDLStatus
// ---------------------------------------------------------------------------

func TestIsRejectedWSDLStatus(t *testing.T) {
	tests := []struct {
		name   string
		status int
		want   bool
	}{
		{"200 OK", 200, false},
		{"201 Created", 201, false},
		{"204 No Content", 204, false},
		{"299", 299, false},
		{"300 Multiple Choices", 300, true},
		{"301 Moved", 301, true},
		{"302 Found", 302, true},
		{"307 Temporary Redirect", 307, true},
		{"308 Permanent Redirect", 308, true},
		{"399", 399, true},
		{"400 Bad Request", 400, true},
		{"401 Unauthorized", 401, true},
		{"403 Forbidden", 403, true},
		{"404 Not Found", 404, true},
		{"500 Internal Server Error", 500, true},
		{"503 Service Unavailable", 503, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isRejectedWSDLStatus(tt.status))
		})
	}
}

// ---------------------------------------------------------------------------
// isAcceptableWSDLContentType
// ---------------------------------------------------------------------------

func TestIsAcceptableWSDLContentType(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   bool
	}{
		{"empty", "", true},
		{"text/xml", "text/xml", true},
		{"application/xml", "application/xml", true},
		{"application/wsdl+xml", "application/wsdl+xml", true},
		{"text/xml with charset", "text/xml; charset=utf-8", true},
		{"application/xml with charset", "application/xml; charset=UTF-8", true},
		{"uppercase", "TEXT/XML", true},
		{"mixed case with whitespace", "  Application/XML  ", true},
		{"text/html", "text/html", false},
		{"application/json", "application/json", false},
		{"text/plain", "text/plain", false},
		{"application/octet-stream", "application/octet-stream", false},
		{"html with charset", "text/html; charset=utf-8", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isAcceptableWSDLContentType(tt.header))
		})
	}
}

// ---------------------------------------------------------------------------
// Group A — TEST-004 (nit): parseHeaderString edge cases
// ---------------------------------------------------------------------------

// TestParseHeaderString_WhitespaceOnlyInteriorEntry exercises the
// `if hdr == "" { continue }` branch in parseHeaderString
// (capability.go:528-530). After trimming, the interior blank segment
// produced by ", ," becomes an empty string and must be skipped so that
// only the two valid headers survive.
func TestParseHeaderString_WhitespaceOnlyInteriorEntry(t *testing.T) {
	result := parseHeaderString("X-A: 1, , X-B: 2")
	require.Len(t, result, 2)
	assert.Equal(t, "1", result["X-A"])
	assert.Equal(t, "2", result["X-B"])
}

// TestParseHeaderString_EmptyValue exercises the path through the
// SplitN branch (capability.go:531-533) where the value after the colon
// is absent, resulting in an empty string being stored. This documents
// that an entry like "X-Empty:" is accepted and stored as an empty value.
func TestParseHeaderString_EmptyValue(t *testing.T) {
	result := parseHeaderString("X-Empty:, X-Set: ok")
	require.Len(t, result, 2)
	assert.Equal(t, "", result["X-Empty"])
	assert.Equal(t, "ok", result["X-Set"])
}

// ---------------------------------------------------------------------------
// Group B — TEST-003 (medium): decodeWSDLResponse table-driven tests
// ---------------------------------------------------------------------------

// validWSDL is a minimal WSDL document that satisfies wsdlgen.ParseWSDL.
// Copied from pkg/generate/wsdl/generator_test.go:179-183.
const validWSDL = `<definitions name="Svc" xmlns="http://schemas.xmlsoap.org/wsdl/">
  <message name="Msg"><part name="p" type="xsd:string"/></message>
  <portType name="PT"><operation name="Op"><input message="tns:Msg"/></operation></portType>
</definitions>`

// makeWSDLResponse builds an *http.Response in-memory for use with
// decodeWSDLResponse, which is a pure function and needs no httptest.Server.
func makeWSDLResponse(status int, contentType string, body []byte) *http.Response {
	h := http.Header{}
	if contentType != "" {
		h.Set("Content-Type", contentType)
	}
	return &http.Response{
		StatusCode: status,
		Header:     h,
		Body:       io.NopCloser(bytes.NewReader(body)),
	}
}

// TestDecodeWSDLResponse_ValidWSDL exercises the happy path through all gates
// in decodeWSDLResponse (capability.go:507-522): 200 status passes the status
// gate, text/xml passes the content-type gate, and validWSDL passes ParseWSDL.
func TestDecodeWSDLResponse_ValidWSDL(t *testing.T) {
	resp := makeWSDLResponse(200, "text/xml", []byte(validWSDL))
	got := decodeWSDLResponse(resp)
	assert.Equal(t, []byte(validWSDL), got)
}

// TestDecodeWSDLResponse_RejectedContentType exercises the content-type gate
// (capability.go:511-513). Even though the body is a valid WSDL, text/html
// is rejected before the body is read.
func TestDecodeWSDLResponse_RejectedContentType(t *testing.T) {
	resp := makeWSDLResponse(200, "text/html", []byte(validWSDL))
	got := decodeWSDLResponse(resp)
	assert.Nil(t, got)
}

// TestDecodeWSDLResponse_RejectedStatus exercises the status gate
// (capability.go:508-510). The status check fires before content-type,
// so all non-2xx codes return nil regardless of body content.
func TestDecodeWSDLResponse_RejectedStatus(t *testing.T) {
	cases := []struct {
		name   string
		status int
	}{
		{"301 redirect", 301},
		{"404 not found", 404},
		{"500 server error", 500},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			resp := makeWSDLResponse(tt.status, "text/xml", []byte(validWSDL))
			got := decodeWSDLResponse(resp)
			assert.Nil(t, got)
		})
	}
}

// TestDecodeWSDLResponse_UnparseableBody exercises the ParseWSDL gate
// (capability.go:518-520). Status and content-type pass, but the body is
// not valid XML so wsdlgen.ParseWSDL rejects it and nil is returned.
func TestDecodeWSDLResponse_UnparseableBody(t *testing.T) {
	resp := makeWSDLResponse(200, "text/xml", []byte("not-valid-xml"))
	got := decodeWSDLResponse(resp)
	assert.Nil(t, got)
}

// TestDecodeWSDLResponse_EmptyContentTypeAccepted exercises the empty-string
// branch inside isAcceptableWSDLContentType (capability.go:444) when called
// end-to-end through decodeWSDLResponse. An empty Content-Type is intentionally
// permitted because some WSDL endpoints omit it; the parser is then the authority.
func TestDecodeWSDLResponse_EmptyContentTypeAccepted(t *testing.T) {
	resp := makeWSDLResponse(200, "", []byte(validWSDL))
	got := decodeWSDLResponse(resp)
	assert.Equal(t, []byte(validWSDL), got)
}

// errReader is a minimal io.Reader that always returns an error on the first
// Read call. Used to exercise the io.ReadAll error branch in decodeWSDLResponse.
type errReader struct{}

func (errReader) Read(_ []byte) (int, error) { return 0, errors.New("read failure") }

// TestDecodeWSDLResponse_BodyReadError exercises the io.ReadAll error branch
// (capability.go:515-517) that guards against mid-read body errors such as a
// TLS abort after headers or a truncated chunked response.
func TestDecodeWSDLResponse_BodyReadError(t *testing.T) {
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/xml"}},
		Body:       io.NopCloser(errReader{}),
	}
	got := decodeWSDLResponse(resp)
	assert.Nil(t, got)
}

// ---------------------------------------------------------------------------
// Group C — TEST-001: Invoke end-to-end via stubbed pipeline
// ---------------------------------------------------------------------------

// captureEmitter returns a *capmodel.WebApplication pointer that is populated
// when the returned Emitter is called, and an Emitter that enforces that it
// receives exactly one WebApplication model.
func captureEmitter(t *testing.T) (*capmodel.WebApplication, capability.Emitter) {
	t.Helper()
	var captured capmodel.WebApplication
	emit := capability.EmitterFunc(func(models ...any) error {
		require.Len(t, models, 1, "Emit should be called with exactly one model")
		w, ok := models[0].(capmodel.WebApplication)
		require.True(t, ok, "emitted model must be capmodel.WebApplication, got %T", models[0])
		captured = w
		return nil
	})
	return &captured, emit
}

// TestInvoke_EmitsWebApplicationPreservingInputFields is the regression guard
// for prior-MED-3: Invoke must preserve all input WebApplication fields and
// overlay only OpenAPI. The stubbed crawlFn returns a single REST-like request
// so the pipeline produces a non-empty OpenAPI spec.
func TestInvoke_EmitsWebApplicationPreservingInputFields(t *testing.T) {
	input := capmodel.WebApplication{
		PrimaryURL: "http://example.com",
		URLs:       []string{"http://example.com", "http://example.com/page"},
		Name:       "example app",
		Seed:       true,
	}

	cap := &Capability{
		crawlFn: func(_ context.Context, _ string, _ invokeParams) ([]crawl.ObservedRequest, error) {
			return []crawl.ObservedRequest{
				{
					Method: "GET",
					URL:    "http://example.com/api/users",
					Response: crawl.ObservedResponse{
						StatusCode:  200,
						ContentType: "application/json",
						Body:        []byte(`[{"id":1,"name":"alice"}]`),
					},
				},
			}, nil
		},
		wsdlProbeFn: func(_ context.Context, _ string) []byte { return nil },
	}

	ctx := capability.ExecutionContext{
		Parameters: capability.Parameters{
			{Name: "headless", Value: "false"},
			{Name: "probe", Value: "false"},
			{Name: "api_type", Value: "rest"},
		},
	}

	captured, emitter := captureEmitter(t)
	err := cap.Invoke(ctx, input, emitter)
	require.NoError(t, err)

	assert.Equal(t, input.PrimaryURL, captured.PrimaryURL)
	assert.Equal(t, input.URLs, captured.URLs)
	assert.Equal(t, input.Name, captured.Name)
	assert.Equal(t, input.Seed, captured.Seed)
	assert.NotEmpty(t, captured.OpenAPI)
	assert.True(t, strings.Contains(captured.OpenAPI, "openapi"),
		"expected OpenAPI 3.0 marker in generated spec, got: %s", captured.OpenAPI)
}

// TestInvoke_WSDLProbeSynthesizesRequest exercises the WSDL probe branch in
// Invoke (capability.go:283-296): when wsdlProbeFn returns non-nil bytes the
// resolved API type becomes "wsdl" and a synthetic ObservedRequest carrying
// the WSDL body is injected into the pipeline.
func TestInvoke_WSDLProbeSynthesizesRequest(t *testing.T) {
	cap := &Capability{
		crawlFn: func(_ context.Context, _ string, _ invokeParams) ([]crawl.ObservedRequest, error) {
			return nil, nil // no crawl results
		},
		wsdlProbeFn: func(_ context.Context, _ string) []byte {
			return []byte(validWSDL)
		},
	}

	input := capmodel.WebApplication{PrimaryURL: "http://example.com"}
	ctx := capability.ExecutionContext{
		Parameters: capability.Parameters{
			{Name: "headless", Value: "false"},
			{Name: "probe", Value: "false"},
			{Name: "api_type", Value: "auto"},
		},
	}

	captured, emitter := captureEmitter(t)
	err := cap.Invoke(ctx, input, emitter)
	require.NoError(t, err)
	assert.NotEmpty(t, captured.OpenAPI)
	assert.True(t,
		strings.Contains(strings.ToLower(captured.OpenAPI), "wsdl") ||
			strings.Contains(captured.OpenAPI, "<definitions"),
		"expected WSDL content in generated spec, got: %s", captured.OpenAPI)
}

// TestInvoke_CrawlErrorPropagates verifies that a crawl error is wrapped and
// returned from Invoke without calling the emitter.
func TestInvoke_CrawlErrorPropagates(t *testing.T) {
	cap := &Capability{
		crawlFn: func(_ context.Context, _ string, _ invokeParams) ([]crawl.ObservedRequest, error) {
			return nil, errors.New("boom")
		},
	}

	input := capmodel.WebApplication{PrimaryURL: "http://example.com"}
	ctx := capability.ExecutionContext{
		Parameters: capability.Parameters{
			{Name: "headless", Value: "false"},
		},
	}

	noEmit := capability.EmitterFunc(func(models ...any) error {
		t.Fatal("Emit should not be called on crawl error")
		return nil
	})

	err := cap.Invoke(ctx, input, noEmit)
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "crawl"),
		"expected error to mention 'crawl', got: %s", err.Error())
	assert.True(t, strings.Contains(err.Error(), "boom"),
		"expected error to contain original message 'boom', got: %s", err.Error())
}

// ---------------------------------------------------------------------------
// Group D — TEST-002: context lifecycle regression guard
// ---------------------------------------------------------------------------

// TestInvoke_GenPhaseUsesFreshContext is the regression guard for prior-MED-2:
// Invoke must create two independent context.WithTimeout calls — one for the
// crawl phase and a fresh one for the generate phase. If a future refactor
// collapses them back into a single context, genDeadline == crawlDeadline, so
// genDeadline.After(crawlDeadline) returns false and the assertion fails,
// catching the regression.
//
// api_type=auto is used so that wsdlProbeFn is invoked (SEC-BE-002 gates the
// probe to "auto" only), giving us a hook to capture the generate-phase context
// deadline without any additional plumbing.
func TestInvoke_GenPhaseUsesFreshContext(t *testing.T) {
	var (
		crawlDeadline   time.Time
		crawlDeadlineOK bool
		genDeadline     time.Time
		genDeadlineOK   bool
	)

	restReq := crawl.ObservedRequest{
		Method: "GET",
		URL:    "http://example.com/api/items",
		Response: crawl.ObservedResponse{
			StatusCode:  200,
			ContentType: "application/json",
			Body:        []byte(`[{"id":1}]`),
		},
	}

	cap := &Capability{
		crawlFn: func(ctx context.Context, _ string, _ invokeParams) ([]crawl.ObservedRequest, error) {
			crawlDeadline, crawlDeadlineOK = ctx.Deadline()
			time.Sleep(50 * time.Millisecond) // simulate some crawl work
			return []crawl.ObservedRequest{restReq}, nil
		},
		wsdlProbeFn: func(ctx context.Context, _ string) []byte {
			genDeadline, genDeadlineOK = ctx.Deadline()
			return nil
		},
	}

	input := capmodel.WebApplication{PrimaryURL: "http://example.com"}
	ctx := capability.ExecutionContext{
		Parameters: capability.Parameters{
			{Name: "timeout", Value: "2"}, // 2-second budget
			{Name: "headless", Value: "false"},
			{Name: "probe", Value: "false"},
			{Name: "api_type", Value: "auto"}, // "auto" so wsdlProbeFn is invoked to capture genCtx deadline
		},
	}

	captured, emitter := captureEmitter(t)
	err := cap.Invoke(ctx, input, emitter)
	require.NoError(t, err)
	_ = captured

	assert.True(t, crawlDeadlineOK, "crawlCtx must have a deadline")
	assert.True(t, genDeadlineOK, "genCtx must have a deadline")
	assert.True(t, genDeadline.After(crawlDeadline),
		"genDeadline %v should be later than crawlDeadline %v — the two contexts must be independent (prior-MED-2 fix)",
		genDeadline, crawlDeadline)
}

// ---------------------------------------------------------------------------
// TEST-004: WSDL probe overrides api_type=rest (SEC-BE-002 regression anchor)
// ---------------------------------------------------------------------------

// TestInvoke_RESTAPITypeSkipsWSDLProbe verifies that the WSDL probe is NOT invoked
// when api_type=rest is requested (SEC-BE-002 fix). The operator's explicit choice
// must not be overridden by a server-controlled response. The emitted spec must be
// OpenAPI, not WSDL.
func TestInvoke_RESTAPITypeSkipsWSDLProbe(t *testing.T) {
	wsdlProbeCalled := false

	cap := &Capability{
		crawlFn: func(_ context.Context, _ string, _ invokeParams) ([]crawl.ObservedRequest, error) {
			return []crawl.ObservedRequest{restRequest()}, nil
		},
		wsdlProbeFn: func(_ context.Context, _ string) []byte {
			wsdlProbeCalled = true
			return []byte(validWSDL)
		},
	}

	input := capmodel.WebApplication{PrimaryURL: "http://example.com"}
	ctx := capability.ExecutionContext{
		Parameters: capability.Parameters{
			{Name: "headless", Value: "false"},
			{Name: "probe", Value: "false"},
			{Name: "api_type", Value: "rest"},
		},
	}

	captured, emitter := captureEmitter(t)
	err := cap.Invoke(ctx, input, emitter)
	require.NoError(t, err)
	assert.NotEmpty(t, captured.OpenAPI)
	assert.False(t, wsdlProbeCalled, "wsdlProbeFn must not be called when api_type=rest")
	assert.True(t, strings.Contains(captured.OpenAPI, "openapi"),
		"expected OpenAPI spec when api_type=rest, got: %s", captured.OpenAPI)
	assert.False(t, strings.Contains(captured.OpenAPI, "<definitions"),
		"expected no WSDL content when api_type=rest, got: %s", captured.OpenAPI)
}

// ---------------------------------------------------------------------------
// TEST-003: api_type=graphql skips WSDL probe
// ---------------------------------------------------------------------------

// TestInvoke_GraphQLAPITypeSkipsWSDLProbe verifies that the api_type=graphql branch
// never invokes wsdlProbeFn. The WSDL probe is guarded at capability.go:283 by
// resolvedAPIType == "auto" || resolvedAPIType == "wsdl" || resolvedAPIType == "rest",
// which excludes "graphql". The test fails if wsdlProbeCalled is true after Invoke.
// The emitted spec must contain the inferred-SDL marker "# Inferred from observed traffic"
// written by pkg/generate/graphql/infer.go:85 when no introspection schema is present.
func TestInvoke_GraphQLAPITypeSkipsWSDLProbe(t *testing.T) {
	wsdlProbeCalled := false

	cap := &Capability{
		crawlFn: func(_ context.Context, _ string, _ invokeParams) ([]crawl.ObservedRequest, error) {
			return []crawl.ObservedRequest{graphqlRequest(), graphqlRequest()}, nil
		},
		wsdlProbeFn: func(_ context.Context, _ string) []byte {
			wsdlProbeCalled = true
			return nil
		},
	}

	input := capmodel.WebApplication{PrimaryURL: "http://example.com"}
	ctx := capability.ExecutionContext{
		Parameters: capability.Parameters{
			{Name: "headless", Value: "false"},
			{Name: "probe", Value: "false"},
			{Name: "api_type", Value: "graphql"},
		},
	}

	captured, emitter := captureEmitter(t)
	err := cap.Invoke(ctx, input, emitter)
	require.NoError(t, err)
	assert.NotEmpty(t, captured.OpenAPI)
	assert.Contains(t, captured.OpenAPI, "# Inferred from observed traffic",
		"expected GraphQL SDL inferred-from-traffic marker in spec, got: %s", captured.OpenAPI)
	assert.False(t, wsdlProbeCalled, "wsdlProbeFn must not be called when api_type=graphql")
}

// ---------------------------------------------------------------------------
// TEST-005: generate-spec error propagates with correct prefix
// ---------------------------------------------------------------------------

// TestInvoke_GenerateErrorPropagates mirrors TestInvoke_CrawlErrorPropagates but
// for the generate-spec path. Setting api_type=bogus forces ClassifyProbeGenerate
// to return "unsupported API type: \"bogus\"" (capability.go:333-335).
// The WSDL probe branch at capability.go:283 is skipped because "bogus" is not
// "auto", "wsdl", or "rest". The emitter must never be called.
func TestInvoke_GenerateErrorPropagates(t *testing.T) {
	cap := &Capability{
		crawlFn: func(_ context.Context, _ string, _ invokeParams) ([]crawl.ObservedRequest, error) {
			return []crawl.ObservedRequest{restRequest()}, nil
		},
	}

	input := capmodel.WebApplication{PrimaryURL: "http://example.com"}
	ctx := capability.ExecutionContext{
		Parameters: capability.Parameters{
			{Name: "headless", Value: "false"},
			{Name: "probe", Value: "false"},
			{Name: "api_type", Value: "bogus"},
		},
	}

	noEmit := capability.EmitterFunc(func(models ...any) error {
		t.Fatal("Emit should not be called on generate error")
		return nil
	})

	err := cap.Invoke(ctx, input, noEmit)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "generate spec",
		"expected error to mention 'generate spec', got: %s", err.Error())
	assert.Contains(t, err.Error(), "unsupported API type",
		"expected error to contain 'unsupported API type', got: %s", err.Error())
}

// ---------------------------------------------------------------------------
// TEST-002: buildCrawlerOptions parameter wiring + runRealCrawl non-headless
// ---------------------------------------------------------------------------

// TestBuildCrawlerOptions_ParameterWiring verifies that buildCrawlerOptions maps
// every invokeParams field to the correct crawl.CrawlerOptions field. This test
// is hermetic -- no browser is launched and no network calls are made.
func TestBuildCrawlerOptions_ParameterWiring(t *testing.T) {
	p := invokeParams{
		depth:       7,
		maxPages:    250,
		timeoutSecs: 120,
		headless:    true,
		scope:       "same-domain",
		headers:     map[string]string{"X-Test": "1"},
		proxy:       "http://127.0.0.1:8080",
	}

	opts := buildCrawlerOptions(p, nil)

	assert.Equal(t, 7, opts.Depth)
	assert.Equal(t, 250, opts.MaxPages)
	assert.Equal(t, 120*time.Second, opts.Timeout)
	assert.True(t, opts.Headless)
	assert.Equal(t, "same-domain", opts.Scope)
	assert.Equal(t, map[string]string{"X-Test": "1"}, opts.Headers)
	assert.Equal(t, "http://127.0.0.1:8080", opts.Proxy)
	assert.Nil(t, opts.BrowserMgr)
	assert.NotNil(t, opts.Stderr, "Stderr should be io.Discard (non-nil)")
}

// TestRunRealCrawl_NonHeadlessReturnsErrorOnCanceledContext verifies that
// runRealCrawl propagates a canceled context without launching a browser when
// headless=false. The early-return at pkg/crawl/crawler.go:100-105 checks
// ctx.Err() before any engine setup, so this test is hermetic and exercises
// the headless=false branch + crawl.NewCrawler construction.
func TestRunRealCrawl_NonHeadlessReturnsErrorOnCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel before passing to runRealCrawl

	p := invokeParams{
		depth:       1,
		maxPages:    1,
		timeoutSecs: 1,
		headless:    false,
		scope:       "same-origin",
	}

	requests, err := runRealCrawl(ctx, "http://example.com", p)
	require.ErrorIs(t, err, context.Canceled)
	assert.Nil(t, requests, "expected nil requests when context is already canceled")
}

// ---------------------------------------------------------------------------
// TestInvokeParams_Validate — positive + negative boundary cases
// ---------------------------------------------------------------------------

// TestInvokeParams_Validate exercises invokeParams.validate() directly to pin
// the exact boundary conditions accepted and rejected. This guards against
// off-by-one regressions (e.g. < 1 flipped to <= 1) that would not be caught
// by the existing TestInvoke_*IsRejected tests because those tests only cover
// the negative path through Invoke's wiring, not validate() boundaries.
func TestInvokeParams_Validate(t *testing.T) {
	cases := []struct {
		name    string
		p       invokeParams
		wantErr string // empty = expect no error
	}{
		// Positive boundary cases — these MUST be accepted.
		{"depth=1 accepted", invokeParams{depth: 1, maxPages: 1, timeoutSecs: 1, confidence: 0.5}, ""},
		{"maxPages=1 accepted", invokeParams{depth: 5, maxPages: 1, timeoutSecs: 1, confidence: 0.5}, ""},
		{"timeoutSecs=1 accepted", invokeParams{depth: 5, maxPages: 5, timeoutSecs: 1, confidence: 0.5}, ""},
		{"confidence=0.0 accepted", invokeParams{depth: 5, maxPages: 5, timeoutSecs: 5, confidence: 0.0}, ""},
		{"confidence=1.0 accepted", invokeParams{depth: 5, maxPages: 5, timeoutSecs: 5, confidence: 1.0}, ""},
		// Negative boundary cases — these MUST be rejected.
		{"depth=0 rejected", invokeParams{depth: 0, maxPages: 5, timeoutSecs: 5, confidence: 0.5}, "invalid depth"},
		{"maxPages=0 rejected", invokeParams{depth: 5, maxPages: 0, timeoutSecs: 5, confidence: 0.5}, "invalid max_pages"},
		{"timeoutSecs=0 rejected", invokeParams{depth: 5, maxPages: 5, timeoutSecs: 0, confidence: 0.5}, "invalid timeout"},
		{"confidence=-0.1 rejected", invokeParams{depth: 5, maxPages: 5, timeoutSecs: 5, confidence: -0.1}, "invalid confidence"},
		{"confidence=1.1 rejected", invokeParams{depth: 5, maxPages: 5, timeoutSecs: 5, confidence: 1.1}, "invalid confidence"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.p.validate()
			if tc.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestResolveAPITypeWithWSDLProbe_* — auto+nil branch and non-auto fast-path
// ---------------------------------------------------------------------------

// TestResolveAPITypeWithWSDLProbe_AutoButProbeReturnsNil verifies that when
// apiType=="auto" and the probe function returns nil, the resolved type stays
// "auto" and no synthetic request is produced. This branch was previously
// uncovered.
func TestResolveAPITypeWithWSDLProbe_AutoButProbeReturnsNil(t *testing.T) {
	probeCalled := false
	probeFn := func(_ context.Context, _ string) []byte {
		probeCalled = true
		return nil
	}
	apiType, syntheticReq := resolveAPITypeWithWSDLProbe(
		context.Background(), "auto", "http://example.com", probeFn,
	)
	assert.True(t, probeCalled, "probeFn must be invoked when apiType=auto")
	assert.Equal(t, "auto", apiType, "apiType must remain 'auto' when probe returns nil")
	assert.Nil(t, syntheticReq, "no synthetic request when probe returns nil")
}

// TestResolveAPITypeWithWSDLProbe_NonAutoSkipsProbe verifies that any apiType
// other than "auto" causes probeFn to be skipped entirely and the original
// apiType is returned unchanged with no synthetic request.
func TestResolveAPITypeWithWSDLProbe_NonAutoSkipsProbe(t *testing.T) {
	for _, apiType := range []string{"rest", "graphql", "wsdl", "anything"} {
		t.Run(apiType, func(t *testing.T) {
			probeCalled := false
			gotType, syntheticReq := resolveAPITypeWithWSDLProbe(
				context.Background(), apiType, "http://example.com",
				func(_ context.Context, _ string) []byte {
					probeCalled = true
					return nil
				},
			)
			assert.False(t, probeCalled, "probeFn must not be invoked for apiType=%s", apiType)
			assert.Equal(t, apiType, gotType)
			assert.Nil(t, syntheticReq)
		})
	}
}

// ---------------------------------------------------------------------------
// TestBuildWSDLProbeURL — pin the SEC-BE-003/SEC-BE-004 URL-building contract
// ---------------------------------------------------------------------------

// TestBuildWSDLProbeURL pins the exact output of buildWSDLProbeURL for a range
// of inputs. The implementation sets RawQuery to the bare flag "wsdl" (no "=")
// when the query is empty, or appends "&wsdl" to the existing raw query string
// verbatim, preserving key order without re-encoding.
func TestBuildWSDLProbeURL(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"empty query gets wsdl flag", "https://example.com/svc", "https://example.com/svc?wsdl", false},
		{"existing query preserved", "https://example.com/svc?token=abc", "https://example.com/svc?token=abc&wsdl", false},
		{"existing wsdl key appended", "https://example.com/svc?wsdl=old", "https://example.com/svc?wsdl=old&wsdl", false},
		{"path preserved", "https://example.com/a/b/c", "https://example.com/a/b/c?wsdl", false},
		{"port preserved", "https://example.com:8443/svc", "https://example.com:8443/svc?wsdl", false},
		{"malformed input rejected", "://bad", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := buildWSDLProbeURL(tc.input)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// ---------------------------------------------------------------------------
// TestParseHeaderString_DropsCRLFAndNUL + TestHeaderValueIsSafe — SEC-BE-005
// ---------------------------------------------------------------------------

// TestParseHeaderString_DropsCRLFAndNUL is the regression guard for SEC-BE-005.
// The reviewer explicitly requested a test demonstrating that CR, LF, and NUL
// bytes in header keys or values cause the entire entry to be silently dropped.
// Expected values were verified empirically against the production implementation.
func TestParseHeaderString_DropsCRLFAndNUL(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want map[string]string
	}{
		{
			"CR in value dropped",
			"X-Bad: foo\rInjected: yes, X-Good: ok",
			map[string]string{"X-Good": "ok"},
		},
		{
			"LF in value dropped",
			"X-Bad: foo\nInjected: yes, X-Good: ok",
			map[string]string{"X-Good": "ok"},
		},
		{
			"CRLF in value dropped",
			"X-Bad: foo\r\nInjected: yes, X-Good: ok",
			map[string]string{"X-Good": "ok"},
		},
		{
			"NUL in value dropped",
			"X-Bad: foo\x00bar, X-Good: ok",
			map[string]string{"X-Good": "ok"},
		},
		{
			"CR in key dropped",
			"X-Bad\rInjected: yes, X-Good: ok",
			map[string]string{"X-Good": "ok"},
		},
		{
			"LF in key dropped",
			"X-Bad\nInjected: yes, X-Good: ok",
			map[string]string{"X-Good": "ok"},
		},
		{
			"NUL in key dropped",
			"X-Bad\x00Injected: yes, X-Good: ok",
			map[string]string{"X-Good": "ok"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseHeaderString(tc.raw)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestHeaderValueIsSafe directly exercises the headerValueIsSafe predicate that
// backs the SEC-BE-005 filter. A future regression that removes or inverts this
// guard would cause TestParseHeaderString_DropsCRLFAndNUL to fail, but
// TestHeaderValueIsSafe pinpoints the exact predicate that broke.
func TestHeaderValueIsSafe(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"plain ascii", "Bearer abc123", true},
		{"empty", "", true},
		{"with space", "Bearer foo bar", true},
		{"with colon (allowed in value)", "Bearer foo:bar", true},
		{"contains CR", "foo\rbar", false},
		{"contains LF", "foo\nbar", false},
		{"contains CRLF", "foo\r\nbar", false},
		{"contains NUL", "foo\x00bar", false},
		{"only CR", "\r", false},
		{"only LF", "\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, headerValueIsSafe(tc.in))
		})
	}
}
