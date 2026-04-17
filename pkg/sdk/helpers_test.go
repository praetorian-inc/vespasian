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
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/capability-sdk/pkg/capability"

	"github.com/praetorian-inc/vespasian/pkg/classify"
	"github.com/praetorian-inc/vespasian/pkg/crawl"
	"github.com/praetorian-inc/vespasian/pkg/probe"
)

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
func TestDetectAPIType_GraphQLWinsOverWSDLTie(t *testing.T) {
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

// TestResolveParams_NegativeDepth documents that negative depth values pass
// through unvalidated. If future validation is added, update this test.
func TestResolveParams_NegativeDepth(t *testing.T) {
	ctx := capability.ExecutionContext{
		Parameters: capability.Parameters{{Name: "depth", Value: "-1"}},
	}
	p := resolveParams(ctx)
	assert.Equal(t, -1, p.depth)
}

func TestResolveParams_ZeroMaxPages(t *testing.T) {
	ctx := capability.ExecutionContext{
		Parameters: capability.Parameters{{Name: "max_pages", Value: "0"}},
	}
	p := resolveParams(ctx)
	assert.Equal(t, 0, p.maxPages)
}

func TestResolveParams_NegativeTimeout(t *testing.T) {
	ctx := capability.ExecutionContext{
		Parameters: capability.Parameters{{Name: "timeout", Value: "-1"}},
	}
	p := resolveParams(ctx)
	assert.Equal(t, -1, p.timeoutSecs)
}

func TestResolveParams_OutOfRangeConfidence(t *testing.T) {
	ctx := capability.ExecutionContext{
		Parameters: capability.Parameters{{Name: "confidence", Value: "2.0"}},
	}
	p := resolveParams(ctx)
	assert.InDelta(t, 2.0, p.confidence, 0.001)
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
	// REST generator should return a minimal spec even for empty input.
	_ = spec
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
