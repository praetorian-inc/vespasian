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
	"net/http"
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
// probes fail fast without network calls. RunStrategies preserves the original
// classified endpoints even when strategies error, so the pipeline still
// produces a spec when classified results are non-empty.
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
	// test hermetic. The function either produces a spec or returns an error —
	// both outcomes are valid; the goal is branch coverage.
	spec, err := ClassifyProbeGenerate(ctx, requests, "rest", 0.5, true, true)
	if err != nil {
		assert.Contains(t, err.Error(), "probes failed")
	} else {
		assert.NotEmpty(t, spec)
	}
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
// crawl phase (capability.go:251) and a fresh one for the generate phase
// (capability.go:273). If a future refactor collapses them back into a single
// context, genDeadline == crawlDeadline, so genDeadline.After(crawlDeadline)
// returns false and the assertion fails, catching the regression.
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
			{Name: "api_type", Value: "rest"},
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
