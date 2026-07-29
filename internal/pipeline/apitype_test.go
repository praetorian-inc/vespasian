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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/vespasian/internal/pipeline"
	"github.com/praetorian-inc/vespasian/pkg/classify"
	"github.com/praetorian-inc/vespasian/pkg/crawl"
	"github.com/praetorian-inc/vespasian/pkg/probe"
)

// ---------------------------------------------------------------------------
// TEST-002: StrategiesForType — pin the branch contract
// ---------------------------------------------------------------------------

func TestStrategiesForType(t *testing.T) {
	cfg := probe.DefaultConfig()

	tests := []struct {
		name        string
		apiType     string
		wantLen     int
		checkFirst  func(t *testing.T, s probe.ProbeStrategy)
		checkSecond func(t *testing.T, s probe.ProbeStrategy)
	}{
		{
			name:    "WSDL returns one WSDLProbe",
			apiType: pipeline.APITypeWSDL,
			wantLen: 1,
			checkFirst: func(t *testing.T, s probe.ProbeStrategy) {
				t.Helper()
				_, ok := s.(*probe.WSDLProbe)
				assert.True(t, ok, "expected *probe.WSDLProbe, got %T", s)
			},
		},
		{
			name:    "GraphQL returns one GraphQLProbe",
			apiType: pipeline.APITypeGraphQL,
			wantLen: 1,
			checkFirst: func(t *testing.T, s probe.ProbeStrategy) {
				t.Helper()
				_, ok := s.(*probe.GraphQLProbe)
				assert.True(t, ok, "expected *probe.GraphQLProbe, got %T", s)
			},
		},
		{
			name:    "gRPC returns GRPCProbe + GRPCGatewayProbe in priority order",
			apiType: pipeline.APITypeGRPC,
			wantLen: 2,
			checkFirst: func(t *testing.T, s probe.ProbeStrategy) {
				t.Helper()
				_, ok := s.(*probe.GRPCProbe)
				assert.True(t, ok, "expected first strategy to be *probe.GRPCProbe (reflection, richest), got %T", s)
			},
			checkSecond: func(t *testing.T, s probe.ProbeStrategy) {
				t.Helper()
				_, ok := s.(*probe.GRPCGatewayProbe)
				assert.True(t, ok, "expected second strategy to be *probe.GRPCGatewayProbe, got %T", s)
			},
		},
		{
			name:    "REST returns OptionsProbe + SchemaProbe",
			apiType: pipeline.APITypeREST,
			wantLen: 2,
			checkFirst: func(t *testing.T, s probe.ProbeStrategy) {
				t.Helper()
				_, ok := s.(*probe.OptionsProbe)
				assert.True(t, ok, "expected first strategy to be *probe.OptionsProbe, got %T", s)
			},
		},
		{
			name:    "unknown type falls through to REST default",
			apiType: "unknown",
			wantLen: 2,
			checkFirst: func(t *testing.T, s probe.ProbeStrategy) {
				t.Helper()
				_, ok := s.(*probe.OptionsProbe)
				assert.True(t, ok, "expected first strategy to be *probe.OptionsProbe, got %T", s)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			strategies := pipeline.StrategiesForType(tt.apiType, cfg)
			require.Len(t, strategies, tt.wantLen)
			tt.checkFirst(t, strategies[0])
			if tt.checkSecond != nil {
				tt.checkSecond(t, strategies[1])
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TEST-004: happy-path tests for DetectAPIType and ClassifiersForType
// ---------------------------------------------------------------------------

func TestDetectAPIType_PrefersGraphQL(t *testing.T) {
	requests := []crawl.ObservedRequest{
		{
			Method:  "POST",
			URL:     "https://x.com/graphql",
			Headers: map[string]string{"Content-Type": "application/json"},
			Body:    []byte(`{"query":"{ user { id } }"}`),
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "application/json",
				Headers:     map[string]string{"Content-Type": "application/json"},
				Body:        []byte(`{"data":{"user":{"id":"1"}}}`),
			},
		},
	}
	got := pipeline.DetectAPIType(requests, 0.5)
	assert.Equal(t, pipeline.APITypeGraphQL, got)
}

func TestDetectAPIType_PrefersRESTWhenNoSignals(t *testing.T) {
	// A plain HTML page has no API signals — DetectAPIType should default to REST.
	requests := []crawl.ObservedRequest{
		{
			Method: "GET",
			URL:    "https://x.com/",
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "text/html",
				Body:        []byte(`<html><body>hello</body></html>`),
			},
		},
	}
	got := pipeline.DetectAPIType(requests, 0.5)
	assert.Equal(t, pipeline.APITypeREST, got)
}

func TestClassifiersForType_KnownTypes(t *testing.T) {
	tests := []struct {
		apiType string
		wantLen int
	}{
		{pipeline.APITypeREST, 1},
		{pipeline.APITypeWSDL, 1},
		{pipeline.APITypeGraphQL, 1},
		{pipeline.APITypeGRPC, 1},
	}
	for _, tt := range tests {
		t.Run(tt.apiType, func(t *testing.T) {
			classifiers := pipeline.ClassifiersForType(tt.apiType)
			require.Len(t, classifiers, tt.wantLen)
		})
	}
}

// TestClassifiersForType_GRPC pins the concrete classifier type returned for the
// gRPC branch. A length-only check (see TestClassifiersForType_KnownTypes) would
// not catch a wrong classifier type wired into the switch.
func TestClassifiersForType_GRPC(t *testing.T) {
	classifiers := pipeline.ClassifiersForType(pipeline.APITypeGRPC)
	require.Len(t, classifiers, 1)
	_, ok := classifiers[0].(*classify.GRPCClassifier)
	assert.True(t, ok, "expected *classify.GRPCClassifier, got %T", classifiers[0])
}

func TestClassifiersForType_UnknownReturnsNil(t *testing.T) {
	assert.Nil(t, pipeline.ClassifiersForType("unknown"))
}

// ---------------------------------------------------------------------------
// TEST-001: WSDL-wins branch of DetectAPIType — pin both the `wsdlCount > 0`
// guard and the `wsdlCount >= restCount` tie-breaker via a single SOAP request
// that fires both WSDL (envelope, conf 0.90) and REST (text/xml + POST, conf
// 0.80) classifiers at threshold 0.5, producing wsdlCount=1 and restCount=1.
// The `>=` tie-breaker is what makes WSDL win in that case.
// ---------------------------------------------------------------------------

// TestDetectAPIType_NeverAutoSelectsGRPC pins the opt-in invariant: gRPC is
// never auto-selected by DetectAPIType, even when a request scores 0.99 on
// classify.GRPCClassifier (gRPC content-type + trailer header). Callers must
// pass --api-type grpc explicitly.
func TestDetectAPIType_NeverAutoSelectsGRPC(t *testing.T) {
	req := crawl.ObservedRequest{
		Method:  "POST",
		URL:     "https://x.com/pkg.Service/Method",
		Headers: map[string]string{"Content-Type": "application/grpc"},
		Response: crawl.ObservedResponse{
			StatusCode:  200,
			ContentType: "application/grpc",
			Headers:     map[string]string{"grpc-status": "0"},
		},
	}

	// Confirm the request actually scores 0.99 on the gRPC classifier, so the
	// test is exercising the intended gRPC-shaped signal.
	isAPI, confidence := (&classify.GRPCClassifier{}).Classify(req)
	require.True(t, isAPI)
	require.InDelta(t, 0.99, confidence, 0.0001)

	got := pipeline.DetectAPIType([]crawl.ObservedRequest{req}, 0.5)
	assert.Equal(t, pipeline.APITypeREST, got)
	assert.NotEqual(t, pipeline.APITypeGRPC, got)
}

func TestDetectAPIType_PrefersWSDL(t *testing.T) {
	requests := []crawl.ObservedRequest{
		{
			Method:  "POST",
			URL:     "https://x.com/service.asmx",
			Headers: map[string]string{"Content-Type": "text/xml"},
			Body:    []byte(`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><GetUser/></soap:Body></soap:Envelope>`),
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "text/xml",
				Body:        []byte(`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><GetUserResponse/></soap:Body></soap:Envelope>`),
			},
		},
	}
	got := pipeline.DetectAPIType(requests, 0.5)
	assert.Equal(t, pipeline.APITypeWSDL, got)
}

// ---------------------------------------------------------------------------
// LAB-4678 audit item 3: the API-type verdict must not turn on how many
// endpoints happened to be emitted that run.
// ---------------------------------------------------------------------------

// restReq is a plain REST JSON request: REST-only signal.
func restReq(n int) crawl.ObservedRequest {
	return crawl.ObservedRequest{
		Method:  "POST",
		URL:     "https://x.com/api/users",
		Headers: map[string]string{"Content-Type": "application/json"},
		Body:    []byte(`{"name":"a"}`),
		Response: crawl.ObservedResponse{
			StatusCode: 200, ContentType: "application/json",
			Body: []byte(`{"id":` + string(rune('0'+n%10)) + `}`),
		},
	}
}

// graphqlReq is a textbook GraphQL call. It also scores 0.95 on the REST
// classifier, which is exactly why exclusive assignment is needed.
func graphqlReq() crawl.ObservedRequest {
	return crawl.ObservedRequest{
		Method:  "POST",
		URL:     "https://x.com/graphql",
		Headers: map[string]string{"Content-Type": "application/json"},
		Body:    []byte(`{"query":"{ user { id } }"}`),
		Response: crawl.ObservedResponse{
			StatusCode: 200, ContentType: "application/json",
			Body: []byte(`{"data":{"user":{"id":"1"}}}`),
		},
	}
}

// wsdlReq is a SOAP envelope: a strong WSDL signal that the specialist wins
// outright over REST in the per-request argmax.
func wsdlReq() crawl.ObservedRequest {
	const envelope = `<?xml version="1.0"?><soap:Envelope ` +
		`xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">` +
		`<soap:Body><GetUser><Id>1</Id></GetUser></soap:Body></soap:Envelope>`
	return crawl.ObservedRequest{
		Method:  "POST",
		URL:     "https://x.com/services/UserService",
		Headers: map[string]string{"Content-Type": "application/soap+xml", "SOAPAction": "GetUser"},
		Body:    []byte(envelope),
		Response: crawl.ObservedResponse{
			StatusCode: 200, ContentType: "application/soap+xml",
			Body: []byte(envelope),
		},
	}
}

// strayXMLReq is the weak minority signal whose ability to retype a whole
// capture caused the earlier presence-wins attempt to be reverted.
func strayXMLReq() crawl.ObservedRequest {
	return crawl.ObservedRequest{
		Method:   "GET",
		URL:      "https://x.com/feed",
		Response: crawl.ObservedResponse{StatusCode: 200, ContentType: "text/xml"},
	}
}

func repeat(req func(int) crawl.ObservedRequest, n int) []crawl.ObservedRequest {
	out := make([]crawl.ObservedRequest, 0, n)
	for i := range n {
		out = append(out, req(i))
	}
	return out
}

// TestDetectAPIType_StableAcrossNearTieCounts is the core item-3 assertion. The
// old raw-count rule flipped the verdict between REST and GraphQL on a single
// observation around the tie point. Sweeping the REST count across that region
// must now produce one stable answer.
//
// It asserts the EXPECTED verdict, not just self-agreement. Comparing every element
// of the output against verdicts[0] is satisfied by any constant function, including
// a DetectAPIType stubbed to return APITypeREST unconditionally, so the version that
// only checked stability carried the criterion in its name without pinning anything
// (LAB-4678 review, TEST-002).
//
// REST is the correct answer across this whole band, and stating why is the point:
// challengerWins requires the challenger to clear MinChallengerMatches AND beat REST
// by DominanceMargin (1.5x). At graphqlN=10 that needs restCount*1.5 <= 10, i.e.
// restCount <= 6, so at restN=8..12 GraphQL never dominates and the verdict is REST
// at every point in the sweep.
func TestDetectAPIType_StableAcrossNearTieCounts(t *testing.T) {
	const graphqlN = 10

	for restN := 8; restN <= 12; restN++ {
		reqs := repeat(restReq, restN)
		for range graphqlN {
			reqs = append(reqs, graphqlReq())
		}
		got := pipeline.DetectAPIType(reqs, 0.5)

		assert.Equal(t, pipeline.APITypeREST, got,
			"at restN=%d with graphqlN=%d, GraphQL does not clear the 1.5x dominance "+
				"margin, so the verdict must be REST", restN, graphqlN)
	}
}

// TestDetectAPIType_StrayXMLCannotRetypeRESTApp pins the failure that caused the
// earlier revert: one incidental text/xml response in a REST-dominant capture
// must not produce a WSDL spec and discard the REST surface.
func TestDetectAPIType_StrayXMLCannotRetypeRESTApp(t *testing.T) {
	reqs := append(repeat(restReq, 20), strayXMLReq())
	assert.Equal(t, pipeline.APITypeREST, pipeline.DetectAPIType(reqs, 0.5),
		"a single stray text/xml must not retype a 20-request REST surface")
}

// TestDetectAPIType_DominantSurfaceStillWins pins that the stability rules did
// not cost dominant-surface selection: a genuinely GraphQL-dominant capture is
// still typed GraphQL.
func TestDetectAPIType_DominantSurfaceStillWins(t *testing.T) {
	reqs := repeat(restReq, 2)
	for range 20 {
		reqs = append(reqs, graphqlReq())
	}
	assert.Equal(t, pipeline.APITypeGraphQL, pipeline.DetectAPIType(reqs, 0.5),
		"a 20-vs-2 GraphQL majority must still win the verdict")
}

// TestDetectAPIType_ExclusiveAssignment pins that a request votes once. A
// GraphQL call scores 0.95 on BOTH the GraphQL and REST classifiers; under the
// old double-counting model those 5 calls also produced restCount=5, so GraphQL
// could never out-count a REST tally that already contained it.
func TestDetectAPIType_ExclusiveAssignment(t *testing.T) {
	var reqs []crawl.ObservedRequest
	for range 5 {
		reqs = append(reqs, graphqlReq())
	}
	assert.Equal(t, pipeline.APITypeGraphQL, pipeline.DetectAPIType(reqs, 0.5),
		"GraphQL requests must not also count toward the REST tally")
}

// TestDetectAPIType_VerdictIndependentOfEmittedCount pins the criterion as
// literally worded: scaling the capture up and down, holding the mix fixed,
// must not change the verdict. This is the truncation case — a shorter run
// emits fewer endpoints in the same proportions.
//
// want is the LITERAL expected verdict. It used to be computed by calling
// DetectAPIType on the scale-1 capture, which made the assertion "the function
// agrees with itself" — satisfied by any constant implementation, and so no
// independent check of the criterion the test is named for (LAB-4678 review,
// TEST-002).
//
// GraphQL is correct at every scale: the mix is 1 REST to 4 GraphQL, so GraphQL
// clears both the MinChallengerMatches floor (from scale 1, where it has 4) and the
// 1.5x margin over REST at every scale.
func TestDetectAPIType_VerdictIndependentOfEmittedCount(t *testing.T) {
	build := func(scale int) []crawl.ObservedRequest {
		reqs := repeat(restReq, 1*scale)
		for range 4 * scale {
			reqs = append(reqs, graphqlReq())
		}
		return reqs
	}

	for _, scale := range []int{1, 2, 3, 5, 10} {
		assert.Equal(t, pipeline.APITypeGraphQL, pipeline.DetectAPIType(build(scale), 0.5),
			"a fixed 1:4 REST:GraphQL mix must type GraphQL at every scale (scale=%d)", scale)
	}
}

// TestDetectAPIType_GraphQLWSDLTieResolvesToGraphQL pins the tie the
// graphqlCount >= wsdlCount comparison actually implements. The comment above it
// used to say "out-count WSDL", which describes >, so a reader reasoning about tie
// behavior would get the wrong answer. Pinning it means the operator cannot be
// changed without a test failing to force the comment along with it (LAB-4678
// review, QUAL-001).
func TestDetectAPIType_GraphQLWSDLTieResolvesToGraphQL(t *testing.T) {
	// Equal GraphQL and WSDL votes, with REST low enough that GraphQL clears the
	// dominance margin and reaches the tie comparison at all.
	var reqs []crawl.ObservedRequest
	for range 8 {
		reqs = append(reqs, graphqlReq())
	}
	for range 8 {
		reqs = append(reqs, wsdlReq())
	}

	assert.Equal(t, pipeline.APITypeGraphQL, pipeline.DetectAPIType(reqs, 0.5),
		"an equal GraphQL/WSDL vote count resolves to GraphQL, matching the "+
			"tie-to-GraphQL ordering of the per-request argmax")
}
