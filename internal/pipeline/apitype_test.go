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
	"github.com/praetorian-inc/vespasian/pkg/crawl"
	"github.com/praetorian-inc/vespasian/pkg/probe"
)

// ---------------------------------------------------------------------------
// TEST-002: StrategiesForType — pin the branch contract
// ---------------------------------------------------------------------------

func TestStrategiesForType(t *testing.T) {
	cfg := probe.DefaultConfig()

	tests := []struct {
		name       string
		apiType    string
		wantLen    int
		checkFirst func(t *testing.T, s probe.ProbeStrategy)
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
	}
	for _, tt := range tests {
		t.Run(tt.apiType, func(t *testing.T) {
			classifiers := pipeline.ClassifiersForType(tt.apiType)
			require.Len(t, classifiers, tt.wantLen)
		})
	}
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
