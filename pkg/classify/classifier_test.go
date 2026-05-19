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

package classify

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/vespasian/pkg/crawl"
)

// stubClassifier is a simple classifier for testing that returns fixed values.
type stubClassifier struct {
	name       string
	isAPI      bool
	confidence float64
}

func (s *stubClassifier) Name() string { return s.name }
func (s *stubClassifier) Classify(_ crawl.ObservedRequest) (bool, float64) {
	return s.isAPI, s.confidence
}

func TestRunClassifiers_Empty(t *testing.T) {
	classifiers := []APIClassifier{&RESTClassifier{}}
	results := RunClassifiers(classifiers, nil, 0.5)
	assert.Empty(t, results)
}

func TestRunClassifiers_ThresholdFiltering(t *testing.T) {
	classifiers := []APIClassifier{&RESTClassifier{}}
	requests := []crawl.ObservedRequest{
		{
			Method: "GET",
			URL:    "https://example.com/api/v1/users",
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "application/json",
			},
		},
		{
			Method: "GET",
			URL:    "https://example.com/page",
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "text/html",
			},
		},
	}

	results := RunClassifiers(classifiers, requests, 0.5)
	require.Len(t, results, 1)
	assert.GreaterOrEqual(t, results[0].Confidence, 0.5)
}

func TestRunClassifiers_ZeroThreshold(t *testing.T) {
	classifiers := []APIClassifier{&RESTClassifier{}}
	requests := []crawl.ObservedRequest{
		{
			Method: "GET",
			URL:    "https://example.com/api/v1/users",
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "application/json",
			},
		},
		{
			Method: "POST",
			URL:    "https://example.com/submit",
			Response: crawl.ObservedResponse{
				StatusCode: 200,
			},
		},
	}

	results := RunClassifiers(classifiers, requests, 0.0)
	assert.Len(t, results, 2)
}

func TestRunClassifiers_DetailedReason(t *testing.T) {
	classifiers := []APIClassifier{&RESTClassifier{}}
	requests := []crawl.ObservedRequest{
		{
			Method: "GET",
			URL:    "https://example.com/data",
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "application/json",
			},
		},
	}

	results := RunClassifiers(classifiers, requests, 0.5)
	require.Len(t, results, 1)
	assert.NotEmpty(t, results[0].Reason)
	assert.NotEqual(t, "classified by rest", results[0].Reason)
}

func TestRunClassifiers_FallbackReason(t *testing.T) {
	// Use stub classifier that does NOT implement DetailedClassifier.
	classifiers := []APIClassifier{
		&stubClassifier{name: "stub", isAPI: true, confidence: 0.9},
	}
	requests := []crawl.ObservedRequest{
		{
			Method: "GET",
			URL:    "https://example.com/data",
			Response: crawl.ObservedResponse{
				StatusCode: 200,
			},
		},
	}

	results := RunClassifiers(classifiers, requests, 0.5)
	require.Len(t, results, 1)
	assert.Equal(t, "classified by stub", results[0].Reason)
}

func TestRunClassifiers_MultipleClassifiers(t *testing.T) {
	classifiers := []APIClassifier{
		&stubClassifier{name: "low", isAPI: true, confidence: 0.3},
		&stubClassifier{name: "high", isAPI: true, confidence: 0.9},
	}
	requests := []crawl.ObservedRequest{
		{
			Method: "GET",
			URL:    "https://example.com/data",
		},
	}

	results := RunClassifiers(classifiers, requests, 0.0)
	require.Len(t, results, 1)
	assert.Equal(t, "high", results[0].APIType)
	assert.InDelta(t, 0.9, results[0].Confidence, 0.001)
}

func TestDeduplicate_MergesSameEndpoint(t *testing.T) {
	classified := []ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:      "GET",
				URL:         "https://example.com/api/users?page=1",
				QueryParams: map[string][]string{"page": {"1"}},
				Response: crawl.ObservedResponse{
					StatusCode: 200,
					Body:       []byte(`[{"id":1}]`),
				},
			},
			IsAPI:      true,
			Confidence: 0.8,
			Reason:     "content-type:application/json",
			APIType:    "rest",
		},
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:      "GET",
				URL:         "https://example.com/api/users?page=2",
				QueryParams: map[string][]string{"page": {"2"}},
				Response: crawl.ObservedResponse{
					StatusCode: 200,
					Body:       []byte(`[{"id":2}]`),
				},
			},
			IsAPI:      true,
			Confidence: 0.85,
			Reason:     "content-type+path",
			APIType:    "rest",
		},
	}

	result := Deduplicate(classified)
	require.Len(t, result, 1)
	// Highest confidence kept.
	assert.InDelta(t, 0.85, result[0].Confidence, 0.001)
	// First occurrence's body preserved.
	assert.Equal(t, `[{"id":1}]`, string(result[0].Response.Body))
}

func TestDeduplicate_MergesQueryParams(t *testing.T) {
	classified := []ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:      "GET",
				URL:         "https://example.com/api/users?page=1",
				QueryParams: map[string][]string{"page": {"1"}},
			},
			IsAPI:      true,
			Confidence: 0.8,
		},
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:      "GET",
				URL:         "https://example.com/api/users?limit=10",
				QueryParams: map[string][]string{"limit": {"10"}},
			},
			IsAPI:      true,
			Confidence: 0.7,
		},
	}

	result := Deduplicate(classified)
	require.Len(t, result, 1)
	assert.Equal(t, []string{"1"}, result[0].QueryParams["page"])
	assert.Equal(t, []string{"10"}, result[0].QueryParams["limit"])
}

func TestDeduplicate_MergesMultiValueQueryParams(t *testing.T) {
	classified := []ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:      "GET",
				URL:         "https://example.com/api/items?tag=a&tag=b",
				QueryParams: map[string][]string{"tag": {"a", "b"}},
			},
			IsAPI:      true,
			Confidence: 0.8,
		},
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:      "GET",
				URL:         "https://example.com/api/items?tag=b&tag=c",
				QueryParams: map[string][]string{"tag": {"b", "c"}},
			},
			IsAPI:      true,
			Confidence: 0.8,
		},
	}

	// TEST-001: capture a deep snapshot of each input slice BEFORE Deduplicate runs.
	beforeSnapshots := make([]map[string][]string, len(classified))
	for i, cr := range classified {
		snap := make(map[string][]string, len(cr.QueryParams))
		for k, vs := range cr.QueryParams {
			copied := make([]string, len(vs))
			copy(copied, vs)
			snap[k] = copied
		}
		beforeSnapshots[i] = snap
	}

	result := Deduplicate(classified)
	require.Len(t, result, 1)
	// Union with order preservation and dedup: a, b (from first), c (new from second).
	assert.Equal(t, []string{"a", "b", "c"}, result[0].QueryParams["tag"])

	// TEST-001: assert inputs were not mutated (copy-on-write guarantee from D1).
	for i, cr := range classified {
		assert.Equal(t, beforeSnapshots[i], cr.QueryParams,
			"Deduplicate must not mutate input[%d].QueryParams", i)
	}
}

func TestMergeUniqueOrdered(t *testing.T) {
	tests := []struct {
		name string
		a    []string
		b    []string
		want []string
	}{
		{
			name: "both nil",
			a:    nil,
			b:    nil,
			want: nil,
		},
		{
			name: "a non-nil b nil",
			a:    []string{"a"},
			b:    nil,
			want: []string{"a"},
		},
		{
			name: "a nil b non-nil",
			a:    nil,
			b:    []string{"a", "b"},
			want: []string{"a", "b"},
		},
		{
			name: "merge with overlap",
			a:    []string{"a", "b"},
			b:    []string{"b", "c"},
			want: []string{"a", "b", "c"},
		},
		{
			name: "b has duplicates already in a",
			a:    []string{"a"},
			b:    []string{"a", "a"},
			want: []string{"a"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MergeUniqueOrdered(tt.a, tt.b)
			assert.Equal(t, tt.want, got)
		})
	}

	// TEST-002: pin copy-on-write contract — input a must not be modified.
	t.Run("does not mutate input a", func(t *testing.T) {
		a := []string{"x"}
		b := []string{"y"}
		result := MergeUniqueOrdered(a, b)
		assert.Equal(t, []string{"x", "y"}, result, "result should contain both values")
		assert.Equal(t, []string{"x"}, a, "input a must not be mutated")
	})

	// TEST-002: pin stronger dedup semantics — duplicates within a are removed.
	t.Run("deduplicates within a", func(t *testing.T) {
		result := MergeUniqueOrdered([]string{"a", "a", "b"}, nil)
		assert.Equal(t, []string{"a", "b"}, result, "duplicates within a should be removed")
	})
}

func TestDeduplicate_NoDuplicates(t *testing.T) {
	classified := []ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://example.com/api/users",
			},
			IsAPI:      true,
			Confidence: 0.8,
		},
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "POST",
				URL:    "https://example.com/api/users",
			},
			IsAPI:      true,
			Confidence: 0.9,
		},
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://example.com/api/posts",
			},
			IsAPI:      true,
			Confidence: 0.7,
		},
	}

	result := Deduplicate(classified)
	assert.Len(t, result, 3)
}

func TestDeduplicate_KeepsHighestConfidence(t *testing.T) {
	classified := []ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://example.com/api/data",
			},
			IsAPI:      true,
			Confidence: 0.6,
			Reason:     "low",
		},
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://example.com/api/data?q=test",
			},
			IsAPI:      true,
			Confidence: 0.95,
			Reason:     "high",
		},
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://example.com/api/data?q=other",
			},
			IsAPI:      true,
			Confidence: 0.7,
			Reason:     "mid",
		},
	}

	result := Deduplicate(classified)
	require.Len(t, result, 1)
	assert.InDelta(t, 0.95, result[0].Confidence, 0.001)
	assert.Equal(t, "high", result[0].Reason)
}

func TestDeduplicate_Empty(t *testing.T) {
	result := Deduplicate(nil)
	assert.Empty(t, result)
}

func TestDeduplicate_PreservesDistinctSOAPActions(t *testing.T) {
	classified := []ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:  "POST",
				URL:     "https://example.com/service",
				Headers: map[string]string{"SOAPAction": `"urn:GetUser"`},
			},
			IsAPI: true, Confidence: 0.95, APIType: "wsdl",
		},
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:  "POST",
				URL:     "https://example.com/service",
				Headers: map[string]string{"SOAPAction": `"urn:DeleteUser"`},
			},
			IsAPI: true, Confidence: 0.90, APIType: "wsdl",
		},
	}

	result := Deduplicate(classified)
	assert.Len(t, result, 2, "distinct SOAPActions on same URL must not be merged")
}

func TestDeduplicate_MergesSameSOAPAction(t *testing.T) {
	classified := []ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:  "POST",
				URL:     "https://example.com/service?param=1",
				Headers: map[string]string{"SOAPAction": `"urn:GetUser"`},
			},
			IsAPI: true, Confidence: 0.80, APIType: "wsdl",
		},
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:  "POST",
				URL:     "https://example.com/service?param=2",
				Headers: map[string]string{"SOAPAction": `"urn:GetUser"`},
			},
			IsAPI: true, Confidence: 0.95, APIType: "wsdl",
		},
	}

	result := Deduplicate(classified)
	require.Len(t, result, 1, "same SOAPAction on same path should merge")
	assert.InDelta(t, 0.95, result[0].Confidence, 0.001, "highest confidence kept")
}

func TestDeduplicate_SOAPActionCaseInsensitive(t *testing.T) {
	classified := []ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:  "POST",
				URL:     "https://example.com/service",
				Headers: map[string]string{"soapaction": `"urn:GetUser"`},
			},
			IsAPI: true, Confidence: 0.90, APIType: "wsdl",
		},
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:  "POST",
				URL:     "https://example.com/service",
				Headers: map[string]string{"SOAPACTION": `"urn:GetUser"`},
			},
			IsAPI: true, Confidence: 0.85, APIType: "wsdl",
		},
	}

	result := Deduplicate(classified)
	assert.Len(t, result, 1, "case-insensitive SOAPAction should merge")
}

func TestDeduplicate_NonSOAPEndpointsStillDedupByPath(t *testing.T) {
	classified := []ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{Method: "GET", URL: "https://example.com/api/users?page=1"},
			IsAPI:           true, Confidence: 0.80, APIType: "rest",
		},
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:  "POST",
				URL:     "https://example.com/service",
				Headers: map[string]string{"SOAPAction": `"urn:GetUser"`},
			},
			IsAPI: true, Confidence: 0.95, APIType: "wsdl",
		},
		{
			ObservedRequest: crawl.ObservedRequest{Method: "GET", URL: "https://example.com/api/users?page=2"},
			IsAPI:           true, Confidence: 0.85, APIType: "rest",
		},
	}

	result := Deduplicate(classified)
	assert.Len(t, result, 2, "REST deduplicates by path, WSDL separate")
}

func TestRunClassifiers_WSDLWinsOverREST(t *testing.T) {
	classifiers := []APIClassifier{
		&RESTClassifier{},
		&WSDLClassifier{},
	}
	requests := []crawl.ObservedRequest{{
		Method:  "POST",
		URL:     "https://example.com/service",
		Headers: map[string]string{"SOAPAction": `"urn:GetUser"`},
		Response: crawl.ObservedResponse{
			StatusCode:  200,
			ContentType: "text/xml",
			Body:        []byte(`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><GetUser/></soap:Body></soap:Envelope>`),
		},
	}}

	results := RunClassifiers(classifiers, requests, 0.5)
	require.Len(t, results, 1)
	assert.Equal(t, "wsdl", results[0].APIType, "WSDL should win for SOAP traffic")
	assert.GreaterOrEqual(t, results[0].Confidence, 0.90)
}

func TestRunClassifiers_PopulatesMultiValueQueryKeys(t *testing.T) {
	// RunClassifiers must record which keys were observed as multi-value
	// (len > 1) BEFORE Deduplicate can merge values across observations.
	classifiers := []APIClassifier{&RESTClassifier{}}
	requests := []crawl.ObservedRequest{
		{
			Method: "GET",
			URL:    "https://example.com/api/items?tag=a&tag=b&page=1",
			QueryParams: map[string][]string{
				"tag":  {"a", "b"}, // multi-value
				"page": {"1"},      // scalar
			},
			Response: crawl.ObservedResponse{StatusCode: 200, ContentType: "application/json"},
		},
		{
			Method: "GET",
			URL:    "https://example.com/api/items?page=2",
			QueryParams: map[string][]string{
				"page": {"2"}, // scalar
			},
			Response: crawl.ObservedResponse{StatusCode: 200, ContentType: "application/json"},
		},
	}
	results := RunClassifiers(classifiers, requests, 0.5)
	require.Len(t, results, 2)

	// First request: tag multi-value, page scalar.
	require.NotNil(t, results[0].MultiValueQueryKeys, "MultiValueQueryKeys must always be non-nil after RunClassifiers")
	assert.True(t, results[0].MultiValueQueryKeys["tag"], "tag was observed as multi-value")
	assert.False(t, results[0].MultiValueQueryKeys["page"], "page was scalar in obs 1")

	// Second request: page scalar, no multi-value keys.
	require.NotNil(t, results[1].MultiValueQueryKeys, "MultiValueQueryKeys must always be non-nil after RunClassifiers")
	assert.Empty(t, results[1].MultiValueQueryKeys, "no key was multi-value in obs 2")
}

func TestDeduplicate_UnionsMultiValueQueryKeys(t *testing.T) {
	// Regression: Deduplicate merges QueryParams via union, which makes
	// the merged slice len > 1 even when each contributing observation
	// was scalar. MultiValueQueryKeys must carry the per-observation
	// truth through dedup so downstream consumers (OpenAPI generator)
	// can tell "actually multi-value" from "scalar with different values
	// across observations".
	classified := []ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:      "GET",
				URL:         "https://x.test/items?page=1",
				QueryParams: map[string][]string{"page": {"1"}},
			},
			MultiValueQueryKeys: map[string]bool{}, // page scalar
		},
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:      "GET",
				URL:         "https://x.test/items?page=2",
				QueryParams: map[string][]string{"page": {"2"}},
			},
			MultiValueQueryKeys: map[string]bool{}, // page scalar
		},
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:      "GET",
				URL:         "https://x.test/items?tag=a&tag=b",
				QueryParams: map[string][]string{"tag": {"a", "b"}},
			},
			MultiValueQueryKeys: map[string]bool{"tag": true},
		},
	}
	result := Deduplicate(classified)
	require.Len(t, result, 1, "all three observations dedup to one GET:/items")

	// Merged QueryParams: page=[1,2], tag=[a,b].
	assert.Equal(t, []string{"1", "2"}, result[0].QueryParams["page"])
	assert.Equal(t, []string{"a", "b"}, result[0].QueryParams["tag"])

	// Critical: MultiValueQueryKeys must reflect per-observation truth.
	require.NotNil(t, result[0].MultiValueQueryKeys)
	assert.False(t, result[0].MultiValueQueryKeys["page"],
		"page was scalar in every contributing observation; dedup must NOT mark it multi-value")
	assert.True(t, result[0].MultiValueQueryKeys["tag"],
		"tag was multi-value in obs 3; dedup must preserve that bit")
}
