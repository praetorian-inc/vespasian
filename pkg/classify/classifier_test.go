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
				QueryParams: map[string]string{"page": "1"},
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
				QueryParams: map[string]string{"page": "2"},
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
				QueryParams: map[string]string{"page": "1"},
			},
			IsAPI:      true,
			Confidence: 0.8,
		},
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:      "GET",
				URL:         "https://example.com/api/users?limit=10",
				QueryParams: map[string]string{"limit": "10"},
			},
			IsAPI:      true,
			Confidence: 0.7,
		},
	}

	result := Deduplicate(classified)
	require.Len(t, result, 1)
	assert.Equal(t, "1", result[0].QueryParams["page"])
	assert.Equal(t, "10", result[0].QueryParams["limit"])
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

// TestDeduplicate_MergesDynamicAndStaticHTMLObservations verifies that Deduplicate
// correctly merges a live-capture observation with a synthetic static:html observation
// on the same METHOD:path. The static:html observations are synthesized by
// analyze.ExtractForms and appended to the request slice before classification.
// Guards against future refactors that might branch on Source and silently drop
// form-derived QueryParams or lose max-confidence selection.
func TestDeduplicate_MergesDynamicAndStaticHTMLObservations(t *testing.T) {
	// Observation A: live browser capture (first in slice — wins body/response).
	obsA := ClassifiedRequest{
		ObservedRequest: crawl.ObservedRequest{
			Method:      "POST",
			URL:         "https://app.example.com/login",
			Source:      "browser",
			QueryParams: map[string]string{"redirect": "/home"},
			Body:        []byte(`redirect=%2Fhome`),
			Response: crawl.ObservedResponse{
				StatusCode: 302,
			},
		},
		IsAPI:      true,
		Confidence: 0.8,
		APIType:    "rest",
	}

	// Observation B: synthetic static:html form analysis (second in slice — loses body/response).
	obsB := ClassifiedRequest{
		ObservedRequest: crawl.ObservedRequest{
			Method:      "POST",
			URL:         "https://app.example.com/login",
			Source:      "static:html",
			QueryParams: map[string]string{"csrf": "abc"},
			Body:        []byte("username=&password="),
		},
		IsAPI:      true,
		Confidence: 0.9,
		APIType:    "rest",
	}

	// Browser-first order mirrors the real generateSpec ordering: live captures
	// are appended before analyze.ExtractForms results.
	result := Deduplicate([]ClassifiedRequest{obsA, obsB})

	// Exactly one entry after dedup on POST:/login.
	require.Len(t, result, 1)

	// QueryParams must contain all keys from both observations.
	assert.Equal(t, "/home", result[0].QueryParams["redirect"], "redirect param from browser observation must be preserved")
	assert.Equal(t, "abc", result[0].QueryParams["csrf"], "csrf param from static:html observation must be merged in")

	// Highest confidence wins (obsB=0.9 > obsA=0.8).
	assert.InDelta(t, 0.9, result[0].Confidence, 0.001, "highest confidence must be kept")

	// First-seen body/response wins (obsA came first).
	assert.Equal(t, obsA.Body, result[0].Body, "first-seen (browser) body must be preserved, not the static form body")
	assert.Equal(t, obsA.Response.StatusCode, result[0].Response.StatusCode, "first-seen response status must be preserved")
}
