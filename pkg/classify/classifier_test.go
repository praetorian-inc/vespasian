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
	if len(results) != 0 {
		t.Errorf("RunClassifiers(nil) = %d results, want 0", len(results))
	}
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
	if len(results) != 1 {
		t.Fatalf("RunClassifiers with threshold 0.5 = %d results, want 1", len(results))
	}
	if results[0].Confidence < 0.5 {
		t.Errorf("result confidence = %v, want >= 0.5", results[0].Confidence)
	}
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
	if len(results) != 2 {
		t.Errorf("RunClassifiers with threshold 0.0 = %d results, want 2", len(results))
	}
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
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Reason == "" {
		t.Error("expected non-empty reason from DetailedClassifier")
	}
	if results[0].Reason == "classified by rest" {
		t.Error("expected detailed reason, got generic fallback")
	}
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
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Reason != "classified by stub" {
		t.Errorf("reason = %q, want %q", results[0].Reason, "classified by stub")
	}
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
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].APIType != "high" {
		t.Errorf("APIType = %q, want %q (highest confidence wins)", results[0].APIType, "high")
	}
	if results[0].Confidence != 0.9 {
		t.Errorf("Confidence = %v, want 0.9", results[0].Confidence)
	}
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
	if len(result) != 1 {
		t.Fatalf("Deduplicate = %d results, want 1", len(result))
	}
	// Highest confidence kept.
	if result[0].Confidence != 0.85 {
		t.Errorf("Confidence = %v, want 0.85", result[0].Confidence)
	}
	// First occurrence's body preserved.
	if string(result[0].Response.Body) != `[{"id":1}]` {
		t.Errorf("Body = %q, want first occurrence body", string(result[0].Response.Body))
	}
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
	if len(result) != 1 {
		t.Fatalf("Deduplicate = %d results, want 1", len(result))
	}
	if result[0].QueryParams["page"] != "1" {
		t.Errorf("missing merged param 'page'")
	}
	if result[0].QueryParams["limit"] != "10" {
		t.Errorf("missing merged param 'limit'")
	}
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
	if len(result) != 3 {
		t.Errorf("Deduplicate (no dups) = %d results, want 3", len(result))
	}
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
	if len(result) != 1 {
		t.Fatalf("Deduplicate = %d results, want 1", len(result))
	}
	if result[0].Confidence != 0.95 {
		t.Errorf("Confidence = %v, want 0.95 (highest)", result[0].Confidence)
	}
	if result[0].Reason != "high" {
		t.Errorf("Reason = %q, want %q (from highest confidence)", result[0].Reason, "high")
	}
}

func TestDeduplicate_Empty(t *testing.T) {
	result := Deduplicate(nil)
	if len(result) != 0 {
		t.Errorf("Deduplicate(nil) = %d results, want 0", len(result))
	}
}
