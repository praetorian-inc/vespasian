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
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/vespasian/pkg/crawl"
	"github.com/praetorian-inc/vespasian/pkg/mediatype"
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
	// LAB-4678: the retained response is selected deterministically (both are
	// populated here, so a stable fingerprint decides), NOT by first-seen order.
	// Assert order-independence rather than a specific body: swapping the input
	// order must yield the identical retained response.
	swapped := Deduplicate([]ClassifiedRequest{classified[1], classified[0]})
	require.Len(t, swapped, 1)
	assert.Equal(t, string(result[0].Response.Body), string(swapped[0].Response.Body),
		"retained response must not depend on observation order")
}

func TestDeduplicate_ResponseSelection_PrefersPopulated(t *testing.T) {
	// Same METHOD:path observed twice: one populated response and one empty
	// (half-captured — no status/content-type/body). The populated response must
	// always be retained, regardless of input order (LAB-4678, A4). Previously
	// the first-seen observation's response was kept, so a half-captured
	// observation arriving first would blank out the documented response.
	populated := ClassifiedRequest{
		ObservedRequest: crawl.ObservedRequest{
			Method: "GET",
			URL:    "https://example.com/api/items",
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "application/json",
				Body:        []byte(`[{"id":1}]`),
			},
		},
		IsAPI: true, Confidence: 0.8, APIType: "rest",
	}
	empty := ClassifiedRequest{
		ObservedRequest: crawl.ObservedRequest{
			Method:   "GET",
			URL:      "https://example.com/api/items",
			Response: crawl.ObservedResponse{}, // half-captured
		},
		IsAPI: true, Confidence: 0.15, APIType: "rest",
	}

	forward := Deduplicate([]ClassifiedRequest{populated, empty})
	reverse := Deduplicate([]ClassifiedRequest{empty, populated})

	require.Len(t, forward, 1)
	require.Len(t, reverse, 1)
	assert.Equal(t, `[{"id":1}]`, string(forward[0].Response.Body),
		"populated response must be retained when it is seen first")
	assert.Equal(t, `[{"id":1}]`, string(reverse[0].Response.Body),
		"populated response must be retained even when the empty one is seen first")
}

func TestDeduplicate_ResponseSelection_TwoPopulatedOrderIndependent(t *testing.T) {
	// Two distinct populated responses on the same endpoint collapse to one
	// entry; the retained response is chosen by a stable fingerprint, so it is
	// identical regardless of input order (LAB-4678, A4 tie-break).
	a := ClassifiedRequest{
		ObservedRequest: crawl.ObservedRequest{
			Method: "GET", URL: "https://example.com/api/items",
			Response: crawl.ObservedResponse{StatusCode: 200, ContentType: "application/json", Body: []byte(`{"a":1}`)},
		}, IsAPI: true, Confidence: 0.8, APIType: "rest",
	}
	b := ClassifiedRequest{
		ObservedRequest: crawl.ObservedRequest{
			Method: "GET", URL: "https://example.com/api/items",
			Response: crawl.ObservedResponse{StatusCode: 200, ContentType: "application/json", Body: []byte(`{"b":2}`)},
		}, IsAPI: true, Confidence: 0.8, APIType: "rest",
	}

	fwd := Deduplicate([]ClassifiedRequest{a, b})
	rev := Deduplicate([]ClassifiedRequest{b, a})
	require.Len(t, fwd, 1)
	require.Len(t, rev, 1)
	assert.Equal(t, string(fwd[0].Response.Body), string(rev[0].Response.Body),
		"fingerprint tie-break must be independent of observation order")
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

// SEC-BE-001: MergeUniqueOrdered must cap output at crawl.MaxQueryParamValues
// and return a fresh allocation when a is already at the cap so callers cannot
// mutate the returned slice and affect the original input.
func TestMergeUniqueOrdered_CappedBehavior(t *testing.T) {
	// makeCapStrings returns n unique strings suitable for cap-boundary tests.
	makeCapStrings := func(n int, prefix string) []string {
		vs := make([]string, n)
		for i := range n {
			vs[i] = prefix + strings.Repeat("x", i+1)
		}
		return vs
	}

	t.Run("at_cap_returns_fresh_dedup_of_a", func(t *testing.T) {
		// a is exactly at the cap with all unique values; b has additional values.
		// After dedup a still fills the cap, so b is not included.
		// The result must be a fresh allocation — mutating a must not affect result.
		a := makeCapStrings(crawl.MaxQueryParamValues, "a")
		b := []string{"extra"}

		result := MergeUniqueOrdered(a, b)

		// Length must equal cap — b must not be included.
		assert.Len(t, result, crawl.MaxQueryParamValues, "result length must equal cap when a is at cap")
		assert.NotContains(t, result, "extra", "b values must be excluded when a fills the cap after dedup")

		// Fresh allocation contract: mutating a[0] must not affect result[0].
		original0 := result[0]
		a[0] = "MUTATED"
		assert.Equal(t, original0, result[0], "result must be a fresh allocation (mutating a must not affect result)")
	})

	t.Run("short_circuit_dedups_a_when_a_has_internal_duplicates", func(t *testing.T) {
		// a has more entries than limit, but many are duplicates.
		// After dedup, len(unique(a)) < limit, so b can contribute values.
		// Verifies the dedup contract holds regardless of a's duplicate density.
		limit := crawl.MaxQueryParamValues
		// Build a with limit+50 entries but only limit/2 unique values.
		half := limit / 2
		a := make([]string, limit+50)
		for i := range a {
			a[i] = makeCapStrings(half, "a")[i%half]
		}
		b := makeCapStrings(20, "b")

		result := MergeUniqueOrdered(a, b)

		// No duplicates in result.
		seen := make(map[string]int)
		for _, v := range result {
			seen[v]++
		}
		for v, count := range seen {
			assert.Equal(t, 1, count, "duplicate found in result: %q appears %d times", v, count)
		}
		// Result must not exceed cap.
		assert.LessOrEqual(t, len(result), limit, "result must not exceed cap")
		// Result must contain some b values (since dedup of a left room).
		hasBVal := false
		for _, v := range result {
			for _, bv := range b {
				if v == bv {
					hasBVal = true
				}
			}
		}
		assert.True(t, hasBVal, "b values must appear when dedup of a leaves room under cap")
	})

	t.Run("output_never_exceeds_cap", func(t *testing.T) {
		a := makeCapStrings(200, "a")
		b := makeCapStrings(200, "b")

		result := MergeUniqueOrdered(a, b)

		assert.LessOrEqual(t, len(result), crawl.MaxQueryParamValues,
			"output length must never exceed crawl.MaxQueryParamValues")
	})

	t.Run("b_values_included_up_to_cap_when_a_under_cap", func(t *testing.T) {
		// a has 250 unique values; b provides 7 values that push the merged
		// slice to exactly 257. The cap is 256, so the 257th value must be
		// dropped.
		a := makeCapStrings(250, "a")
		b := []string{"b_val_1", "b_val_2", "b_val_3", "b_val_4", "b_val_5", "b_val_6", "b_val_7"}

		result := MergeUniqueOrdered(a, b)

		assert.Equal(t, crawl.MaxQueryParamValues, len(result), "result must be exactly capped at MaxQueryParamValues")
		assert.Contains(t, result, "b_val_6", "b_val_6 is the 256th value and must be included")
		assert.NotContains(t, result, "b_val_7", "b_val_7 is the 257th value and must be excluded")
	})

	t.Run("b_partial_overlap_with_a", func(t *testing.T) {
		// a has 250 unique values including "shared"; b starts with "shared"
		// (dedup) then adds 10 new values. The cap is 256, so values after the
		// 6th new value must be dropped.
		a := makeCapStrings(249, "a")
		a = append(a, "shared") // 250 total; "shared" is last

		b := []string{"shared", "new1", "new2", "new3", "new4", "new5", "new6", "new7", "new8", "new9", "new10"}

		result := MergeUniqueOrdered(a, b)

		// "shared" already in a — dedup must not double-count it.
		count := 0
		for _, v := range result {
			if v == "shared" {
				count++
			}
		}
		assert.Equal(t, 1, count, "shared must appear exactly once in result (dedup)")

		// Cap still applies: result must not exceed MaxQueryParamValues.
		assert.LessOrEqual(t, len(result), crawl.MaxQueryParamValues,
			"result must not exceed crawl.MaxQueryParamValues even with partial overlap")
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

// TestDeduplicate_SOAPDistinctBodiesSurvive verifies that two SOAP requests
// to the same endpoint and SOAPAction with DIFFERENT envelope bytes are
// preserved as separate entries — the new body-fingerprint behavior. This
// makes the contrast with TestDeduplicate_MergesSameSOAPAction (which uses
// empty bodies) explicit, so future readers don't think the bodyless test
// implies bodies are also collapsed.
func TestDeduplicate_SOAPDistinctBodiesSurvive(t *testing.T) {
	classified := []ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "POST",
				URL:    "https://example.com/service",
				Headers: map[string]string{
					"SOAPAction":   `"urn:GetUser"`,
					"Content-Type": "text/xml; charset=utf-8",
				},
				Body: []byte(`<env:Envelope xmlns:env="..."><env:Body><GetUser><id>1</id></GetUser></env:Body></env:Envelope>`),
			},
			IsAPI: true, Confidence: 0.85, APIType: "wsdl",
		},
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "POST",
				URL:    "https://example.com/service",
				Headers: map[string]string{
					"SOAPAction":   `"urn:GetUser"`,
					"Content-Type": "text/xml; charset=utf-8",
				},
				Body: []byte(`<env:Envelope xmlns:env="..."><env:Body><GetUser><id>2</id></GetUser></env:Body></env:Envelope>`),
			},
			IsAPI: true, Confidence: 0.90, APIType: "wsdl",
		},
	}

	result := Deduplicate(classified)
	require.Len(t, result, 2,
		"distinct SOAP envelope bodies on same path+SOAPAction should survive (allows downstream merge to see all observations)")

	// Also assert the actual envelope bytes survive.
	gotBodies := make([]string, 0, len(result))
	for _, r := range result {
		gotBodies = append(gotBodies, string(r.Body))
	}
	assert.ElementsMatch(t,
		[]string{
			`<env:Envelope xmlns:env="..."><env:Body><GetUser><id>1</id></GetUser></env:Body></env:Envelope>`,
			`<env:Envelope xmlns:env="..."><env:Body><GetUser><id>2</id></GetUser></env:Body></env:Envelope>`,
		},
		gotBodies,
		"both SOAP envelope bodies (<id>1</id> and <id>2</id>) must survive dedup",
	)
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

func TestDeduplicate_KeepsDistinctBodiesByContentType(t *testing.T) {
	classified := []ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:  "POST",
				URL:     "https://example.com/api/submit",
				Headers: map[string]string{"Content-Type": "application/json"},
				Body:    []byte(`{"key":"value"}`),
			},
			IsAPI: true, Confidence: 0.9, APIType: "rest",
		},
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:  "POST",
				URL:     "https://example.com/api/submit",
				Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
				Body:    []byte(`key=value`),
			},
			IsAPI: true, Confidence: 0.8, APIType: "rest",
		},
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:  "POST",
				URL:     "https://example.com/api/submit",
				Headers: map[string]string{"Content-Type": "multipart/form-data; boundary=abc123"},
				Body:    []byte("--abc123\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\nvalue\r\n--abc123--\r\n"),
			},
			IsAPI: true, Confidence: 0.85, APIType: "rest",
		},
	}

	result := Deduplicate(classified)
	assert.Len(t, result, 3, "distinct content types on same path must not be merged")
}

func TestDeduplicate_MergesSameContentType(t *testing.T) {
	// Byte-identical bodies with the same CT must collapse — they are true duplicates.
	body := []byte(`{"name":"alice"}`)
	classified := []ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:  "POST",
				URL:     "https://example.com/api/create",
				Headers: map[string]string{"Content-Type": "application/json"},
				Body:    body,
			},
			IsAPI: true, Confidence: 0.8, APIType: "rest",
		},
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:  "POST",
				URL:     "https://example.com/api/create",
				Headers: map[string]string{"Content-Type": "application/json"},
				Body:    body,
			},
			IsAPI: true, Confidence: 0.9, APIType: "rest",
		},
	}

	result := Deduplicate(classified)
	require.Len(t, result, 1, "byte-identical bodies on same path+CT should collapse to one entry")
	assert.InDelta(t, 0.9, result[0].Confidence, 0.001, "highest confidence kept")
}

func TestDeduplicate_GETsCollapseIgnoringContentType(t *testing.T) {
	classified := []ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:  "GET",
				URL:     "https://example.com/api/items",
				Headers: map[string]string{"Content-Type": "application/json"},
				// No body
			},
			IsAPI: true, Confidence: 0.8, APIType: "rest",
		},
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:  "GET",
				URL:     "https://example.com/api/items?page=2",
				Headers: map[string]string{"Content-Type": "application/xml"},
				// No body
			},
			IsAPI: true, Confidence: 0.85, APIType: "rest",
		},
	}

	result := Deduplicate(classified)
	require.Len(t, result, 1, "empty-body GETs should collapse by path regardless of Content-Type header")
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

// TestDeduplicate_DistinctBodiesSurvive verifies that form-encoded POST observations
// with distinct body bytes survive deduplication as separate entries, enabling
// downstream buildOperation to union fields across observations (LAB-2106).
func TestDeduplicate_DistinctBodiesSurvive(t *testing.T) {
	ct := "application/x-www-form-urlencoded"
	classified := []ClassifiedRequest{
		{ObservedRequest: crawl.ObservedRequest{Method: "POST", URL: "https://example.com/api/checkout", Headers: map[string]string{"Content-Type": ct}, Body: []byte("product_id=1&qty=1")}, IsAPI: true, Confidence: 0.8},
		{ObservedRequest: crawl.ObservedRequest{Method: "POST", URL: "https://example.com/api/checkout", Headers: map[string]string{"Content-Type": ct}, Body: []byte("product_id=2&coupon=SAVE10")}, IsAPI: true, Confidence: 0.8},
		{ObservedRequest: crawl.ObservedRequest{Method: "POST", URL: "https://example.com/api/checkout", Headers: map[string]string{"Content-Type": ct}, Body: []byte("product_id=3&gift_wrap=true&note=hello")}, IsAPI: true, Confidence: 0.8},
		{ObservedRequest: crawl.ObservedRequest{Method: "POST", URL: "https://example.com/api/checkout", Headers: map[string]string{"Content-Type": ct}, Body: []byte("product_id=4&address_id=99")}, IsAPI: true, Confidence: 0.8},
		{ObservedRequest: crawl.ObservedRequest{Method: "POST", URL: "https://example.com/api/checkout", Headers: map[string]string{"Content-Type": ct}, Body: []byte("product_id=5&promo=FLASH")}, IsAPI: true, Confidence: 0.8},
	}

	result := Deduplicate(classified)
	assert.Len(t, result, 5, "5 POST observations with distinct bodies must each survive dedup")

	// Also assert that the SET of body bytes in the result equals the input set.
	gotBodies := make([]string, 0, len(result))
	for _, r := range result {
		gotBodies = append(gotBodies, string(r.Body))
	}
	assert.ElementsMatch(t,
		[]string{
			"product_id=1&qty=1",
			"product_id=2&coupon=SAVE10",
			"product_id=3&gift_wrap=true&note=hello",
			"product_id=4&address_id=99",
			"product_id=5&promo=FLASH",
		},
		gotBodies,
		"result bodies should match input bodies exactly",
	)
}

// TestDeduplicate_IdenticalBodiesCollapse verifies that POST observations with
// byte-identical bodies collapse to a single entry (true duplicates).
func TestDeduplicate_IdenticalBodiesCollapse(t *testing.T) {
	body := []byte(`{"user":"alice","role":"admin"}`)
	ct := "application/json"
	classified := []ClassifiedRequest{
		{ObservedRequest: crawl.ObservedRequest{Method: "POST", URL: "https://example.com/api/users", Headers: map[string]string{"Content-Type": ct}, Body: body}, IsAPI: true, Confidence: 0.8},
		{ObservedRequest: crawl.ObservedRequest{Method: "POST", URL: "https://example.com/api/users", Headers: map[string]string{"Content-Type": ct}, Body: body}, IsAPI: true, Confidence: 0.85},
		{ObservedRequest: crawl.ObservedRequest{Method: "POST", URL: "https://example.com/api/users", Headers: map[string]string{"Content-Type": ct}, Body: body}, IsAPI: true, Confidence: 0.9},
		{ObservedRequest: crawl.ObservedRequest{Method: "POST", URL: "https://example.com/api/users", Headers: map[string]string{"Content-Type": ct}, Body: body}, IsAPI: true, Confidence: 0.7},
		{ObservedRequest: crawl.ObservedRequest{Method: "POST", URL: "https://example.com/api/users", Headers: map[string]string{"Content-Type": ct}, Body: body}, IsAPI: true, Confidence: 0.75},
	}

	result := Deduplicate(classified)
	require.Len(t, result, 1, "5 POST observations with byte-identical bodies must collapse to 1 entry")
	assert.InDelta(t, 0.9, result[0].Confidence, 0.001, "highest confidence kept")
}

// TestDeduplicate_GETsStillCollapseByPath verifies that bodyless GETs continue
// to deduplicate by path regardless of any header differences (unchanged behavior).
// Inputs explicitly carry an empty MultiValueQueryKeys map to mirror what
// RunClassifiers produces in production (classifier.go:59) — leaving it nil
// would let buildOperation fall through to its len(vals)>1 fallback and emit
// an array for these scalar observations (the round-6 regression).
func TestDeduplicate_GETsStillCollapseByPath(t *testing.T) {
	classified := []ClassifiedRequest{
		{ObservedRequest: crawl.ObservedRequest{Method: "GET", URL: "https://example.com/api/products?page=1", QueryParams: map[string][]string{"page": {"1"}}}, MultiValueQueryKeys: map[string]bool{}, IsAPI: true, Confidence: 0.8},
		{ObservedRequest: crawl.ObservedRequest{Method: "GET", URL: "https://example.com/api/products?page=2", QueryParams: map[string][]string{"page": {"2"}}}, MultiValueQueryKeys: map[string]bool{}, IsAPI: true, Confidence: 0.85},
		{ObservedRequest: crawl.ObservedRequest{Method: "GET", URL: "https://example.com/api/products?page=3", QueryParams: map[string][]string{"page": {"3"}}}, MultiValueQueryKeys: map[string]bool{}, IsAPI: true, Confidence: 0.75},
	}

	result := Deduplicate(classified)
	require.Len(t, result, 1, "bodyless GETs must still collapse by path")
	assert.InDelta(t, 0.85, result[0].Confidence, 0.001, "highest confidence kept")
	// Query params from all 3 observations should be merged via union (LAB-2110).
	assert.Equal(t, []string{"1", "2", "3"}, result[0].QueryParams["page"])
	// MultiValueQueryKeys is non-nil and empty after dedup — pins the
	// invariant that buildOperation will emit SCALAR (not ARRAY) for this
	// merged shape, matching TestBuildOperation_PostDedupScalarNotOverWidened.
	require.NotNil(t, result[0].MultiValueQueryKeys, "MultiValueQueryKeys must be non-nil after dedup")
	assert.Empty(t, result[0].MultiValueQueryKeys, "page was scalar in every contributing observation; merged map must remain empty")
}

// TestDeduplicate_MultipartBoundaryNormalized verifies that two logically
// identical multipart bodies with DIFFERENT boundary tokens dedup correctly.
// Boundaries are random per-request from clients, so without normalization
// every observation would be unique.
func TestDeduplicate_MultipartBoundaryNormalized(t *testing.T) {
	body1 := []byte("--BoundaryAAA\r\n" +
		"Content-Disposition: form-data; name=\"x\"\r\n\r\n" +
		"value\r\n" +
		"--BoundaryAAA--\r\n")
	body2 := []byte("--BoundaryZZZ\r\n" +
		"Content-Disposition: form-data; name=\"x\"\r\n\r\n" +
		"value\r\n" +
		"--BoundaryZZZ--\r\n")
	classified := []ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "POST", URL: "https://example.com/api/upload",
				Headers: map[string]string{"Content-Type": "multipart/form-data; boundary=BoundaryAAA"},
				Body:    body1,
			},
			IsAPI: true, Confidence: 0.85, APIType: "rest",
		},
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "POST", URL: "https://example.com/api/upload",
				Headers: map[string]string{"Content-Type": "multipart/form-data; boundary=BoundaryZZZ"},
				Body:    body2,
			},
			IsAPI: true, Confidence: 0.95, APIType: "rest",
		},
	}
	result := Deduplicate(classified)
	require.Len(t, result, 1, "identical multipart content with different boundaries should dedup to one entry")
	assert.InDelta(t, 0.95, result[0].Confidence, 0.001, "highest confidence kept")
}

// TestDeduplicate_MultipartShortBoundarySkipsNormalize verifies that when the
// multipart boundary is shorter than 4 characters, boundary normalization is
// skipped and the raw body bytes are used for fingerprinting instead.
// Two observations with boundary=ab (2 chars) and different boundary values
// but otherwise identical content must NOT dedup because the normalization
// path is not taken — they hash to different raw bytes.
func TestDeduplicate_MultipartShortBoundarySkipsNormalize(t *testing.T) {
	// Both observations have the same logical content but different raw bytes
	// because the boundary tokens differ and are NOT normalized (len < 4).
	body1 := []byte("--ab\r\nContent-Disposition: form-data; name=\"x\"\r\n\r\nvalue\r\n--ab--\r\n")
	body2 := []byte("--cd\r\nContent-Disposition: form-data; name=\"x\"\r\n\r\nvalue\r\n--cd--\r\n")
	classified := []ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "POST", URL: "https://example.com/api/upload",
				Headers: map[string]string{"Content-Type": "multipart/form-data; boundary=ab"},
				Body:    body1,
			},
			IsAPI: true, Confidence: 0.85, APIType: "rest",
		},
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "POST", URL: "https://example.com/api/upload",
				Headers: map[string]string{"Content-Type": "multipart/form-data; boundary=cd"},
				Body:    body2,
			},
			IsAPI: true, Confidence: 0.90, APIType: "rest",
		},
	}
	result := Deduplicate(classified)
	assert.Len(t, result, 2,
		"short boundaries (<4 chars) skip normalization, so raw body hashes differ and observations must NOT dedup")
}

// TestDeduplicate_BodyWithoutContentType verifies body-fingerprint logic when
// no Content-Type header is present. Two distinct body bytes should survive as
// two separate entries; two identical bodies should collapse to one.
func TestDeduplicate_BodyWithoutContentType(t *testing.T) {
	t.Run("two distinct bodies survive", func(t *testing.T) {
		classified := []ClassifiedRequest{
			{
				ObservedRequest: crawl.ObservedRequest{
					Method: "POST",
					URL:    "https://example.com/api/data",
					// No Content-Type header
					Body: []byte("foo=1&bar=2"),
				},
				IsAPI: true, Confidence: 0.8, APIType: "rest",
			},
			{
				ObservedRequest: crawl.ObservedRequest{
					Method: "POST",
					URL:    "https://example.com/api/data",
					// No Content-Type header
					Body: []byte("baz=3&qux=4"),
				},
				IsAPI: true, Confidence: 0.8, APIType: "rest",
			},
		}
		result := Deduplicate(classified)
		assert.Len(t, result, 2, "two distinct bodies without Content-Type must not be merged")
	})

	t.Run("two identical bodies collapse to one", func(t *testing.T) {
		body := []byte("same=body&data=here")
		classified := []ClassifiedRequest{
			{
				ObservedRequest: crawl.ObservedRequest{
					Method: "POST",
					URL:    "https://example.com/api/data",
					Body:   body,
				},
				IsAPI: true, Confidence: 0.8, APIType: "rest",
			},
			{
				ObservedRequest: crawl.ObservedRequest{
					Method: "POST",
					URL:    "https://example.com/api/data",
					Body:   body,
				},
				IsAPI: true, Confidence: 0.9, APIType: "rest",
			},
		}
		result := Deduplicate(classified)
		require.Len(t, result, 1, "byte-identical bodies without Content-Type must collapse to one entry")
		assert.InDelta(t, 0.9, result[0].Confidence, 0.001, "highest confidence kept")
	})
}

// TestGetContentType verifies case-insensitive header lookup for Content-Type.
func TestGetContentType(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		want    string
	}{
		{
			name:    "empty headers",
			headers: map[string]string{},
			want:    "",
		},
		{
			name:    "exact case Content-Type",
			headers: map[string]string{"Content-Type": "application/json"},
			want:    "application/json",
		},
		{
			name:    "lowercase content-type",
			headers: map[string]string{"content-type": "application/json"},
			want:    "application/json",
		},
		{
			name:    "title-case Content-type",
			headers: map[string]string{"Content-type": "application/json"},
			want:    "application/json",
		},
		{
			name:    "uppercase CONTENT-TYPE",
			headers: map[string]string{"CONTENT-TYPE": "application/json"},
			want:    "application/json",
		},
		{
			name:    "absent header returns empty",
			headers: map[string]string{"Accept": "text/html"},
			want:    "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := getContentType(tc.headers)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestBaseMediaType verifies that mediatype.Base strips parameters and lowercases.
func TestBaseMediaType(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "plain application/json",
			input: "application/json",
			want:  "application/json",
		},
		{
			name:  "with parameters application/json; charset=utf-8",
			input: "application/json; charset=utf-8",
			want:  "application/json",
		},
		{
			name:  "lowercase normalization Application/JSON",
			input: "Application/JSON",
			want:  "application/json",
		},
		{
			name:  "whitespace handling",
			input: "  text/html  ; q=1",
			want:  "text/html",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := mediatype.Base(tc.input)
			assert.Equal(t, tc.want, got)
		})
	}
}

// BenchmarkDeduplicate exercises the dedup hot path (key construction +
// body fingerprint when applicable) at varying scales. Establishes a
// baseline before stretch-goal performance work.
func BenchmarkDeduplicate(b *testing.B) {
	for _, n := range []int{100, 1000, 5000} {
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			// Build a fixture: n distinct POST observations, urlencoded bodies
			input := make([]ClassifiedRequest, n)
			for i := range n {
				input[i] = ClassifiedRequest{
					ObservedRequest: crawl.ObservedRequest{
						Method:  "POST",
						URL:     fmt.Sprintf("https://example.com/api/endpoint%d", i%50),
						Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
						Body:    fmt.Appendf(nil, "name=u%d&value=%d", i, i),
					},
					IsAPI: true, Confidence: 0.9, APIType: "rest",
				}
			}
			b.ResetTimer()
			for b.Loop() {
				_ = Deduplicate(input)
			}
		})
	}
}

// --- LAB-4678 Phase 1 ---

// TestDeduplicate_KeepsDistinctHosts verifies that the same METHOD:path on two
// different in-scope hosts (a same-domain scan can observe several) survives
// deduplication instead of collapsing and losing one host's observation.
func TestDeduplicate_KeepsDistinctHosts(t *testing.T) {
	classified := []ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:   "GET",
				URL:      "https://api.example.com/v1/users",
				Response: crawl.ObservedResponse{StatusCode: 200, ContentType: "application/json", Body: []byte(`{"a":1}`)},
			},
			IsAPI: true, Confidence: 0.9, APIType: "rest",
		},
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:   "GET",
				URL:      "https://www.example.com/v1/users",
				Response: crawl.ObservedResponse{StatusCode: 200, ContentType: "application/json", Body: []byte(`{"b":2}`)},
			},
			IsAPI: true, Confidence: 0.9, APIType: "rest",
		},
	}

	result := Deduplicate(classified)
	assert.Len(t, result, 2, "same path on distinct hosts must not merge")
}

// TestDeduplicate_SameHostDefaultPortCollapses verifies the host in the dedup
// key is canonicalized: an explicit :443 on https collapses with the bare host,
// so a default-port variation does not create a spurious duplicate endpoint.
func TestDeduplicate_SameHostDefaultPortCollapses(t *testing.T) {
	classified := []ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{Method: "GET", URL: "https://example.com/v1/users"},
			IsAPI:           true, Confidence: 0.9, APIType: "rest",
		},
		{
			ObservedRequest: crawl.ObservedRequest{Method: "GET", URL: "https://example.com:443/v1/users"},
			IsAPI:           true, Confidence: 0.9, APIType: "rest",
		},
	}

	result := Deduplicate(classified)
	assert.Len(t, result, 1, "https default port :443 must canonicalize to the bare host")
}

// TestNearMisses returns only endpoints in the [floor, threshold) band: an
// endpoint with real-but-weak signal (path heuristic alone) is a near-miss,
// a static asset (0 confidence) is excluded, and a strong API (>= threshold)
// is excluded because it is emitted, not a miss.
func TestNearMisses(t *testing.T) {
	classifiers := []APIClassifier{&RESTClassifier{}}
	requests := []crawl.ObservedRequest{
		// Path heuristic only (0.15): below threshold but a real near-miss.
		{Method: "GET", URL: "https://ex.com/api/thing"},
		// Static asset: Rule 1 excludes -> confidence 0, below floor.
		{Method: "GET", URL: "https://ex.com/static/app.css"},
		// Strong API (JSON response, 0.85): at/above threshold, emitted not missed.
		{
			Method: "GET", URL: "https://ex.com/api/data",
			Response: crawl.ObservedResponse{ContentType: "application/json", Body: []byte(`{"x":1}`)},
		},
	}

	nm := NearMisses(classifiers, requests, NearMissFloor, DefaultConfidenceThreshold)
	require.Len(t, nm, 1, "only the weak-signal endpoint is a near-miss")
	assert.Contains(t, nm[0].URL, "/api/thing")
	assert.GreaterOrEqual(t, nm[0].Confidence, NearMissFloor)
	assert.Less(t, nm[0].Confidence, DefaultConfidenceThreshold)
}
