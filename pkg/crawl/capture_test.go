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

package crawl

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// makeUniqueStrings returns a slice of n distinct strings "v", "vv", "vvv", ...
// Shared across TestCapQueryValues subtests (Rule of Three satisfied: 6+ callers).
func makeUniqueStrings(n int) []string {
	vs := make([]string, n)
	for i := range n {
		vs[i] = strings.Repeat("v", i+1)
	}
	return vs
}

// TestCapQueryValues (SEC-BE-001) verifies that CapQueryValues enforces the
// MaxQueryParamValues cap per key, mutates q in place, and handles edge cases.
func TestCapQueryValues(t *testing.T) {
	t.Run("under_cap_no_truncation", func(t *testing.T) {
		q := url.Values{"k": makeUniqueStrings(10)}
		got := CapQueryValues(q)
		if len(got["k"]) != 10 {
			t.Errorf("len = %d, want 10 (values under cap must not be truncated)", len(got["k"]))
		}
	})

	t.Run("exactly_at_cap_no_truncation", func(t *testing.T) {
		q := url.Values{"k": makeUniqueStrings(MaxQueryParamValues)}
		got := CapQueryValues(q)
		if len(got["k"]) != MaxQueryParamValues {
			t.Errorf("len = %d, want %d (values exactly at cap must not be truncated)", len(got["k"]), MaxQueryParamValues)
		}
	})

	t.Run("over_cap_truncates_to_MaxQueryParamValues", func(t *testing.T) {
		q := url.Values{"k": makeUniqueStrings(MaxQueryParamValues + 50)}
		got := CapQueryValues(q)
		if len(got["k"]) != MaxQueryParamValues {
			t.Errorf("len = %d, want %d (values over cap must be truncated)", len(got["k"]), MaxQueryParamValues)
		}
	})

	t.Run("multiple_keys_only_over_cap_keys_truncated", func(t *testing.T) {
		q := url.Values{
			"under": makeUniqueStrings(10),
			"at":    makeUniqueStrings(MaxQueryParamValues),
			"over":  makeUniqueStrings(MaxQueryParamValues + 20),
		}
		CapQueryValues(q)
		if len(q["under"]) != 10 {
			t.Errorf("q[under] len = %d, want 10 (under-cap key must not be truncated)", len(q["under"]))
		}
		if len(q["at"]) != MaxQueryParamValues {
			t.Errorf("q[at] len = %d, want %d (at-cap key must not be truncated)", len(q["at"]), MaxQueryParamValues)
		}
		if len(q["over"]) != MaxQueryParamValues {
			t.Errorf("q[over] len = %d, want %d (over-cap key must be truncated)", len(q["over"]), MaxQueryParamValues)
		}
	})

	t.Run("nil_map_returns_nil", func(t *testing.T) {
		// ranging over a nil map is a no-op in Go; CapQueryValues must not panic.
		got := CapQueryValues(nil)
		if got != nil {
			t.Errorf("got %v, want nil (nil input must return nil)", got)
		}
	})

	t.Run("empty_map_returns_empty", func(t *testing.T) {
		q := url.Values{}
		got := CapQueryValues(q)
		if len(got) != 0 {
			t.Errorf("len = %d, want 0 (empty map must return empty)", len(got))
		}
	})

	t.Run("mutation_in_place", func(t *testing.T) {
		// Callers in crawler.go / network.go / forms.go rely on CapQueryValues
		// mutating q and returning the same map -- not a copy.
		q := url.Values{"k": makeUniqueStrings(MaxQueryParamValues + 1)}
		got := CapQueryValues(q)
		// Same map identity: pointer equality via reflect.
		if reflect.ValueOf(q).Pointer() != reflect.ValueOf(got).Pointer() {
			t.Error("CapQueryValues must return the same map it received (mutation in place)")
		}
		// In-place mutation: q itself was modified, not a copy.
		if len(q["k"]) != MaxQueryParamValues {
			t.Errorf("q[k] len = %d after CapQueryValues, want %d (in-place mutation)", len(q["k"]), MaxQueryParamValues)
		}
	})
}

// TestCapture_MultiValueQueryParamsRoundTrip (TEST-003) verifies that an
// ObservedRequest with multi-value QueryParams survives a WriteCapture/ReadCapture
// round-trip with exact value preservation.
func TestCapture_MultiValueQueryParamsRoundTrip(t *testing.T) {
	original := []ObservedRequest{
		{
			Method: "GET",
			URL:    "https://example.com/api/items",
			QueryParams: map[string][]string{
				"tag": {"a", "b"},
			},
			Response: ObservedResponse{
				StatusCode: 200,
			},
			Source: "browser",
		},
	}

	var buf bytes.Buffer
	if err := WriteCapture(&buf, original); err != nil {
		t.Fatalf("WriteCapture failed: %v", err)
	}

	result, err := ReadCapture(&buf)
	if err != nil {
		t.Fatalf("ReadCapture failed: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("expected 1 request, got %d", len(result))
	}
	if !reflect.DeepEqual(original[0].QueryParams, result[0].QueryParams) {
		t.Errorf("QueryParams mismatch: want %v, got %v", original[0].QueryParams, result[0].QueryParams)
	}
}

// TestReadCapture_RejectsLegacyShape (TEST-003) verifies that the old
// map[string]string shape for query_params (used in versions ≤ LAB-2110)
// produces a non-nil unmarshal error rather than silently dropping values.
func TestReadCapture_RejectsLegacyShape(t *testing.T) {
	// Old shape: query_params is map[string]string, not map[string][]string.
	legacy := `[{"method":"GET","url":"http://x.test/","query_params":{"k":"v"},"response":{"status_code":200},"source":"test"}]`

	_, err := ReadCapture(strings.NewReader(legacy))
	if err == nil {
		t.Fatal("expected unmarshal error for legacy map[string]string shape, got nil")
	}
	var typeErr *json.UnmarshalTypeError
	if !errors.As(err, &typeErr) {
		t.Errorf("expected *json.UnmarshalTypeError, got %T: %v", err, err)
	}
}

func TestWriteCapture(t *testing.T) {
	t.Run("single request serializes correctly", func(t *testing.T) {
		requests := []ObservedRequest{
			{
				Method: "GET",
				URL:    "https://example.com/api/users",
				Headers: map[string]string{
					"User-Agent": "Mozilla/5.0",
				},
				QueryParams: map[string][]string{
					"page": {"1"},
				},
				Body: []byte("request body"),
				Response: ObservedResponse{
					StatusCode:  200,
					ContentType: "application/json",
					Body:        []byte("response body"),
					Headers: map[string]string{
						"Content-Type": "application/json",
					},
				},
				Source:  "browser",
				PageURL: "https://example.com/page",
			},
		}

		var buf bytes.Buffer
		err := WriteCapture(&buf, requests)
		if err != nil {
			t.Fatalf("WriteCapture failed: %v", err)
		}

		output := buf.String()
		if !strings.Contains(output, `"method": "GET"`) {
			t.Error("Output missing method field")
		}
		if !strings.Contains(output, `"url": "https://example.com/api/users"`) {
			t.Error("Output missing url field")
		}
		if !strings.Contains(output, `"status_code": 200`) {
			t.Error("Output missing status_code field")
		}
	})

	t.Run("multiple requests serialize correctly", func(t *testing.T) {
		requests := []ObservedRequest{
			{
				Method: "GET",
				URL:    "https://example.com/api/users",
				Response: ObservedResponse{
					StatusCode: 200,
				},
				Source: "browser",
			},
			{
				Method: "POST",
				URL:    "https://example.com/api/login",
				Response: ObservedResponse{
					StatusCode: 201,
				},
				Source: "xhr",
			},
		}

		var buf bytes.Buffer
		err := WriteCapture(&buf, requests)
		if err != nil {
			t.Fatalf("WriteCapture failed: %v", err)
		}

		output := buf.String()
		if !strings.Contains(output, `"method": "GET"`) {
			t.Error("Output missing first request method")
		}
		if !strings.Contains(output, `"method": "POST"`) {
			t.Error("Output missing second request method")
		}
		if !strings.Contains(output, `"status_code": 200`) {
			t.Error("Output missing first status code")
		}
		if !strings.Contains(output, `"status_code": 201`) {
			t.Error("Output missing second status code")
		}
	})

	t.Run("empty slice writes empty array", func(t *testing.T) {
		requests := []ObservedRequest{}

		var buf bytes.Buffer
		err := WriteCapture(&buf, requests)
		if err != nil {
			t.Fatalf("WriteCapture failed: %v", err)
		}

		output := strings.TrimSpace(buf.String())
		if output != "[]" {
			t.Errorf("Expected empty array '[]', got: %s", output)
		}
	})
}

func TestReadCapture(t *testing.T) {
	t.Run("valid JSON round-trips correctly", func(t *testing.T) {
		jsonData := `[
  {
    "method": "GET",
    "url": "https://example.com/api/users",
    "headers": {
      "User-Agent": "Mozilla/5.0"
    },
    "query_params": {
      "page": ["1"]
    },
    "body": "cmVxdWVzdCBib2R5",
    "response": {
      "status_code": 200,
      "headers": {
        "Content-Type": "application/json"
      },
      "content_type": "application/json",
      "body": "cmVzcG9uc2UgYm9keQ=="
    },
    "source": "browser",
    "page_url": "https://example.com/page"
  }
]`

		reader := strings.NewReader(jsonData)
		requests, err := ReadCapture(reader)
		if err != nil {
			t.Fatalf("ReadCapture failed: %v", err)
		}

		if len(requests) != 1 {
			t.Fatalf("Expected 1 request, got %d", len(requests))
		}

		req := requests[0]
		if req.Method != "GET" {
			t.Errorf("Expected method GET, got %s", req.Method)
		}
		if req.URL != "https://example.com/api/users" {
			t.Errorf("Expected URL https://example.com/api/users, got %s", req.URL)
		}
		if req.Response.StatusCode != 200 {
			t.Errorf("Expected status code 200, got %d", req.Response.StatusCode)
		}
		if req.Source != "browser" {
			t.Errorf("Expected source browser, got %s", req.Source)
		}
	})

	t.Run("empty array returns empty slice", func(t *testing.T) {
		jsonData := `[]`

		reader := strings.NewReader(jsonData)
		requests, err := ReadCapture(reader)
		if err != nil {
			t.Fatalf("ReadCapture failed: %v", err)
		}

		if len(requests) != 0 {
			t.Errorf("Expected empty slice, got %d requests", len(requests))
		}
	})

	t.Run("invalid JSON returns error", func(t *testing.T) {
		jsonData := `not valid json`

		reader := strings.NewReader(jsonData)
		_, err := ReadCapture(reader)
		if err == nil {
			t.Fatal("Expected error for invalid JSON, got nil")
		}
	})

	t.Run("malformed JSON returns error", func(t *testing.T) {
		jsonData := `[{"method": "GET", "url": "test"`

		reader := strings.NewReader(jsonData)
		_, err := ReadCapture(reader)
		if err == nil {
			t.Fatal("Expected error for malformed JSON, got nil")
		}
	})
}

// TestReadCapture_LimitedReader verifies ReadCapture uses limited reader
func TestReadCapture_LimitedReader(t *testing.T) {
	t.Run("large input within limit succeeds", func(t *testing.T) {
		// Create a JSON array with enough data to be significant but under MaxCaptureFileSize
		largeButValid := `[`
		for i := 0; i < 100; i++ {
			if i > 0 {
				largeButValid += ","
			}
			largeButValid += `{"method":"GET","url":"https://example.com/` + strings.Repeat("x", 1000) + `","response":{"status_code":200},"source":"test"}`
		}
		largeButValid += `]`

		reader := strings.NewReader(largeButValid)
		requests, err := ReadCapture(reader)
		if err != nil {
			t.Fatalf("ReadCapture failed for large valid input: %v", err)
		}

		if len(requests) != 100 {
			t.Errorf("Expected 100 requests, got %d", len(requests))
		}
	})

	t.Run("input exceeding MaxCaptureFileSize returns error", func(t *testing.T) {
		// Create a reader that produces more than MaxCaptureFileSize bytes
		// Use a custom reader that repeats data indefinitely
		infiniteReader := &infiniteJSONReader{remaining: MaxCaptureFileSize + 1000}
		_, err := ReadCapture(infiniteReader)
		if err == nil {
			t.Fatal("Expected error for input exceeding MaxCaptureFileSize, got nil")
		}
	})
}

// infiniteJSONReader is a test helper that produces JSON data up to a limit
type infiniteJSONReader struct {
	remaining int64
	started   bool
}

func (r *infiniteJSONReader) Read(p []byte) (n int, err error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}

	// Start with opening bracket
	if !r.started {
		r.started = true
		p[0] = '['
		r.remaining--
		return 1, nil
	}

	// Fill buffer with JSON-like data
	toWrite := int64(len(p))
	if toWrite > r.remaining {
		toWrite = r.remaining
	}

	for i := int64(0); i < toWrite; i++ {
		p[i] = 'x'
	}

	r.remaining -= toWrite
	return int(toWrite), nil
}

func TestWriteReadRoundTrip(t *testing.T) {
	t.Run("round-trip preserves all fields", func(t *testing.T) {
		original := []ObservedRequest{
			{
				Method: "POST",
				URL:    "https://example.com/api/data",
				Headers: map[string]string{
					"User-Agent":   "TestAgent/1.0",
					"Content-Type": "application/json",
				},
				QueryParams: map[string][]string{
					"id":    {"123"},
					"debug": {"true"},
				},
				Body: []byte("test request body"),
				Response: ObservedResponse{
					StatusCode:  201,
					ContentType: "application/json",
					Body:        []byte("test response body"),
					Headers: map[string]string{
						"X-Request-ID": "abc-123",
					},
				},
				Source:  "fetch",
				PageURL: "https://example.com/dashboard",
			},
		}

		// Write to buffer
		var buf bytes.Buffer
		err := WriteCapture(&buf, original)
		if err != nil {
			t.Fatalf("WriteCapture failed: %v", err)
		}

		// Read back from buffer
		result, err := ReadCapture(&buf)
		if err != nil {
			t.Fatalf("ReadCapture failed: %v", err)
		}

		// Compare using reflect.DeepEqual
		if !reflect.DeepEqual(original, result) {
			t.Errorf("Round-trip data mismatch.\nOriginal: %+v\nResult: %+v", original, result)
		}
	})

	t.Run("round-trip with multiple requests preserves order and data", func(t *testing.T) {
		original := []ObservedRequest{
			{
				Method: "GET",
				URL:    "https://example.com/first",
				Response: ObservedResponse{
					StatusCode: 200,
				},
				Source: "browser",
			},
			{
				Method: "POST",
				URL:    "https://example.com/second",
				Response: ObservedResponse{
					StatusCode: 201,
				},
				Source: "xhr",
			},
			{
				Method: "DELETE",
				URL:    "https://example.com/third",
				Response: ObservedResponse{
					StatusCode: 204,
				},
				Source: "fetch",
			},
		}

		// Write to buffer
		var buf bytes.Buffer
		err := WriteCapture(&buf, original)
		if err != nil {
			t.Fatalf("WriteCapture failed: %v", err)
		}

		// Read back from buffer
		result, err := ReadCapture(&buf)
		if err != nil {
			t.Fatalf("ReadCapture failed: %v", err)
		}

		// Compare using reflect.DeepEqual
		if !reflect.DeepEqual(original, result) {
			t.Errorf("Round-trip data mismatch")
		}

		// Verify order is preserved
		if len(result) != 3 {
			t.Fatalf("Expected 3 requests, got %d", len(result))
		}
		if result[0].Method != "GET" || result[1].Method != "POST" || result[2].Method != "DELETE" {
			t.Error("Request order not preserved")
		}
	})

	t.Run("round-trip with empty slice", func(t *testing.T) {
		original := []ObservedRequest{}

		// Write to buffer
		var buf bytes.Buffer
		err := WriteCapture(&buf, original)
		if err != nil {
			t.Fatalf("WriteCapture failed: %v", err)
		}

		// Read back from buffer
		result, err := ReadCapture(&buf)
		if err != nil {
			t.Fatalf("ReadCapture failed: %v", err)
		}

		// Empty slice should round-trip
		if len(result) != 0 {
			t.Errorf("Expected empty slice, got %d requests", len(result))
		}
	})

	t.Run("round-trip preserves omitempty fields", func(t *testing.T) {
		// Test with minimal fields (omitempty should omit Headers, QueryParams, Body, PageURL)
		original := []ObservedRequest{
			{
				Method: "GET",
				URL:    "https://example.com/minimal",
				Response: ObservedResponse{
					StatusCode: 200,
				},
				Source: "browser",
			},
		}

		// Write to buffer
		var buf bytes.Buffer
		err := WriteCapture(&buf, original)
		if err != nil {
			t.Fatalf("WriteCapture failed: %v", err)
		}

		// Read back from buffer
		result, err := ReadCapture(&buf)
		if err != nil {
			t.Fatalf("ReadCapture failed: %v", err)
		}

		// Compare - nil maps should be preserved as nil
		if !reflect.DeepEqual(original, result) {
			t.Errorf("Round-trip data mismatch.\nOriginal: %+v\nResult: %+v", original, result)
		}
	})
}

// TestCapQueryValues_KeyCap (SEC-BE-003) verifies that CapQueryValues enforces
// the MaxQueryParamKeys cap, drops excess keys deterministically in
// lexicographic order, and leaves the per-key value cap unchanged.
func TestCapQueryValues_KeyCap(t *testing.T) {
	t.Run("caps_distinct_keys_at_MaxQueryParamKeys", func(t *testing.T) {
		q := url.Values{}
		for i := 0; i < MaxQueryParamKeys+50; i++ {
			key := fmt.Sprintf("key%05d", i)
			q[key] = []string{"v"}
		}
		CapQueryValues(q)
		if len(q) != MaxQueryParamKeys {
			t.Errorf("len(q) = %d, want %d (keys over cap must be dropped)", len(q), MaxQueryParamKeys)
		}
	})

	t.Run("key_count_cap_is_deterministic_lexicographic", func(t *testing.T) {
		// Build two identical url.Values and verify the kept key sets are identical
		// and are the lex-smallest MaxQueryParamKeys keys.
		// Keys are "key00000" .. "key00561" (512+50=562 total); zero-padded so
		// lexicographic order matches numeric order.
		total := MaxQueryParamKeys + 50
		makeQ := func() url.Values {
			q := url.Values{}
			for i := 0; i < total; i++ {
				key := fmt.Sprintf("key%05d", i)
				q[key] = []string{"v"}
			}
			return q
		}

		q1 := makeQ()
		q2 := makeQ()
		CapQueryValues(q1)
		CapQueryValues(q2)

		// TEST-004: direct two-set equality via sorted slices — self-contained, no
		// implicit dependency on a preceding length check.
		keys1 := make([]string, 0, len(q1))
		for k := range q1 {
			keys1 = append(keys1, k)
		}
		sort.Strings(keys1)
		keys2 := make([]string, 0, len(q2))
		for k := range q2 {
			keys2 = append(keys2, k)
		}
		sort.Strings(keys2)
		if !reflect.DeepEqual(keys1, keys2) {
			t.Errorf("determinism failed: run1 kept %v, run2 kept %v", keys1, keys2)
		}

		// The kept keys must be the lex-smallest MaxQueryParamKeys keys.
		// "key00000" .. "key00511" sort before "key00512" .. "key00561".
		for i := 0; i < MaxQueryParamKeys; i++ {
			key := fmt.Sprintf("key%05d", i)
			if _, ok := q1[key]; !ok {
				t.Errorf("expected lex-smallest key %q to be retained, but it was dropped", key)
			}
		}
		// Keys from MaxQueryParamKeys onward must be dropped.
		for i := MaxQueryParamKeys; i < total; i++ {
			key := fmt.Sprintf("key%05d", i)
			if _, ok := q1[key]; ok {
				t.Errorf("expected key %q (past cap) to be dropped, but it was retained", key)
			}
		}
	})
}
