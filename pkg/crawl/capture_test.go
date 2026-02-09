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
	"reflect"
	"strings"
	"testing"
)

func TestWriteCapture(t *testing.T) {
	t.Run("single request serializes correctly", func(t *testing.T) {
		requests := []ObservedRequest{
			{
				Method: "GET",
				URL:    "https://example.com/api/users",
				Headers: map[string]string{
					"User-Agent": "Mozilla/5.0",
				},
				QueryParams: map[string]string{
					"page": "1",
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
      "page": "1"
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
				QueryParams: map[string]string{
					"id":    "123",
					"debug": "true",
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
