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
	"testing"

	"github.com/projectdiscovery/katana/pkg/navigation"
	"github.com/projectdiscovery/katana/pkg/output"
)

// TestMapScope tests the MapScope function with table-driven tests
func TestMapScope(t *testing.T) {
	tests := []struct {
		name  string
		scope string
		want  string
	}{
		{
			name:  "same-origin maps to fqdn",
			scope: "same-origin",
			want:  "fqdn",
		},
		{
			name:  "same-domain maps to rdn",
			scope: "same-domain",
			want:  "rdn",
		},
		{
			name:  "empty string defaults to fqdn",
			scope: "",
			want:  "fqdn",
		},
		{
			name:  "unknown scope defaults to fqdn",
			scope: "unknown",
			want:  "fqdn",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MapScope(tt.scope)
			if got != tt.want {
				t.Errorf("MapScope(%q) = %q, want %q", tt.scope, got, tt.want)
			}
		})
	}
}

// TestMapResult_Normal tests MapResult with a normal result
func TestMapResult_Normal(t *testing.T) {
	result := output.Result{
		Request: &navigation.Request{
			Method: "POST",
			URL:    "https://example.com/api?foo=bar&baz=qux",
			Body:   "request body",
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
			Source: "crawler",
		},
		Response: &navigation.Response{
			StatusCode: 200,
			Headers: navigation.Headers{
				"Content-Type": "text/html",
			},
			Body: "response body",
		},
	}

	observed := MapResult(result)

	if observed.Method != "POST" {
		t.Errorf("Method = %q, want %q", observed.Method, "POST")
	}
	if observed.URL != "https://example.com/api?foo=bar&baz=qux" {
		t.Errorf("URL = %q, want %q", observed.URL, "https://example.com/api?foo=bar&baz=qux")
	}
	if string(observed.Body) != "request body" {
		t.Errorf("Body = %q, want %q", string(observed.Body), "request body")
	}
	if observed.Source != "crawler" {
		t.Errorf("Source = %q, want %q", observed.Source, "crawler")
	}
	if observed.Headers["Content-Type"] != "application/json" {
		t.Errorf("Headers[Content-Type] = %q, want %q", observed.Headers["Content-Type"], "application/json")
	}

	// Check query params
	if len(observed.QueryParams) != 2 {
		t.Errorf("QueryParams length = %d, want 2", len(observed.QueryParams))
	}
	if observed.QueryParams["foo"] != "bar" {
		t.Errorf("QueryParams[foo] = %q, want %q", observed.QueryParams["foo"], "bar")
	}
	if observed.QueryParams["baz"] != "qux" {
		t.Errorf("QueryParams[baz] = %q, want %q", observed.QueryParams["baz"], "qux")
	}

	// Check response
	if observed.Response.StatusCode != 200 {
		t.Errorf("Response.StatusCode = %d, want 200", observed.Response.StatusCode)
	}
	if observed.Response.ContentType != "text/html" {
		t.Errorf("Response.ContentType = %q, want %q", observed.Response.ContentType, "text/html")
	}
	if string(observed.Response.Body) != "response body" {
		t.Errorf("Response.Body = %q, want %q", string(observed.Response.Body), "response body")
	}
}

// TestMapResult_EmptyMethod tests MapResult defaults to GET when method is empty
func TestMapResult_EmptyMethod(t *testing.T) {
	result := output.Result{
		Request: &navigation.Request{
			Method: "",
			URL:    "https://example.com",
		},
	}

	observed := MapResult(result)

	if observed.Method != "GET" {
		t.Errorf("Method = %q, want %q", observed.Method, "GET")
	}
}

// TestMapResult_NilRequest tests MapResult handles nil Request pointer
func TestMapResult_NilRequest(t *testing.T) {
	result := output.Result{
		Request: nil,
		Response: &navigation.Response{
			StatusCode: 200,
		},
	}

	// Should not panic
	observed := MapResult(result)

	if observed.Method != "GET" {
		t.Errorf("Method = %q, want %q (default)", observed.Method, "GET")
	}
	if observed.Source != "katana" {
		t.Errorf("Source = %q, want %q (default)", observed.Source, "katana")
	}
	if observed.Response.StatusCode != 200 {
		t.Errorf("Response.StatusCode = %d, want 200", observed.Response.StatusCode)
	}
}

// TestMapResult_NilResponse tests MapResult handles nil Response pointer
func TestMapResult_NilResponse(t *testing.T) {
	result := output.Result{
		Request: &navigation.Request{
			Method: "GET",
			URL:    "https://example.com",
		},
		Response: nil,
	}

	// Should not panic
	observed := MapResult(result)

	if observed.Method != "GET" {
		t.Errorf("Method = %q, want %q", observed.Method, "GET")
	}
	if observed.Response.StatusCode != 0 {
		t.Errorf("Response.StatusCode = %d, want 0 (zero value)", observed.Response.StatusCode)
	}
}

// TestMapResult_URLWithoutQueryParams tests MapResult with URL without query params
func TestMapResult_URLWithoutQueryParams(t *testing.T) {
	result := output.Result{
		Request: &navigation.Request{
			URL: "https://example.com/path",
		},
	}

	observed := MapResult(result)

	if len(observed.QueryParams) != 0 {
		t.Errorf("QueryParams length = %d, want 0", len(observed.QueryParams))
	}
}

// TestMapResult_InvalidURL tests MapResult with invalid URL
func TestMapResult_InvalidURL(t *testing.T) {
	result := output.Result{
		Request: &navigation.Request{
			URL: "://invalid-url",
		},
	}

	// Should not panic, query params just won't be parsed
	observed := MapResult(result)

	if observed.QueryParams != nil {
		t.Errorf("QueryParams = %v, want nil (failed parse)", observed.QueryParams)
	}
}

// TestToStringSlice tests ToStringSlice conversion
func TestToStringSlice(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		wantLen int
	}{
		{
			name: "single header",
			headers: map[string]string{
				"Authorization": "Bearer token123",
			},
			wantLen: 1,
		},
		{
			name: "multiple headers",
			headers: map[string]string{
				"Content-Type":  "application/json",
				"Authorization": "Bearer token123",
				"User-Agent":    "vespasian/1.0",
			},
			wantLen: 3,
		},
		{
			name:    "nil map",
			headers: nil,
			wantLen: 0,
		},
		{
			name:    "empty map",
			headers: map[string]string{},
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ToStringSlice(tt.headers)

			if len(result) != tt.wantLen {
				t.Errorf("ToStringSlice() length = %d, want %d", len(result), tt.wantLen)
			}

			// Verify format for non-empty results
			if tt.wantLen > 0 {
				// Build a map to check all headers are present
				found := make(map[string]bool)
				for _, header := range result {
					found[header] = true
				}

				for key, value := range tt.headers {
					expected := key + ": " + value
					if !found[expected] {
						t.Errorf("ToStringSlice() missing header %q", expected)
					}
				}
			}
		})
	}
}

// TestToStringSlice_Format verifies the exact format of header strings
func TestToStringSlice_Format(t *testing.T) {
	headers := map[string]string{
		"Content-Type": "application/json",
	}

	result := ToStringSlice(headers)

	if len(result) != 1 {
		t.Fatalf("ToStringSlice() length = %d, want 1", len(result))
	}

	// goflags.StringSlice is a []string
	if result[0] != "Content-Type: application/json" {
		t.Errorf("ToStringSlice()[0] = %q, want %q", result[0], "Content-Type: application/json")
	}
}

// TestNewCrawler tests the constructor
func TestNewCrawler(t *testing.T) {
	opts := CrawlerOptions{
		Depth:    5,
		MaxPages: 100,
		Scope:    "same-domain",
		Headless: true,
		Headers: map[string]string{
			"User-Agent": "test",
		},
	}

	crawler := NewCrawler(opts)

	if crawler == nil {
		t.Fatal("NewCrawler() returned nil")
	}

	if crawler.opts.Depth != 5 {
		t.Errorf("crawler.opts.Depth = %d, want 5", crawler.opts.Depth)
	}
	if crawler.opts.MaxPages != 100 {
		t.Errorf("crawler.opts.MaxPages = %d, want 100", crawler.opts.MaxPages)
	}
	if crawler.opts.Scope != "same-domain" {
		t.Errorf("crawler.opts.Scope = %q, want %q", crawler.opts.Scope, "same-domain")
	}
	if !crawler.opts.Headless {
		t.Errorf("crawler.opts.Headless = false, want true")
	}
	if crawler.opts.Headers["User-Agent"] != "test" {
		t.Errorf("crawler.opts.Headers[User-Agent] = %q, want %q", crawler.opts.Headers["User-Agent"], "test")
	}
}

// TestDefaultMaxPages verifies the DefaultMaxPages constant value
func TestDefaultMaxPages(t *testing.T) {
	if DefaultMaxPages != 1000 {
		t.Errorf("DefaultMaxPages = %d, want 1000", DefaultMaxPages)
	}
}

// TestMaxResponseBodySize verifies the MaxResponseBodySize constant value
func TestMaxResponseBodySize(t *testing.T) {
	expected := 1 * 1024 * 1024 // 1 MB
	if MaxResponseBodySize != expected {
		t.Errorf("MaxResponseBodySize = %d, want %d", MaxResponseBodySize, expected)
	}
}


// TestPageTimeout verifies the PageTimeout constant value
func TestPageTimeout(t *testing.T) {
	if PageTimeout != 30 {
		t.Errorf("PageTimeout = %d, want 30", PageTimeout)
	}
}
// TestMapResult_TruncatesLargeResponseBody tests that response bodies exceeding MaxResponseBodySize get truncated
func TestMapResult_TruncatesLargeResponseBody(t *testing.T) {
	largeBody := make([]byte, MaxResponseBodySize+1000) // 1000 bytes over limit
	for i := range largeBody {
		largeBody[i] = byte('A')
	}

	result := output.Result{
		Request: &navigation.Request{
			Method: "GET",
			URL:    "https://example.com",
		},
		Response: &navigation.Response{
			StatusCode: 200,
			Body:       string(largeBody),
		},
	}

	observed := MapResult(result)

	if len(observed.Response.Body) != MaxResponseBodySize {
		t.Errorf("Response body length = %d, want %d (truncated)", len(observed.Response.Body), MaxResponseBodySize)
	}

	// Verify all bytes are 'A' (no corruption during truncation)
	for i, b := range observed.Response.Body {
		if b != byte('A') {
			t.Errorf("Response body[%d] = %c, want 'A' (truncation corrupted data)", i, b)
			break
		}
	}
}

// TestMapResult_TruncatesLargeRequestBody tests that request bodies exceeding MaxResponseBodySize get truncated
func TestMapResult_TruncatesLargeRequestBody(t *testing.T) {
	largeBody := make([]byte, MaxResponseBodySize+500) // 500 bytes over limit
	for i := range largeBody {
		largeBody[i] = byte('B')
	}

	result := output.Result{
		Request: &navigation.Request{
			Method: "POST",
			URL:    "https://example.com",
			Body:   string(largeBody),
		},
	}

	observed := MapResult(result)

	if len(observed.Body) != MaxResponseBodySize {
		t.Errorf("Request body length = %d, want %d (truncated)", len(observed.Body), MaxResponseBodySize)
	}

	// Verify all bytes are 'B' (no corruption during truncation)
	for i, b := range observed.Body {
		if b != byte('B') {
			t.Errorf("Request body[%d] = %c, want 'B' (truncation corrupted data)", i, b)
			break
		}
	}
}

// TestMapResult_SmallBodyNotTruncated tests that bodies under the limit are preserved
func TestMapResult_SmallBodyNotTruncated(t *testing.T) {
	smallRequestBody := []byte("small request body")
	smallResponseBody := []byte("small response body")

	result := output.Result{
		Request: &navigation.Request{
			Method: "POST",
			URL:    "https://example.com",
			Body:   string(smallRequestBody),
		},
		Response: &navigation.Response{
			StatusCode: 200,
			Body:       string(smallResponseBody),
		},
	}

	observed := MapResult(result)

	if string(observed.Body) != string(smallRequestBody) {
		t.Errorf("Request body = %q, want %q (should not be truncated)", string(observed.Body), string(smallRequestBody))
	}

	if string(observed.Response.Body) != string(smallResponseBody) {
		t.Errorf("Response body = %q, want %q (should not be truncated)", string(observed.Response.Body), string(smallResponseBody))
	}
}
