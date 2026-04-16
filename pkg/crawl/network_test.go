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
	"strings"
	"testing"

	"github.com/go-rod/rod/lib/proto"
	"github.com/ysmood/gson"
)

func TestMapNetworkToObservedRequest_Normal(t *testing.T) {
	req := &pendingRequest{
		method:      "POST",
		url:         "https://example.com/api/users?page=1&limit=10",
		headers:     map[string]string{"content-type": "application/json"},
		body:        `{"name":"Alice"}`,
		statusCode:  201,
		respHeaders: map[string]string{"content-type": "application/json"},
		contentType: "application/json",
		respBody:    []byte(`{"id":1,"name":"Alice"}`),
		complete:    true,
	}

	obs := mapNetworkToObservedRequest(req, "https://example.com/app")

	if obs.Method != "POST" {
		t.Errorf("Method = %q, want %q", obs.Method, "POST")
	}
	if obs.URL != "https://example.com/api/users?page=1&limit=10" {
		t.Errorf("URL = %q, want original", obs.URL)
	}
	if obs.Source != "browser" {
		t.Errorf("Source = %q, want %q", obs.Source, "browser")
	}
	if obs.PageURL != "https://example.com/app" {
		t.Errorf("PageURL = %q, want %q", obs.PageURL, "https://example.com/app")
	}
	if obs.QueryParams["page"] != "1" {
		t.Errorf("QueryParams[page] = %q, want %q", obs.QueryParams["page"], "1")
	}
	if obs.QueryParams["limit"] != "10" {
		t.Errorf("QueryParams[limit] = %q, want %q", obs.QueryParams["limit"], "10")
	}
	if string(obs.Body) != `{"name":"Alice"}` {
		t.Errorf("Body = %q, want request body", string(obs.Body))
	}
	if obs.Response.StatusCode != 201 {
		t.Errorf("Response.StatusCode = %d, want 201", obs.Response.StatusCode)
	}
	if obs.Response.ContentType != "application/json" {
		t.Errorf("Response.ContentType = %q, want %q", obs.Response.ContentType, "application/json")
	}
	if string(obs.Response.Body) != `{"id":1,"name":"Alice"}` {
		t.Errorf("Response.Body = %q, want response body", string(obs.Response.Body))
	}
}

func TestMapNetworkToObservedRequest_EmptyMethod(t *testing.T) {
	req := &pendingRequest{
		url: "https://example.com/page",
	}

	obs := mapNetworkToObservedRequest(req, "https://example.com/")
	if obs.Method != "GET" {
		t.Errorf("Method = %q, want %q (default)", obs.Method, "GET")
	}
}

func TestMapNetworkToObservedRequest_BodyTruncation(t *testing.T) {
	largeBody := strings.Repeat("x", MaxResponseBodySize+100)

	req := &pendingRequest{
		method:   "GET",
		url:      "https://example.com/large",
		respBody: []byte(largeBody),
		body:     largeBody,
		complete: true,
	}

	obs := mapNetworkToObservedRequest(req, "https://example.com/")

	if len(obs.Response.Body) != MaxResponseBodySize {
		t.Errorf("Response.Body len = %d, want %d (truncated)", len(obs.Response.Body), MaxResponseBodySize)
	}
	if len(obs.Body) != MaxResponseBodySize {
		t.Errorf("Body len = %d, want %d (truncated)", len(obs.Body), MaxResponseBodySize)
	}
}

func TestMapNetworkToObservedRequest_SmallBody(t *testing.T) {
	req := &pendingRequest{
		method:   "GET",
		url:      "https://example.com/small",
		respBody: []byte("small response"),
		complete: true,
	}

	obs := mapNetworkToObservedRequest(req, "https://example.com/")
	if string(obs.Response.Body) != "small response" {
		t.Errorf("Response.Body = %q, want %q", string(obs.Response.Body), "small response")
	}
}

func TestMapNetworkToObservedRequest_NoQueryParams(t *testing.T) {
	req := &pendingRequest{
		method: "GET",
		url:    "https://example.com/page",
	}

	obs := mapNetworkToObservedRequest(req, "https://example.com/")
	if len(obs.QueryParams) != 0 {
		t.Errorf("QueryParams = %v, want empty", obs.QueryParams)
	}
}

func TestMapNetworkToObservedRequest_NilHeaders(t *testing.T) {
	req := &pendingRequest{
		method: "GET",
		url:    "https://example.com/page",
	}

	obs := mapNetworkToObservedRequest(req, "https://example.com/")
	if obs.Headers != nil {
		t.Errorf("Headers = %v, want nil", obs.Headers)
	}
	if obs.Response.Headers != nil {
		t.Errorf("Response.Headers = %v, want nil", obs.Response.Headers)
	}
}

func TestTruncateBody(t *testing.T) {
	small := []byte("hello")
	if got := truncateBody(small); string(got) != "hello" {
		t.Errorf("truncateBody(small) = %q, want %q", string(got), "hello")
	}

	large := make([]byte, MaxResponseBodySize+500)
	for i := range large {
		large[i] = 'x'
	}
	if got := truncateBody(large); len(got) != MaxResponseBodySize {
		t.Errorf("truncateBody(large) len = %d, want %d", len(got), MaxResponseBodySize)
	}

	if got := truncateBody(nil); got != nil {
		t.Errorf("truncateBody(nil) = %v, want nil", got)
	}
}

func TestFlattenNetworkHeaders(t *testing.T) {
	headers := proto.NetworkHeaders{
		"Content-Type":    gson.New("application/json"),
		"X-Custom-Header": gson.New("value"),
	}

	flat := flattenNetworkHeaders(headers)
	if flat["content-type"] != "application/json" {
		t.Errorf("content-type = %q, want %q", flat["content-type"], "application/json")
	}
	if flat["x-custom-header"] != "value" {
		t.Errorf("x-custom-header = %q, want %q", flat["x-custom-header"], "value")
	}
}

func TestFlattenNetworkHeaders_Empty(t *testing.T) {
	flat := flattenNetworkHeaders(nil)
	if flat != nil {
		t.Errorf("flattenNetworkHeaders(nil) = %v, want nil", flat)
	}

	flat = flattenNetworkHeaders(proto.NetworkHeaders{})
	if flat != nil {
		t.Errorf("flattenNetworkHeaders({}) = %v, want nil", flat)
	}
}
