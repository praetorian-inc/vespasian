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
)

func TestFormsToObservedRequests_PostForm(t *testing.T) {
	forms := []discoveredForm{
		{
			Action:      "https://example.com/api/login",
			Method:      "POST",
			ContentType: "application/x-www-form-urlencoded",
			Fields: map[string]string{
				"username": "admin",
				"password": "",
			},
		},
	}

	results := formsToObservedRequests(forms, "https://example.com/login")

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	r := results[0]
	if r.Method != "POST" {
		t.Errorf("Method = %q, want POST", r.Method)
	}
	if r.URL != "https://example.com/api/login" {
		t.Errorf("URL = %q, want %q", r.URL, "https://example.com/api/login")
	}
	if r.Source != "form" {
		t.Errorf("Source = %q, want %q", r.Source, "form")
	}
	if r.PageURL != "https://example.com/login" {
		t.Errorf("PageURL = %q, want %q", r.PageURL, "https://example.com/login")
	}
	if r.Headers["content-type"] != "application/x-www-form-urlencoded" {
		t.Errorf("content-type header = %q, want %q", r.Headers["content-type"], "application/x-www-form-urlencoded")
	}

	body := string(r.Body)
	if !strings.Contains(body, "username=admin") {
		t.Errorf("body = %q, expected username=admin", body)
	}
	if !strings.Contains(body, "password=") {
		t.Errorf("body = %q, expected password=", body)
	}
}

func TestFormsToObservedRequests_GetForm(t *testing.T) {
	forms := []discoveredForm{
		{
			Action: "https://example.com/search",
			Method: "GET",
			Fields: map[string]string{
				"q":    "test",
				"page": "1",
			},
		},
	}

	results := formsToObservedRequests(forms, "https://example.com/")

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	r := results[0]
	if r.Method != "GET" {
		t.Errorf("Method = %q, want GET", r.Method)
	}
	// GET forms should merge fields into query params.
	if r.QueryParams["q"] != "test" {
		t.Errorf("QueryParams[q] = %q, want %q", r.QueryParams["q"], "test")
	}
	if r.QueryParams["page"] != "1" {
		t.Errorf("QueryParams[page] = %q, want %q", r.QueryParams["page"], "1")
	}
	// Body should be empty for GET.
	if len(r.Body) > 0 {
		t.Errorf("GET form should have empty body, got %q", string(r.Body))
	}
}

func TestFormsToObservedRequests_NoFields(t *testing.T) {
	forms := []discoveredForm{
		{
			Action: "https://example.com/submit",
			Method: "POST",
			Fields: map[string]string{},
		},
	}

	results := formsToObservedRequests(forms, "https://example.com/")
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Method != "POST" {
		t.Errorf("Method = %q, want POST", results[0].Method)
	}
}

func TestFormsToObservedRequests_MultipartEnctype(t *testing.T) {
	forms := []discoveredForm{
		{
			Action:      "https://example.com/upload",
			Method:      "POST",
			ContentType: "multipart/form-data",
			Fields: map[string]string{
				"name": "test",
			},
		},
	}

	results := formsToObservedRequests(forms, "https://example.com/")
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Headers["content-type"] != "multipart/form-data" {
		t.Errorf("content-type = %q, want multipart/form-data", results[0].Headers["content-type"])
	}
}

func TestFormsToObservedRequests_Empty(t *testing.T) {
	results := formsToObservedRequests(nil, "https://example.com/")
	if results != nil {
		t.Errorf("expected nil for empty forms, got %v", results)
	}
}

func TestDiscoveredForm_DefaultValues(t *testing.T) {
	// Verify default struct behavior for method and content type.
	df := discoveredForm{
		Action: "https://example.com/test",
		Fields: map[string]string{"x": "1"},
	}

	// Method defaults should be set by extractForms, but if empty, formsToObservedRequests
	// should still produce valid output.
	results := formsToObservedRequests([]discoveredForm{df}, "https://example.com/")
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	// Empty method means GET form behavior (fields in query params).
	if !strings.Contains(results[0].URL, "x=1") {
		t.Errorf("expected query param in URL for GET form, got %q", results[0].URL)
	}
}
