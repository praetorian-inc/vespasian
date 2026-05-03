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

// resolveFormAction is the pure attribute-resolution core of extractForms.
// Default-suite coverage for every branch.

// No action attribute → pageURL (HTML §4.10.21.3). This is the TEST-005
// regression: previously the no-action branch used baseURL, so a login
// form with no action on /login with <base href="/"> reported its
// endpoint as "/" instead of "/login".
func TestResolveFormAction_NoActionUsesPageURL(t *testing.T) {
	got, ok := resolveFormAction("", "https://ex.com/login", "https://ex.com/")
	if !ok || got != "https://ex.com/login" {
		t.Errorf("got (%q, %v), want (%q, true)", got, ok, "https://ex.com/login")
	}
}

func TestResolveFormAction_WhitespaceActionUsesPageURL(t *testing.T) {
	got, ok := resolveFormAction("   \t\n", "https://ex.com/login", "https://ex.com/")
	if !ok || got != "https://ex.com/login" {
		t.Errorf("got (%q, %v), want (%q, true)", got, ok, "https://ex.com/login")
	}
}

// Relative action resolves against baseURL, not pageURL — this is the
// TEST-003 coverage gap. A regression that passed pageURL to resolveURL
// would produce https://ex.com/deep/page/api/login instead.
func TestResolveFormAction_RootRelativeResolvesAgainstBase(t *testing.T) {
	got, ok := resolveFormAction("/api/login", "https://ex.com/deep/page", "https://ex.com/")
	if !ok || got != "https://ex.com/api/login" {
		t.Errorf("got (%q, %v), want (%q, true)", got, ok, "https://ex.com/api/login")
	}
}

// Bare relative action resolves against baseURL, not deep/page — TEST-004.
func TestResolveFormAction_BareRelativeResolvesAgainstBase(t *testing.T) {
	got, ok := resolveFormAction("submit", "https://ex.com/deep/page", "https://ex.com/")
	if !ok || got != "https://ex.com/submit" {
		t.Errorf("got (%q, %v), want (%q, true)", got, ok, "https://ex.com/submit")
	}
}

// Absolute HTTPS action passes through unchanged.
func TestResolveFormAction_AbsoluteAction(t *testing.T) {
	got, ok := resolveFormAction("https://ex.com/api/login", "https://ex.com/login", "https://ex.com/")
	if !ok || got != "https://ex.com/api/login" {
		t.Errorf("got (%q, %v), want (%q, true)", got, ok, "https://ex.com/api/login")
	}
}

// Non-navigable schemes are rejected so the caller can drop the form —
// TEST-001 coverage for javascript:, mailto:, data:, tel:, blob:.
func TestResolveFormAction_NonNavigableSchemesRejected(t *testing.T) {
	cases := []string{
		"javascript:void(0)",
		"mailto:x@y.com",
		"data:text/html,<x>",
		"tel:+1234567890",
		"blob:https://ex.com/abc",
	}
	for _, raw := range cases {
		got, ok := resolveFormAction(raw, "https://ex.com/login", "https://ex.com/")
		if ok || got != "" {
			t.Errorf("resolveFormAction(%q, ...) = (%q, %v), want (\"\", false)", raw, got, ok)
		}
	}
}

// Malformed action → ("", false) so the form is skipped.
func TestResolveFormAction_MalformedActionRejected(t *testing.T) {
	got, ok := resolveFormAction("http://[::1:", "https://ex.com/login", "https://ex.com/")
	if ok || got != "" {
		t.Errorf("got (%q, %v), want (\"\", false)", got, ok)
	}
}
