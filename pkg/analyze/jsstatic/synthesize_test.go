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

package jsstatic

import (
	"encoding/json"
	"testing"

	restgen "github.com/praetorian-inc/vespasian/pkg/generate/rest"
)

func TestToRequests_TaggedSourceJS(t *testing.T) {
	endpoints := []ExtractedEndpoint{
		{Method: "GET", URL: "/api/x", SourceTag: SourceJS, OriginBundle: "https://h/app.js"},
	}
	reqs := toRequests(endpoints, "https://h/app.js")
	if len(reqs) != 1 {
		t.Fatalf("expected 1 request, got %d", len(reqs))
	}
	if reqs[0].Source != "static:js" {
		t.Errorf("expected Source=static:js, got %q", reqs[0].Source)
	}
}

func TestToRequests_TaggedSourceSourcemap(t *testing.T) {
	endpoints := []ExtractedEndpoint{
		{Method: "GET", URL: "/api/x", SourceTag: SourceSourcemap, OriginBundle: "https://h/app.js"},
	}
	reqs := toRequests(endpoints, "https://h/app.js")
	if len(reqs) != 1 {
		t.Fatalf("expected 1 request, got %d", len(reqs))
	}
	if reqs[0].Source != "static:js-sourcemap" {
		t.Errorf("expected Source=static:js-sourcemap, got %q", reqs[0].Source)
	}
}

func TestToRequests_BodyFieldsToSyntheticJSON(t *testing.T) {
	endpoints := []ExtractedEndpoint{
		{Method: "POST", URL: "/api/x", BodyFields: []string{"name", "email"}, SourceTag: SourceJS, OriginBundle: "https://h/app.js"},
	}
	reqs := toRequests(endpoints, "https://h/app.js")
	if len(reqs) != 1 {
		t.Fatalf("expected 1 request, got %d", len(reqs))
	}
	want := `{"email":null,"name":null}`
	got := string(reqs[0].Body)
	if got != want {
		t.Errorf("expected Body=%s, got %s", want, got)
	}
}

func TestToRequests_NoBodyForGET(t *testing.T) {
	endpoints := []ExtractedEndpoint{
		{Method: "GET", URL: "/api/x", BodyFields: []string{}, SourceTag: SourceJS, OriginBundle: "https://h/app.js"},
	}
	reqs := toRequests(endpoints, "https://h/app.js")
	if len(reqs) != 1 {
		t.Fatalf("expected 1 request, got %d", len(reqs))
	}
	if reqs[0].Body != nil {
		t.Errorf("expected nil Body for GET, got %s", string(reqs[0].Body))
	}
}

func TestToRequests_NoBodyForPOSTWithoutFields(t *testing.T) {
	endpoints := []ExtractedEndpoint{
		{Method: "POST", URL: "/api/x", BodyFields: []string{}, SourceTag: SourceJS, OriginBundle: "https://h/app.js"},
	}
	reqs := toRequests(endpoints, "https://h/app.js")
	if len(reqs) != 1 {
		t.Fatalf("expected 1 request, got %d", len(reqs))
	}
	if reqs[0].Body != nil {
		t.Errorf("expected nil Body for POST without fields, got %s", string(reqs[0].Body))
	}
}

func TestToRequests_RelativeURLResolution(t *testing.T) {
	endpoints := []ExtractedEndpoint{
		{Method: "GET", URL: "/api/x", SourceTag: SourceJS, OriginBundle: "https://h/app.js"},
	}
	reqs := toRequests(endpoints, "https://h/app.js")
	if len(reqs) != 1 {
		t.Fatalf("expected 1 request, got %d", len(reqs))
	}
	want := "https://h/api/x"
	if reqs[0].URL != want {
		t.Errorf("expected URL=%s, got %s", want, reqs[0].URL)
	}
}

func TestToRequests_AbsoluteURLPreserved(t *testing.T) {
	endpoints := []ExtractedEndpoint{
		{Method: "GET", URL: "https://other/x", SourceTag: SourceJS, OriginBundle: "https://h/app.js"},
	}
	reqs := toRequests(endpoints, "https://h/app.js")
	if len(reqs) != 1 {
		t.Fatalf("expected 1 request, got %d", len(reqs))
	}
	if reqs[0].URL != "https://other/x" {
		t.Errorf("expected URL=https://other/x, got %s", reqs[0].URL)
	}
}

func TestToRequests_ContentTypeHeader(t *testing.T) {
	endpoints := []ExtractedEndpoint{
		{Method: "POST", URL: "/api/x", ContentType: "application/json", SourceTag: SourceJS, OriginBundle: "https://h/app.js"},
	}
	reqs := toRequests(endpoints, "https://h/app.js")
	if len(reqs) != 1 {
		t.Fatalf("expected 1 request, got %d", len(reqs))
	}
	ct := reqs[0].Headers["Content-Type"]
	if ct != "application/json" {
		t.Errorf("expected Content-Type=application/json, got %q", ct)
	}
}

func TestToRequests_PageURLPropagated(t *testing.T) {
	endpoints := []ExtractedEndpoint{
		{Method: "GET", URL: "/api/x", PageURL: "https://h/page", SourceTag: SourceJS, OriginBundle: "https://h/app.js"},
	}
	reqs := toRequests(endpoints, "https://h/app.js")
	if len(reqs) != 1 {
		t.Fatalf("expected 1 request, got %d", len(reqs))
	}
	if reqs[0].PageURL != "https://h/page" {
		t.Errorf("expected PageURL=https://h/page, got %s", reqs[0].PageURL)
	}
}

// relative endpoints should resolve against PageURL when available.
func TestToRequests_RelativeEndpoint_ResolvedAgainstPageURL(t *testing.T) {
	// Bundle at /static/js/app.js, PageURL at /dashboard.
	// endpoint "api/users" is relative to the page, not the bundle.
	endpoints := []ExtractedEndpoint{
		{
			Method:       "GET",
			URL:          "api/users",
			PageURL:      "https://h/dashboard",
			SourceTag:    SourceJS,
			OriginBundle: "https://h/static/js/app.js",
		},
	}
	reqs := toRequests(endpoints, "https://h/static/js/app.js")
	if len(reqs) != 1 {
		t.Fatalf("expected 1 request, got %d", len(reqs))
	}
	// Should resolve relative to page URL: https://h/api/users
	want := "https://h/api/users"
	if reqs[0].URL != want {
		t.Errorf("expected URL=%s (resolved against PageURL), got %s", want, reqs[0].URL)
	}
}

// When PageURL is empty, fallback to captureURL (the bundle URL). This test
// uses a non-root bundle path so the bundle-base resolution yields a URL that
// is distinguishable from a hypothetical page-base resolution. If a future
// change accidentally swapped the precedence, this test would fail.
func TestToRequests_RelativeEndpoint_FallsBackToCaptureURL(t *testing.T) {
	endpoints := []ExtractedEndpoint{
		{
			Method:       "GET",
			URL:          "api/users",
			PageURL:      "", // empty → must fall back to captureURL
			SourceTag:    SourceJS,
			OriginBundle: "https://h/static/js/app.js",
		},
	}
	reqs := toRequests(endpoints, "https://h/static/js/app.js")
	if len(reqs) != 1 {
		t.Fatalf("expected 1 request, got %d", len(reqs))
	}
	// captureURL is the bundle URL "https://h/static/js/app.js"; relative
	// resolution against that base yields "https://h/static/js/api/users".
	// (Page-base would have yielded "https://h/api/users", which is rejected
	// by this assertion if precedence is wrong.)
	want := "https://h/static/js/api/users"
	if reqs[0].URL != want {
		t.Errorf("expected URL=%s (bundle-base fallback), got %s", want, reqs[0].URL)
	}
}

func TestToRequests_InferSchemaCompatible(t *testing.T) {
	endpoints := []ExtractedEndpoint{
		{Method: "POST", URL: "/api/x", BodyFields: []string{"name", "email"}, SourceTag: SourceJS, OriginBundle: "https://h/app.js"},
	}
	reqs := toRequests(endpoints, "https://h/app.js")
	if len(reqs) != 1 {
		t.Fatalf("expected 1 request, got %d", len(reqs))
	}

	// Verify body is valid JSON.
	var parsed map[string]interface{}
	if err := json.Unmarshal(reqs[0].Body, &parsed); err != nil {
		t.Fatalf("Body is not valid JSON: %v", err)
	}

	// InferSchema should return a non-nil object schema.
	schema := restgen.InferSchema(reqs[0].Body)
	if schema == nil {
		t.Fatal("InferSchema returned nil for synthetic body")
	}
	if schema.Value == nil || schema.Value.Properties == nil {
		t.Fatal("InferSchema returned schema without properties")
	}
	if _, ok := schema.Value.Properties["name"]; !ok {
		t.Error("InferSchema schema missing 'name' property")
	}
	if _, ok := schema.Value.Properties["email"]; !ok {
		t.Error("InferSchema schema missing 'email' property")
	}
}
