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
