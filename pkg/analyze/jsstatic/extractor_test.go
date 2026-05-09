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
	"testing"
)

// helper: find the first endpoint matching the given URL (or all if wantURL is "").
func findEndpoint(endpoints []ExtractedEndpoint, wantURL string) *ExtractedEndpoint {
	for i := range endpoints {
		if endpoints[i].URL == wantURL || wantURL == "" {
			return &endpoints[i]
		}
	}
	return nil
}

func TestExtractFromBundle_Fetch(t *testing.T) {
	src := []byte(`fetch("/api/users")`)
	endpoints, err := ExtractFromBundle(src, "https://example.com/app.js", Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ep := findEndpoint(endpoints, "/api/users")
	if ep == nil {
		t.Fatalf("expected endpoint /api/users, got: %v", endpoints)
	}
	if ep.Method != "GET" {
		t.Errorf("Method = %q, want GET", ep.Method)
	}
}

func TestExtractFromBundle_FetchPostMethod(t *testing.T) {
	src := []byte(`fetch("/api/x", {method: "POST"})`)
	endpoints, err := ExtractFromBundle(src, "https://example.com/app.js", Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ep := findEndpoint(endpoints, "/api/x")
	if ep == nil {
		t.Fatalf("expected endpoint /api/x, got: %v", endpoints)
	}
	if ep.Method != "POST" {
		t.Errorf("Method = %q, want POST", ep.Method)
	}
}

func TestExtractFromBundle_FetchPostJSONStringify(t *testing.T) {
	// Task 5 tightened: BodyFields should contain the JSON.stringify object keys.
	src := []byte(`fetch("/api/x", {method:"POST", body: JSON.stringify({name, email})})`)
	endpoints, err := ExtractFromBundle(src, "https://example.com/app.js", Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ep := findEndpoint(endpoints, "/api/x")
	if ep == nil {
		t.Fatalf("expected endpoint /api/x, got: %v", endpoints)
	}
	if ep.Method != "POST" {
		t.Errorf("Method = %q, want POST", ep.Method)
	}
	// Alphabetically sorted per architecture.
	if len(ep.BodyFields) != 2 || ep.BodyFields[0] != "email" || ep.BodyFields[1] != "name" {
		t.Errorf("BodyFields = %v, want [email name]", ep.BodyFields)
	}
}

func TestExtractFromBundle_FetchTemplateLiteralPathParam(t *testing.T) {
	// Task 4 tightened: token recovery enabled, should use identifier name.
	src := []byte("fetch(`/api/users/${userId}`)")
	endpoints, err := ExtractFromBundle(src, "https://example.com/app.js", Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ep := findEndpoint(endpoints, "/api/users/{userId}")
	if ep == nil {
		t.Fatalf("expected endpoint /api/users/{userId}, got: %v", endpoints)
	}
}

func TestExtractFromBundle_FiltersAssetURLs(t *testing.T) {
	assets := []string{
		`fetch("/img/logo.png")`,
		`fetch("/styles/main.css")`,
		`fetch("/icons/ic.svg")`,
		`fetch("/fonts/font.woff2")`,
		`fetch("/app.js.map")`,
		`fetch("/bundle.js")`,
		`fetch("/favicon.ico")`,
	}
	for _, src := range assets {
		endpoints, err := ExtractFromBundle([]byte(src), "", Options{})
		if err != nil {
			t.Fatalf("unexpected error for %q: %v", src, err)
		}
		if len(endpoints) != 0 {
			t.Errorf("expected no endpoints for asset URL in %q, got: %v", src, endpoints)
		}
	}
}

func TestExtractFromBundle_FiltersDataAndJsSchemes(t *testing.T) {
	schemes := []string{
		`fetch("data:text/plain,hello")`,
		`fetch("javascript:void(0)")`,
		`fetch("blob:https://example.com/uuid")`,
		`fetch("mailto:user@example.com")`,
		`fetch("tel:+15551234567")`,
		`fetch("chrome-extension://abc/page.html")`,
	}
	for _, src := range schemes {
		endpoints, err := ExtractFromBundle([]byte(src), "", Options{})
		if err != nil {
			t.Fatalf("unexpected error for %q: %v", src, err)
		}
		if len(endpoints) != 0 {
			t.Errorf("expected no endpoints for scheme in %q, got: %v", src, endpoints)
		}
	}
}

func TestExtractFromBundle_FiltersExprOnlyURLs(t *testing.T) {
	// A URL that is purely EXPR should be dropped.
	src := []byte("fetch(someVar)")
	endpoints, err := ExtractFromBundle(src, "", Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Purely dynamic var -> jsluice may emit "EXPR"; filter it out.
	for _, ep := range endpoints {
		if ep.URL == "EXPR" || ep.URL == "" {
			t.Errorf("expected EXPR-only URL to be filtered, got: %v", ep)
		}
	}
}

func TestExtractFromBundle_AxiosGet(t *testing.T) {
	src := []byte(`axios.get("/api/items")`)
	endpoints, err := ExtractFromBundle(src, "", Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ep := findEndpoint(endpoints, "/api/items")
	if ep == nil {
		t.Fatalf("expected endpoint /api/items, got: %v", endpoints)
	}
	if ep.Method != "GET" {
		t.Errorf("Method = %q, want GET", ep.Method)
	}
}

func TestExtractFromBundle_AxiosPost(t *testing.T) {
	src := []byte(`axios.post("/api/x", {a, b})`)
	endpoints, err := ExtractFromBundle(src, "", Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ep := findEndpoint(endpoints, "/api/x")
	if ep == nil {
		t.Fatalf("expected endpoint /api/x, got: %v", endpoints)
	}
	if ep.Method != "POST" {
		t.Errorf("Method = %q, want POST", ep.Method)
	}
	if len(ep.BodyFields) != 2 || ep.BodyFields[0] != "a" || ep.BodyFields[1] != "b" {
		t.Errorf("BodyFields = %v, want [a b]", ep.BodyFields)
	}
}

func TestExtractFromBundle_AxiosConfigObject(t *testing.T) {
	src := []byte(`axios({url:"/api/x", method:"PUT", data:{x, y}})`)
	endpoints, err := ExtractFromBundle(src, "", Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ep := findEndpoint(endpoints, "/api/x")
	if ep == nil {
		t.Fatalf("expected endpoint /api/x, got: %v", endpoints)
	}
	if ep.Method != "PUT" {
		t.Errorf("Method = %q, want PUT", ep.Method)
	}
	if len(ep.BodyFields) != 2 || ep.BodyFields[0] != "x" || ep.BodyFields[1] != "y" {
		t.Errorf("BodyFields = %v, want [x y]", ep.BodyFields)
	}
}

func TestExtractFromBundle_AxiosShorthandPropertyKeys(t *testing.T) {
	src := []byte(`axios.post("/x", {name})`)
	endpoints, err := ExtractFromBundle(src, "", Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ep := findEndpoint(endpoints, "/x")
	if ep == nil {
		t.Fatalf("expected endpoint /x, got: %v", endpoints)
	}
	if len(ep.BodyFields) != 1 || ep.BodyFields[0] != "name" {
		t.Errorf("BodyFields = %v, want [name]", ep.BodyFields)
	}
}

func TestExtractFromBundle_AxiosUnknownMethodIgnored(t *testing.T) {
	src := []byte(`axios.unknown("/x")`)
	endpoints, err := ExtractFromBundle(src, "", Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should not be emitted.
	for _, ep := range endpoints {
		if ep.URL == "/x" {
			t.Errorf("unexpected endpoint from axios.unknown: %v", ep)
		}
	}
}

func TestExtractFromBundle_FetchPlainBodyStringIgnored(t *testing.T) {
	src := []byte(`fetch("/x", {body:"raw"})`)
	endpoints, err := ExtractFromBundle(src, "", Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ep := findEndpoint(endpoints, "/x")
	if ep != nil && len(ep.BodyFields) != 0 {
		t.Errorf("expected no BodyFields for plain body string, got: %v", ep.BodyFields)
	}
}

func TestExtractFromBundle_TemplateLiteralUnnamed(t *testing.T) {
	// Call expression inside template substitution -> not a recoverable name.
	src := []byte("fetch(`/api/${a()}/x`)")
	endpoints, err := ExtractFromBundle(src, "https://example.com/app.js", Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ep := findEndpoint(endpoints, "/api/{param}/x")
	if ep == nil {
		t.Fatalf("expected endpoint /api/{param}/x, got: %v", endpoints)
	}
}

func TestExtractFromBundle_TemplateLiteralMember(t *testing.T) {
	// member_expression: user.id -> rightmost name is 'id'.
	src := []byte("fetch(`/u/${user.id}`)")
	endpoints, err := ExtractFromBundle(src, "https://example.com/app.js", Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ep := findEndpoint(endpoints, "/u/{id}")
	if ep == nil {
		t.Fatalf("expected endpoint /u/{id}, got: %v", endpoints)
	}
}

func TestExtractFromBundle_EmptyInput(t *testing.T) {
	endpoints, err := ExtractFromBundle(nil, "", Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if endpoints != nil {
		t.Errorf("expected nil endpoints for empty input, got: %v", endpoints)
	}
}
