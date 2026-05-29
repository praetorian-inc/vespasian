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
	"strings"
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
	endpoints, err := ExtractFromBundle(src, "https://example.com/app.js")
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
	endpoints, err := ExtractFromBundle(src, "https://example.com/app.js")
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
	// BodyFields should contain the JSON.stringify object keys.
	src := []byte(`fetch("/api/x", {method:"POST", body: JSON.stringify({name, email})})`)
	endpoints, err := ExtractFromBundle(src, "https://example.com/app.js")
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
	// Token recovery enabled — the path parameter should use the identifier name.
	src := []byte("fetch(`/api/users/${userId}`)")
	endpoints, err := ExtractFromBundle(src, "https://example.com/app.js")
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
		endpoints, err := ExtractFromBundle([]byte(src), "")
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
		endpoints, err := ExtractFromBundle([]byte(src), "")
		if err != nil {
			t.Fatalf("unexpected error for %q: %v", src, err)
		}
		if len(endpoints) != 0 {
			t.Errorf("expected no endpoints for scheme in %q, got: %v", src, endpoints)
		}
	}
}

func TestExtractFromBundle_FiltersExprOnlyURLs(t *testing.T) {
	// A bundle that contains BOTH a real fetch and a pure-EXPR fetch. The
	// real one must survive; the EXPR-only one must be filtered. This pins
	// the filter behavior without depending on jsluice emitting an "EXPR"
	// entry for the pure-dynamic call (which would make the assertion
	// vacuous when jsluice silently drops it upstream).
	src := []byte(`fetch("/api/real"); fetch(someVar);`)
	endpoints, err := ExtractFromBundle(src, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(endpoints) == 0 {
		t.Fatal("expected at least the /api/real endpoint to survive the filter")
	}
	var sawReal bool
	for _, ep := range endpoints {
		if ep.URL == "EXPR" || ep.URL == "" {
			t.Errorf("expected EXPR-only URL to be filtered, got: %v", ep)
		}
		if ep.URL == "/api/real" {
			sawReal = true
		}
	}
	if !sawReal {
		t.Errorf("expected /api/real to be kept, got endpoints: %v", endpoints)
	}
}

func TestExtractFromBundle_AxiosGet(t *testing.T) {
	src := []byte(`axios.get("/api/items")`)
	endpoints, err := ExtractFromBundle(src, "")
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
	endpoints, err := ExtractFromBundle(src, "")
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
	endpoints, err := ExtractFromBundle(src, "")
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
	endpoints, err := ExtractFromBundle(src, "")
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
	endpoints, err := ExtractFromBundle(src, "")
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
	endpoints, err := ExtractFromBundle(src, "")
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
	endpoints, err := ExtractFromBundle(src, "https://example.com/app.js")
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
	endpoints, err := ExtractFromBundle(src, "https://example.com/app.js")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ep := findEndpoint(endpoints, "/u/{id}")
	if ep == nil {
		t.Fatalf("expected endpoint /u/{id}, got: %v", endpoints)
	}
}

// fetch with template-literal URL + body must produce body fields.
func TestExtractFromBundle_FetchTemplateLiteralWithBody(t *testing.T) {
	src := []byte("fetch(`/users/${id}`, {method:\"POST\", body: JSON.stringify({name, email})})")
	endpoints, err := ExtractFromBundle(src, "https://example.com/app.js")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ep := findEndpoint(endpoints, "/users/{id}")
	if ep == nil {
		t.Fatalf("expected endpoint /users/{id}, got: %v", endpoints)
	}
	if ep.Method != "POST" {
		t.Errorf("Method = %q, want POST", ep.Method)
	}
	if len(ep.BodyFields) != 2 || ep.BodyFields[0] != "email" || ep.BodyFields[1] != "name" {
		t.Errorf("BodyFields = %v, want [email name]", ep.BodyFields)
	}
}

// axios.get with template-literal URL must yield endpoint.
func TestExtractFromBundle_AxiosTemplateLiteral(t *testing.T) {
	src := []byte("axios.get(`/users/${id}`)")
	endpoints, err := ExtractFromBundle(src, "https://example.com/app.js")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ep := findEndpoint(endpoints, "/users/{id}")
	if ep == nil {
		t.Fatalf("expected endpoint /users/{id}, got: %v", endpoints)
	}
	if ep.Method != "GET" {
		t.Errorf("Method = %q, want GET", ep.Method)
	}
}

// collectObjectKeys must strip surrounding quotes from string-literal keys.
func TestCollectObjectKeys_StringLiteralKeys(t *testing.T) {
	src := []byte(`fetch("/x", {method:"POST", body: JSON.stringify({"first-name": 1, "last-name": 2})})`)
	endpoints, err := ExtractFromBundle(src, "https://example.com/app.js")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ep := findEndpoint(endpoints, "/x")
	if ep == nil {
		t.Fatalf("expected endpoint /x, got: %v", endpoints)
	}
	// Keys should be unquoted: first-name, last-name (sorted).
	if len(ep.BodyFields) != 2 {
		t.Fatalf("expected 2 BodyFields, got %v", ep.BodyFields)
	}
	if ep.BodyFields[0] != "first-name" || ep.BodyFields[1] != "last-name" {
		t.Errorf("BodyFields = %v, want [first-name last-name]", ep.BodyFields)
	}
}

// collapseTemplateLiteral must handle nested braces. The nested object
// `{user:1}` inside the call expression `getId({user:1})` would corrupt the
// URL into `/api/EXPR)}` if the implementation used a naive first-`}` scan.
// We assert the EXACT recovered URL and fail hard on any brace artifact.
func TestCollapseTemplateLiteral_NestedBraces(t *testing.T) {
	src := []byte("fetch(`/api/${getId({user:1})}`)")
	endpoints, err := ExtractFromBundle(src, "https://example.com/app.js")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The substitution is a call_expression `getId({user:1})`. Token-recovery
	// only picks up identifier and member_expression substitutions (where the
	// recovered name is a meaningful runtime value); call expressions yield an
	// unnamed parameter, so NormalizeEXPRPath falls back to the {param} default.
	const want = "/api/{param}"
	ep := findEndpoint(endpoints, want)
	if ep == nil {
		t.Fatalf("expected endpoint %q, got: %v", want, endpoints)
	}
	// Hard check: no corruption artifacts. The legitimate {param} placeholder
	// contains `{` and `}`, but a naive first-`}` scan would leave fragments
	// like `EXPR)}`, `})}`, `:1})}` inside the URL.
	for _, frag := range []string{")", "EXPR", "${", "})}", ":1}"} {
		if strings.Contains(ep.URL, frag) {
			t.Fatalf("endpoint URL %q still contains template artifact %q", ep.URL, frag)
		}
	}
}

// Regression for review finding 001: jsluice emits a redundant method-less
// "fetch" match alongside the method-bearing one. A non-GET fetch must NOT
// surface a phantom GET for the same URL.
func TestExtractFromBundle_PostFetch_NoPhantomGet(t *testing.T) {
	src := []byte(`fetch("/api/users", {method: "POST"})`)
	endpoints, err := ExtractFromBundle(src, "https://example.com/app.js")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var methods []string
	for _, ep := range endpoints {
		if ep.URL == "/api/users" {
			methods = append(methods, ep.Method)
		}
	}
	if len(methods) != 1 || methods[0] != "POST" {
		t.Errorf("expected exactly [POST] for /api/users (no phantom GET), got %v", methods)
	}
}

// A bundle that genuinely calls BOTH GET and POST on the same URL must keep
// both — the phantom-GET fix must not collapse a real bare-GET fetch.
func TestExtractFromBundle_FetchGetAndPost_BothSurvive(t *testing.T) {
	src := []byte(`fetch("/api/users"); fetch("/api/users", {method: "POST"});`)
	endpoints, err := ExtractFromBundle(src, "https://example.com/app.js")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := map[string]bool{}
	for _, ep := range endpoints {
		if ep.URL == "/api/users" {
			got[ep.Method] = true
		}
	}
	if !got["GET"] || !got["POST"] {
		t.Errorf("expected both GET and POST for /api/users, got %v", got)
	}
}

// Regression for review finding 002: axios.request({url, method, data}) must be
// extracted (the URL/method/body all come from the config object, not a
// positional URL arg).
func TestExtractFromBundle_AxiosRequestConfig(t *testing.T) {
	src := []byte(`axios.request({url:"/api/req", method:"DELETE", data:{a, b}})`)
	endpoints, err := ExtractFromBundle(src, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ep := findEndpoint(endpoints, "/api/req")
	if ep == nil {
		t.Fatalf("expected endpoint /api/req, got: %v", endpoints)
	}
	if ep.Method != "DELETE" {
		t.Errorf("Method = %q, want DELETE", ep.Method)
	}
	if len(ep.BodyFields) != 2 || ep.BodyFields[0] != "a" || ep.BodyFields[1] != "b" {
		t.Errorf("BodyFields = %v, want [a b]", ep.BodyFields)
	}
}

func TestExtractFromBundle_EmptyInput(t *testing.T) {
	endpoints, err := ExtractFromBundle(nil, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if endpoints != nil {
		t.Errorf("expected nil endpoints for empty input, got: %v", endpoints)
	}
}
