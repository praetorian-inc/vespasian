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
	// TEST-002: assert exactly one matching endpoint.
	count := 0
	var ep *ExtractedEndpoint
	for i := range endpoints {
		if endpoints[i].URL == "/api/items" {
			count++
			ep = &endpoints[i]
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 endpoint at /api/items, got %d (endpoints: %v)", count, endpoints)
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
	// TEST-002: assert exactly one matching endpoint.
	count := 0
	var ep *ExtractedEndpoint
	for i := range endpoints {
		if endpoints[i].URL == "/api/x" {
			count++
			ep = &endpoints[i]
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 endpoint at /api/x, got %d (endpoints: %v)", count, endpoints)
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
	// TEST-002: assert exactly one matching endpoint.
	count := 0
	var ep *ExtractedEndpoint
	for i := range endpoints {
		if endpoints[i].URL == "/api/x" {
			count++
			ep = &endpoints[i]
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 endpoint at /api/x, got %d (endpoints: %v)", count, endpoints)
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
	// TEST-002: assert exactly one matching endpoint.
	count := 0
	var ep *ExtractedEndpoint
	for i := range endpoints {
		if endpoints[i].URL == "/users/{id}" {
			count++
			ep = &endpoints[i]
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 endpoint at /users/{id}, got %d (endpoints: %v)", count, endpoints)
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
	// TEST-002: assert exactly one matching endpoint.
	count := 0
	var ep *ExtractedEndpoint
	for i := range endpoints {
		if endpoints[i].URL == "/users/{id}" {
			count++
			ep = &endpoints[i]
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 endpoint at /users/{id}, got %d (endpoints: %v)", count, endpoints)
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

// TEST-001: axios.put must extract body fields from the second positional arg.
func TestExtractFromBundle_AxiosPut(t *testing.T) {
	src := []byte(`axios.put("/api/users/1", {name, email})`)
	endpoints, err := ExtractFromBundle(src, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	count := 0
	var ep *ExtractedEndpoint
	for i := range endpoints {
		if endpoints[i].URL == "/api/users/1" {
			count++
			ep = &endpoints[i]
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 endpoint at /api/users/1, got %d (endpoints: %v)", count, endpoints)
	}
	if ep.Method != "PUT" {
		t.Errorf("Method = %q, want PUT", ep.Method)
	}
	if len(ep.BodyFields) != 2 || ep.BodyFields[0] != "email" || ep.BodyFields[1] != "name" {
		t.Errorf("BodyFields = %v, want [email name]", ep.BodyFields)
	}
}

// TEST-001: axios.patch must extract body fields from the second positional arg.
func TestExtractFromBundle_AxiosPatch(t *testing.T) {
	src := []byte(`axios.patch("/api/users/1", {role})`)
	endpoints, err := ExtractFromBundle(src, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	count := 0
	var ep *ExtractedEndpoint
	for i := range endpoints {
		if endpoints[i].URL == "/api/users/1" {
			count++
			ep = &endpoints[i]
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 endpoint at /api/users/1, got %d (endpoints: %v)", count, endpoints)
	}
	if ep.Method != "PATCH" {
		t.Errorf("Method = %q, want PATCH", ep.Method)
	}
	if len(ep.BodyFields) != 1 || ep.BodyFields[0] != "role" {
		t.Errorf("BodyFields = %v, want [role]", ep.BodyFields)
	}
}

// TEST-001: axios.delete second arg is CONFIG (not body); config keys must NOT
// become body fields.
func TestExtractFromBundle_AxiosDeleteConfigNotBody(t *testing.T) {
	src := []byte(`axios.delete("/api/users/1", {headers: {Authorization: "x"}})`)
	endpoints, err := ExtractFromBundle(src, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	count := 0
	var ep *ExtractedEndpoint
	for i := range endpoints {
		if endpoints[i].URL == "/api/users/1" {
			count++
			ep = &endpoints[i]
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 endpoint at /api/users/1, got %d (endpoints: %v)", count, endpoints)
	}
	if ep.Method != "DELETE" {
		t.Errorf("Method = %q, want DELETE", ep.Method)
	}
	// Config object keys (headers, Authorization) must NOT appear as body fields.
	if len(ep.BodyFields) != 0 {
		t.Errorf("BodyFields = %v, want [] (config keys must not become body fields)", ep.BodyFields)
	}
}

// TEST-001: axios.delete body is in config.data — extract those keys only.
func TestExtractFromBundle_AxiosDeleteWithDataBody(t *testing.T) {
	src := []byte(`axios.delete("/api/users/1", {data: {reason}})`)
	endpoints, err := ExtractFromBundle(src, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	count := 0
	var ep *ExtractedEndpoint
	for i := range endpoints {
		if endpoints[i].URL == "/api/users/1" {
			count++
			ep = &endpoints[i]
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 endpoint at /api/users/1, got %d (endpoints: %v)", count, endpoints)
	}
	if ep.Method != "DELETE" {
		t.Errorf("Method = %q, want DELETE", ep.Method)
	}
	if len(ep.BodyFields) != 1 || ep.BodyFields[0] != "reason" {
		t.Errorf("BodyFields = %v, want [reason]", ep.BodyFields)
	}
}

// LAB-4992: the fully-offline analyzer must reconstruct API paths that exist
// only as JS string concatenations — String.prototype.concat, +-string chains,
// and literal+literal service-prefix concatenation — which jsluice's AST
// analysis cannot resolve. These flow through the shared crawl extractor
// (crawl.ExtractStaticConcatPaths) so the offline static path recovers the same
// forms as the active JS-replay path. Non-literal operands become the numeric
// sentinel "0" (parameterized later by pkg/generate/rest).
func TestExtractFromBundle_ConcatReconstruction(t *testing.T) {
	// Mirrors test/concat-spa/app.js plus a literal+literal service prefix.
	src := []byte(`
function loadOrders(uid)  { return fetch("/api/users/".concat(uid, "/orders")); }
function loadReviews(pid) { var u = "/api/products/" + pid + "/reviews"; return fetch(u); }
var LOGIN = "identity/" + "api/auth/login";
`)
	endpoints, err := ExtractFromBundle(src, "https://example.com/app.js")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Each form must reconstruct its concrete candidate path.
	for _, want := range []string{
		"/api/users/0/orders",      // String.prototype.concat form
		"/api/products/0/reviews",  // +-string chain form
		"/identity/api/auth/login", // literal+literal service-prefix form
	} {
		ep := findEndpoint(endpoints, want)
		if ep == nil {
			t.Errorf("expected reconstructed endpoint %q, got: %v", want, endpoints)
			continue
		}
		if ep.Method != "GET" {
			t.Errorf("%s: Method = %q, want GET (bare path carries no method)", want, ep.Method)
		}
		if ep.SourceTag != SourceJSConcat {
			t.Errorf("%s: SourceTag = %q, want %q", want, ep.SourceTag, SourceJSConcat)
		}
	}
}

// LAB-4992 dedup guard: a concat reconstruction whose URL collides with a URL
// jsluice already recovered (with a real method) must NOT gain a phantom GET
// companion. Here axios.post gives jsluice POST /api/users/5, and the literal
// +-chain "/api/users/" + "5" reconstructs to the SAME /api/users/5 — so the
// astURLs guard must suppress the GET candidate. (Deleting the guard makes this
// test fail with a phantom [POST GET].)
//
// This case pins only the ABSOLUTE-LITERAL collision. The two tests below pin
// the harder cases the original guard silently missed: a dynamic operand
// (sentinel "0" vs AST {param}) and a relative operand (leading-slash mismatch).
func TestExtractFromBundle_ConcatNoPhantomForKnownURL(t *testing.T) {
	src := []byte(`axios.post("/api/users/5", {a}); var u = "/api/users/" + "5";`)
	endpoints, err := ExtractFromBundle(src, "https://example.com/app.js")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var methods []string
	for _, ep := range endpoints {
		if ep.URL == "/api/users/5" {
			methods = append(methods, ep.Method)
		}
	}
	if len(methods) != 1 || methods[0] != "POST" {
		t.Errorf("expected exactly [POST] for /api/users/5 (no phantom GET), got %v", methods)
	}
}

// LAB-4992 dedup guard, dynamic-operand case (was QUAL-002): the AST walker
// recovers the template literal fetch(`/api/users/${uid}/orders`) as
// /api/users/{uid}/orders, while the +-chain "/api/users/" + uid + "/orders"
// reconstructs to /api/users/0/orders (numeric sentinel for the non-literal
// operand). These are the SAME logical endpoint, so the concat GET candidate
// must be suppressed. Before concatDedupKey normalized "0" and {param} segments
// to a common token, the raw string compare never matched and a phantom
// /api/users/0/orders GET slipped through.
func TestExtractFromBundle_ConcatNoPhantomForDynamicSegment(t *testing.T) {
	src := []byte("function f(uid){ return fetch(`/api/users/${uid}/orders`); }\n" +
		`var u = "/api/users/" + uid + "/orders"; fetch(u);`)
	endpoints, err := ExtractFromBundle(src, "https://example.com/app.js")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ep := findEndpoint(endpoints, "/api/users/0/orders"); ep != nil {
		t.Errorf("phantom concat companion /api/users/0/orders emitted alongside AST-recovered param path; got %v", endpoints)
	}
	// The AST-recovered parameterized form must still be present.
	if ep := findEndpoint(endpoints, "/api/users/{uid}/orders"); ep == nil {
		t.Errorf("expected AST-recovered /api/users/{uid}/orders, got %v", endpoints)
	}
}

// LAB-4992 dedup guard, relative-operand case (was QUAL-003): the AST walker
// recovers fetch("api/users/5") as the relative URL "api/users/5" (no leading
// slash), while the +-chain "api/users/" + "5" reconstructs to "api/users/5"
// and extractConcatEndpoints prepends a leading slash → "/api/users/5". These
// are the SAME endpoint, so the concat GET candidate must be suppressed. Before
// concatDedupKey normalized the leading slash on both sides, the slash mismatch
// bypassed the guard and a phantom "/api/users/5" slipped through.
func TestExtractFromBundle_ConcatNoPhantomForRelativeURL(t *testing.T) {
	src := []byte(`fetch("api/users/5"); var u = "api/users/" + "5"; fetch(u);`)
	endpoints, err := ExtractFromBundle(src, "https://example.com/app.js")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ep := findEndpoint(endpoints, "/api/users/5"); ep != nil {
		t.Errorf("phantom concat companion /api/users/5 emitted alongside AST-recovered relative path; got %v", endpoints)
	}
	if ep := findEndpoint(endpoints, "api/users/5"); ep == nil {
		t.Errorf("expected AST-recovered relative api/users/5, got %v", endpoints)
	}
}

// LAB-4992 dedup guard, must-survive direction: concatDedupKey must NOT
// over-merge distinct CONCRETE paths. A concat reconstruction with a concrete
// (non-sentinel) segment that only shares a prefix with an AST-recovered param
// path is a genuinely different endpoint and must survive. Here the AST recovers
// /api/items/{x} from the template literal and the +-chain reconstructs the
// concrete /api/items/5 — both must appear (5 canonicalizes to "5", not "{}").
func TestExtractFromBundle_ConcatConcreteSegmentNotOverMerged(t *testing.T) {
	src := []byte("function f(x){ return fetch(`/api/items/${x}`); }\n" +
		`var u = "/api/items/" + "5"; fetch(u);`)
	endpoints, err := ExtractFromBundle(src, "https://example.com/app.js")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ep := findEndpoint(endpoints, "/api/items/{x}"); ep == nil {
		t.Errorf("expected AST-recovered /api/items/{x}, got %v", endpoints)
	}
	if ep := findEndpoint(endpoints, "/api/items/5"); ep == nil {
		t.Errorf("concrete concat path /api/items/5 was over-merged/suppressed; must survive alongside the param path; got %v", endpoints)
	}
}

// LAB-4992 dedup guard, absolute-vs-relative same-origin case: an AST walker
// recovers a FULL same-origin URL (fetch("https://example.com/api/v1/webhook"))
// while the +-chain reconstructs the same path relatively ("/api/v1/" +
// "webhook"). concatDedupKey strips scheme+host and origin-scopes the key to the
// bundle host, so the relative concat candidate collapses onto the absolute AST
// URL and its phantom GET companion is suppressed.
func TestExtractFromBundle_ConcatNoPhantomForSameOriginAbsoluteURL(t *testing.T) {
	src := []byte(`fetch("https://example.com/api/v1/webhook"); var u = "/api/v1/" + "webhook"; fetch(u);`)
	endpoints, err := ExtractFromBundle(src, "https://example.com/app.js")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ep := findEndpoint(endpoints, "/api/v1/webhook"); ep != nil {
		t.Errorf("phantom relative concat companion /api/v1/webhook emitted alongside same-origin absolute AST URL; got %v", endpoints)
	}
	if ep := findEndpoint(endpoints, "https://example.com/api/v1/webhook"); ep == nil {
		t.Errorf("expected AST-recovered absolute https://example.com/api/v1/webhook, got %v", endpoints)
	}
}

// LAB-4992 dedup guard, cross-host case (regression from the origin-scoping fix):
// an AST-recovered absolute URL to a DIFFERENT host must NOT suppress a
// same-origin concat candidate that merely shares its path — they are genuinely
// distinct endpoints. Here axios.post targets beacon.other.com/api/track while
// the concat reconstructs same-origin /api/track; both must survive.
func TestExtractFromBundle_ConcatCrossHostNotSuppressed(t *testing.T) {
	src := []byte(`axios.post("https://beacon.other.com/api/track", {a}); var u = "/api/" + "track"; fetch(u);`)
	endpoints, err := ExtractFromBundle(src, "https://example.com/app.js")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ep := findEndpoint(endpoints, "/api/track"); ep == nil {
		t.Errorf("same-origin concat /api/track was wrongly suppressed by a cross-host AST URL sharing the path; got %v", endpoints)
	}
	if ep := findEndpoint(endpoints, "https://beacon.other.com/api/track"); ep == nil {
		t.Errorf("expected cross-host AST POST https://beacon.other.com/api/track, got %v", endpoints)
	}
}

// LAB-4992 dedup guard, sentinel-"0" exception: concatDedupKey deliberately
// treats a lone literal "0" segment as dynamic (it is indistinguishable offline
// from a substituted sentinel), so a concat "/api/items/" + "0" -> /api/items/0
// collapses onto the AST-recovered param path /api/items/{x} and its phantom GET
// companion is suppressed. This pins the documented exception (the opposite of
// the non-sentinel "5" case in ConcatConcreteSegmentNotOverMerged).
func TestExtractFromBundle_ConcatSentinelZeroCollapsesOntoParam(t *testing.T) {
	src := []byte("function f(x){ return fetch(`/api/items/${x}`); }\n" +
		`var u = "/api/items/" + "0"; fetch(u);`)
	endpoints, err := ExtractFromBundle(src, "https://example.com/app.js")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ep := findEndpoint(endpoints, "/api/items/{x}"); ep == nil {
		t.Errorf("expected AST-recovered /api/items/{x}, got %v", endpoints)
	}
	if ep := findEndpoint(endpoints, "/api/items/0"); ep != nil {
		t.Errorf("literal-0 concat companion /api/items/0 must collapse onto the param path (documented sentinel exception); got %v", endpoints)
	}
}

// LAB-4992 dedup guard, case-insensitive host: hostnames are case-insensitive,
// so concatDedupKey/hostOfURL lower-case them. An AST absolute URL on
// "EXAMPLE.com" and a same-origin relative concat on the "example.com" bundle
// must be recognized as the same origin, suppressing the phantom companion.
func TestExtractFromBundle_ConcatDedupHostCaseInsensitive(t *testing.T) {
	src := []byte(`fetch("https://EXAMPLE.com/api/ping"); var u = "/api/" + "ping"; fetch(u);`)
	endpoints, err := ExtractFromBundle(src, "https://example.com/app.js")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ep := findEndpoint(endpoints, "/api/ping"); ep != nil {
		t.Errorf("relative concat /api/ping must dedup against the differently-cased same-origin AST URL; got %v", endpoints)
	}
	if ep := findEndpoint(endpoints, "https://EXAMPLE.com/api/ping"); ep == nil {
		t.Errorf("expected AST-recovered https://EXAMPLE.com/api/ping, got %v", endpoints)
	}
}

// TEST-001: extractConcatEndpoints' emit guard is
// `if filterURL(p) || isExprOnly(p) || astURLs[...] { continue }` — this pins
// the filterURL/isExprOnly half, which previously had zero coverage. A concat
// reconstruction that carries an API indicator (satisfying hasAPIIndicator in
// cleanConcatPath, via "api/") but reconstructs to an asset URL (".js") must
// still be dropped by filterURL before it is ever emitted as an
// ExtractedEndpoint.
func TestExtractFromBundle_ConcatFilteredAsAsset(t *testing.T) {
	src := []byte(`var u = "/api/" + "bundle.js"; fetch(u);`)
	endpoints, err := ExtractFromBundle(src, "https://example.com/app.js")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ep := findEndpoint(endpoints, "/api/bundle.js"); ep != nil {
		t.Errorf("concat reconstruction /api/bundle.js must be dropped by filterURL (asset extension), got %v", endpoints)
	}
}

// SEC-BE-001: the concat receiver form must not emit an absolute,
// cross-origin reconstruction. A hostile bundle literal like
// "https://attacker.example/api/x".concat(id) would otherwise reconstruct to
// an absolute URL on an attacker-chosen host and be emitted as an unprobed
// static:js-concat candidate — Rule 6 (pkg/classify) would floor it to
// default confidence, and the live probe stage has no same-origin gate of
// its own, so the attacker host would be probed (SSRF-reflector /
// scope-escape via a fully offline analysis path). A relative reconstruction
// and a same-host absolute reconstruction must still be emitted.
func TestExtractFromBundle_ConcatCrossOriginGate(t *testing.T) {
	src := []byte(`
var cross = "https://attacker.example/api/".concat("x");
var same = "https://example.com/api/".concat("y");
var rel = "/api/".concat("z");
`)
	endpoints, err := ExtractFromBundle(src, "https://example.com/app.js")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ep := findEndpoint(endpoints, "https://attacker.example/api/x"); ep != nil {
		t.Errorf("cross-origin concat reconstruction must NOT be emitted; got %v", endpoints)
	}
	if ep := findEndpoint(endpoints, "https://example.com/api/y"); ep == nil {
		t.Errorf("same-host absolute concat reconstruction must still be emitted, got %v", endpoints)
	}
	if ep := findEndpoint(endpoints, "/api/z"); ep == nil {
		t.Errorf("relative concat reconstruction must still be emitted, got %v", endpoints)
	}
}

// QUAL-001: concatDedupKey must normalize a trailing slash so a trailing-slash
// concat reconstruction dedupes against an AST form that has none — matching
// the active JS-replay path's addPath, which does strings.TrimRight(raw, "/").
// Here the AST walker recovers the template literal fetch(`/api/posts/${id}/comment`)
// with no trailing slash, while the +-chain "/api/posts/" + id + "/comment/"
// reconstructs WITH a trailing slash (cleanConcatPath never trims it). Before
// concatDedupKey trimmed the trailing slash, these hashed to different keys
// ("host|/api/posts/{}/comment" vs "host|/api/posts/{}/comment/") and the
// astURLs guard missed, emitting a phantom GET companion.
func TestExtractFromBundle_ConcatNoPhantomForTrailingSlash(t *testing.T) {
	src := []byte("function f(id){ return fetch(`/api/posts/${id}/comment`); }\n" +
		`var u = "/api/posts/" + id + "/comment/"; fetch(u);`)
	endpoints, err := ExtractFromBundle(src, "https://example.com/app.js")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ep := findEndpoint(endpoints, "/api/posts/0/comment/"); ep != nil {
		t.Errorf("phantom trailing-slash concat companion /api/posts/0/comment/ emitted alongside AST-recovered param path; got %v", endpoints)
	}
	if ep := findEndpoint(endpoints, "/api/posts/{id}/comment"); ep == nil {
		t.Errorf("expected AST-recovered /api/posts/{id}/comment, got %v", endpoints)
	}
}

// QUAL-001: concatDedupKey must preserve the root "/" case — trimming the
// trailing slash must not turn "/" into "", which would silently key root
// endpoints under the empty path instead of "/".
func TestConcatDedupKey_RootSlashPreserved(t *testing.T) {
	if got := concatDedupKey("/", "example.com"); got != "example.com|/" {
		t.Errorf("concatDedupKey(%q, %q) = %q, want %q", "/", "example.com", got, "example.com|/")
	}
}

// QUAL-001: concatDedupKey must collapse a trailing-slash key onto its
// non-trailing-slash counterpart directly (unit-level pin, complementing the
// end-to-end TestExtractFromBundle_ConcatNoPhantomForTrailingSlash above).
func TestConcatDedupKey_TrailingSlashNormalized(t *testing.T) {
	withSlash := concatDedupKey("/api/posts/{id}/comment/", "example.com")
	withoutSlash := concatDedupKey("/api/posts/{id}/comment", "example.com")
	if withSlash != withoutSlash {
		t.Errorf("concatDedupKey with trailing slash = %q, without = %q, want equal", withSlash, withoutSlash)
	}
}
