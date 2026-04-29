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

package analyze

import (
	"net/url"
	"strings"
	"testing"

	"github.com/praetorian-inc/vespasian/pkg/crawl"
)

// parseBody returns the synthesized request's url-encoded body as url.Values.
func parseBody(t *testing.T, r crawl.ObservedRequest) url.Values {
	t.Helper()
	v, err := url.ParseQuery(string(r.Body))
	if err != nil {
		t.Fatalf("ParseQuery: %v", err)
	}
	return v
}

// htmlReq is a helper that builds a minimal ObservedRequest with an HTML response body.
func htmlReq(pageURL, body string) crawl.ObservedRequest {
	return crawl.ObservedRequest{
		URL: pageURL,
		Response: crawl.ObservedResponse{
			ContentType: "text/html",
			Body:        []byte(body),
		},
	}
}

// --- ExtractForms integration tests ---

func TestExtractForms_SimpleGetForm(t *testing.T) {
	reqs := []crawl.ObservedRequest{htmlReq("https://host/page", `<form action="/search"><input name="q"></form>`)}
	got := ExtractForms(reqs)
	if len(got) != 1 {
		t.Fatalf("expected 1 result, got %d", len(got))
	}
	r := got[0]
	if r.Method != "GET" {
		t.Errorf("Method = %q, want GET", r.Method)
	}
	if r.URL != "https://host/search?q=" {
		t.Errorf("URL = %q, want https://host/search?q=", r.URL)
	}
	if r.Source != "static:html" {
		t.Errorf("Source = %q, want static:html", r.Source)
	}
	if r.PageURL != "https://host/page" {
		t.Errorf("PageURL = %q, want https://host/page", r.PageURL)
	}
	if _, ok := r.QueryParams["q"]; !ok {
		t.Errorf("QueryParams missing key q; got %v", r.QueryParams)
	}
}

func TestExtractForms_PostFormMixedInputs(t *testing.T) {
	body := `<form method="post" action="/login">
		<input name="username" type="text">
		<input name="password" type="password">
		<input name="remember" type="hidden" value="1">
		<input type="submit" value="Login">
		<button type="button">Cancel</button>
	</form>`
	reqs := []crawl.ObservedRequest{htmlReq("https://host/login", body)}
	got := ExtractForms(reqs)
	if len(got) != 1 {
		t.Fatalf("expected 1 result, got %d", len(got))
	}
	r := got[0]
	if r.Method != "POST" {
		t.Errorf("Method = %q, want POST", r.Method)
	}
	if r.Headers["content-type"] != "application/x-www-form-urlencoded" {
		t.Errorf("content-type = %q, want application/x-www-form-urlencoded", r.Headers["content-type"])
	}
	vals := parseBody(t, r)
	if v, ok := vals["username"]; !ok || (len(v) > 0 && v[0] != "") {
		t.Errorf(`vals["username"] = %v, want present with empty value`, v)
	}
	if v, ok := vals["password"]; !ok || (len(v) > 0 && v[0] != "") {
		t.Errorf(`vals["password"] = %v, want present with empty value`, v)
	}
	if v, ok := vals["remember"]; !ok {
		t.Errorf(`vals["remember"] missing; got %v`, vals)
	} else if len(v) > 0 && v[0] != "" {
		// remember is hidden — value MUST be stripped per SEC-BE-005
		t.Errorf(`vals["remember"] = %v, want present with empty value (hidden value stripped)`, v)
	}
	// submit and button should not appear
	bodyStr := string(r.Body)
	if strings.Contains(bodyStr, "Login") {
		t.Errorf("submit value should not appear in body; got %q", bodyStr)
	}
}

func TestExtractForms_MultipartEnctypeRetained(t *testing.T) {
	body := `<form method="post" enctype="multipart/form-data" action="/upload">
		<input name="avatar" type="text">
		<input name="photo" type="file">
	</form>`
	reqs := []crawl.ObservedRequest{htmlReq("https://host/profile", body)}
	got := ExtractForms(reqs)
	if len(got) != 1 {
		t.Fatalf("expected 1 result, got %d", len(got))
	}
	if got[0].Headers["content-type"] != "multipart/form-data" {
		t.Errorf("content-type = %q, want multipart/form-data", got[0].Headers["content-type"])
	}
	// file input should be skipped; avatar present
	if !strings.Contains(string(got[0].Body), "avatar=") {
		t.Errorf("body missing avatar=; got %q", string(got[0].Body))
	}
	if strings.Contains(string(got[0].Body), "photo=") {
		t.Errorf("file input should not appear; got %q", string(got[0].Body))
	}
}

func TestExtractForms_RelativeActionResolved(t *testing.T) {
	reqs := []crawl.ObservedRequest{htmlReq("https://ex.com/users/42/edit", `<form action="../profile"><input name="x"></form>`)}
	got := ExtractForms(reqs)
	if len(got) != 1 {
		t.Fatalf("expected 1 result, got %d", len(got))
	}
	if got[0].URL != "https://ex.com/users/profile?x=" {
		t.Errorf("URL = %q, want https://ex.com/users/profile?x=", got[0].URL)
	}
}

func TestExtractForms_MissingActionSelfSubmits(t *testing.T) {
	reqs := []crawl.ObservedRequest{htmlReq("https://ex.com/login", `<form method="post"><input name="user"></form>`)}
	got := ExtractForms(reqs)
	if len(got) != 1 {
		t.Fatalf("expected 1 result, got %d", len(got))
	}
	if got[0].URL != "https://ex.com/login" {
		t.Errorf("URL = %q, want https://ex.com/login", got[0].URL)
	}
}

// TestExtractForms_HiddenFieldFlagged verifies that hidden fields have their
// names preserved (for parameter discovery) while their values are stripped
// (SEC-BE-005: hidden fields commonly bear secrets that must not be replayed).
func TestExtractForms_HiddenFieldFlagged(t *testing.T) {
	body := `<form method="post" action="/go"><input type="hidden" name="return_to" value="/home"></form>`
	reqs := []crawl.ObservedRequest{htmlReq("https://host/page", body)}
	got := ExtractForms(reqs)
	if len(got) != 1 {
		t.Fatalf("expected 1 result, got %d", len(got))
	}
	vals := parseBody(t, got[0])
	if v, ok := vals["return_to"]; !ok {
		t.Errorf(`vals["return_to"] missing; got %v`, vals)
	} else if len(v) > 0 && v[0] != "" {
		t.Errorf(`vals["return_to"] = %q, want empty (hidden value stripped per SEC-BE-005)`, v[0])
	}
}

func TestExtractForms_CSRFNamesFlagged(t *testing.T) {
	csrfNames := []string{"csrf_token", "_token", "authenticity_token", "xsrfField"}
	for _, name := range csrfNames {
		body := `<form method="post" action="/go"><input name="` + name + `" value="abc"></form>`
		reqs := []crawl.ObservedRequest{htmlReq("https://host/", body)}
		got := ExtractForms(reqs)
		if len(got) != 1 {
			t.Errorf("csrfName=%q: expected 1 result, got %d", name, len(got))
			continue
		}
		if !strings.Contains(string(got[0].Body), name+"=") {
			t.Errorf("csrfName=%q: field not found in body %q", name, string(got[0].Body))
		}
	}
}

func TestExtractForms_NestedFormsBothEmitted(t *testing.T) {
	body := `<form action="/a"><form action="/b"><input name="x"></form></form>`
	reqs := []crawl.ObservedRequest{htmlReq("https://host/", body)}
	got := ExtractForms(reqs)
	if len(got) != 2 {
		t.Fatalf("expected 2 results, got %d", len(got))
	}
	urls := map[string]bool{got[0].URL: true, got[1].URL: true}
	if !urls["https://host/a"] && !urls["https://host/a?x="] {
		t.Errorf("missing /a form; got %v", urls)
	}
	found := false
	for u := range urls {
		if strings.HasPrefix(u, "https://host/b") {
			found = true
		}
	}
	if !found {
		t.Errorf("missing /b form; got %v", urls)
	}
	// TEST-007: every synthesized request (not just one) must carry SourceStaticHTML.
	for i, r := range got {
		if r.Source != SourceStaticHTML {
			t.Errorf("got[%d].Source = %q, want %q", i, r.Source, SourceStaticHTML)
		}
	}
}

func TestExtractForms_SelectAndTextareaExtracted(t *testing.T) {
	body := `<form action="/search"><select name="country"><option>US</option></select><textarea name="bio"></textarea></form>`
	reqs := []crawl.ObservedRequest{htmlReq("https://host/", body)}
	got := ExtractForms(reqs)
	if len(got) != 1 {
		t.Fatalf("expected 1 result, got %d", len(got))
	}
	if _, ok := got[0].QueryParams["country"]; !ok {
		t.Errorf("QueryParams missing country; got %v", got[0].QueryParams)
	}
	if _, ok := got[0].QueryParams["bio"]; !ok {
		t.Errorf("QueryParams missing bio; got %v", got[0].QueryParams)
	}
	// TEST-004: assert values, not just key presence.
	// select with no value attribute -> option text content ("US").
	if got[0].QueryParams["country"] != "US" {
		t.Errorf("QueryParams[country] = %q, want US", got[0].QueryParams["country"])
	}
	// textarea with empty content -> empty string.
	if got[0].QueryParams["bio"] != "" {
		t.Errorf("QueryParams[bio] = %q, want empty string", got[0].QueryParams["bio"])
	}
}

func TestExtractForms_FormWithNoNamedFields(t *testing.T) {
	reqs := []crawl.ObservedRequest{htmlReq("https://host/", `<form action="/ping"></form>`)}
	got := ExtractForms(reqs)
	if len(got) != 1 {
		t.Fatalf("expected 1 result, got %d", len(got))
	}
	if got[0].URL != "https://host/ping" {
		t.Errorf("URL = %q, want https://host/ping", got[0].URL)
	}
	if got[0].Method != "GET" {
		t.Errorf("Method = %q, want GET", got[0].Method)
	}
}

func TestExtractForms_NonHTMLResponseSkipped(t *testing.T) {
	req := crawl.ObservedRequest{
		URL: "https://host/api",
		Response: crawl.ObservedResponse{
			ContentType: "application/json",
			Body:        []byte(`{"form":"<form action='/x'></form>"}`),
		},
	}
	got := ExtractForms([]crawl.ObservedRequest{req})
	if len(got) != 0 {
		t.Errorf("expected 0 results for JSON response, got %d", len(got))
	}
}

func TestExtractForms_EmptyBodySkipped(t *testing.T) {
	req := crawl.ObservedRequest{
		URL: "https://host/",
		Response: crawl.ObservedResponse{
			ContentType: "text/html",
			Body:        nil,
		},
	}
	got := ExtractForms([]crawl.ObservedRequest{req})
	if len(got) != 0 {
		t.Errorf("expected 0 results for empty body, got %d", len(got))
	}
}

func TestExtractForms_MissingContentTypeSniffed(t *testing.T) {
	req := crawl.ObservedRequest{
		URL: "https://host/",
		Response: crawl.ObservedResponse{
			ContentType: "",
			Body:        []byte(`<!doctype html><form action="/x"><input name="q"></form>`),
		},
	}
	got := ExtractForms([]crawl.ObservedRequest{req})
	if len(got) != 1 {
		t.Fatalf("expected 1 result via sniff, got %d", len(got))
	}
}

func TestExtractForms_NamelessInputsIgnored(t *testing.T) {
	body := `<form action="/go"><input><input value="no-name"></form>`
	reqs := []crawl.ObservedRequest{htmlReq("https://host/", body)}
	got := ExtractForms(reqs)
	if len(got) != 1 {
		t.Fatalf("expected 1 result, got %d", len(got))
	}
	if len(got[0].QueryParams) != 0 {
		t.Errorf("expected empty QueryParams, got %v", got[0].QueryParams)
	}
}

func TestExtractForms_MethodNormalised(t *testing.T) {
	cases := []struct {
		input    string // value for method attribute; "" means omit the attribute
		expected string
	}{
		{"post", "POST"},
		{"POST", "POST"},
		{"Post", "POST"},
		{" post ", "POST"},
		{"", "GET"}, // omitted method defaults to GET
		{"PATCH", "PATCH"},
		{"delete", "DELETE"},
		{"PuT", "PUT"},
	}
	for _, tc := range cases {
		var body string
		if tc.input == "" {
			body = `<form action="/x"><input name="a"></form>`
		} else {
			body = `<form method="` + tc.input + `" action="/x"><input name="a"></form>`
		}
		reqs := []crawl.ObservedRequest{htmlReq("https://host/", body)}
		got := ExtractForms(reqs)
		if len(got) != 1 {
			t.Errorf("input=%q: expected 1 result, got %d", tc.input, len(got))
			continue
		}
		if got[0].Method != tc.expected {
			t.Errorf("input=%q: Method = %q, want %q", tc.input, got[0].Method, tc.expected)
		}
	}
}

func TestExtractForms_SourceIsStaticHTML(t *testing.T) {
	if SourceStaticHTML != "static:html" {
		t.Errorf("SourceStaticHTML constant = %q, want static:html", SourceStaticHTML)
	}
	reqs := []crawl.ObservedRequest{htmlReq("https://host/", `<form action="/x"><input name="q"></form>`)}
	got := ExtractForms(reqs)
	for _, r := range got {
		if r.Source != SourceStaticHTML {
			t.Errorf("Source = %q, want %q", r.Source, SourceStaticHTML)
		}
	}
}

func TestExtractForms_PageURLMatchesParentRequestURL(t *testing.T) {
	pageURL := "https://host/a/b?c=d"
	reqs := []crawl.ObservedRequest{htmlReq(pageURL, `<form action="/x"><input name="q"></form>`)}
	got := ExtractForms(reqs)
	if len(got) != 1 {
		t.Fatalf("expected 1 result, got %d", len(got))
	}
	if got[0].PageURL != pageURL {
		t.Errorf("PageURL = %q, want %q", got[0].PageURL, pageURL)
	}
}

func TestExtractForms_SubmitButtonImageResetFileSkipped(t *testing.T) {
	body := `<form action="/go" method="post">
		<input name="valid" type="text" value="yes">
		<input name="sub" type="submit" value="Submit">
		<input name="btn" type="button" value="Click">
		<input name="img" type="image" value="img">
		<input name="rst" type="reset" value="Reset">
		<input name="fil" type="file">
	</form>`
	reqs := []crawl.ObservedRequest{htmlReq("https://host/", body)}
	got := ExtractForms(reqs)
	if len(got) != 1 {
		t.Fatalf("expected 1 result, got %d", len(got))
	}
	vals := parseBody(t, got[0])
	if vals.Get("valid") != "yes" {
		t.Errorf(`vals["valid"] = %q, want "yes"`, vals.Get("valid"))
	}
	bodyStr := string(got[0].Body)
	for _, skipped := range []string{"sub=", "btn=", "img=", "rst=", "fil="} {
		if strings.Contains(bodyStr, skipped) {
			t.Errorf("body should not contain %q; got %q", skipped, bodyStr)
		}
	}
}

func TestExtractForms_ValueFallbackPlaceholder(t *testing.T) {
	body := `<form action="/search"><input name="q" placeholder="search"></form>`
	reqs := []crawl.ObservedRequest{htmlReq("https://host/", body)}
	got := ExtractForms(reqs)
	if len(got) != 1 {
		t.Fatalf("expected 1 result, got %d", len(got))
	}
	if got[0].QueryParams["q"] != "search" {
		t.Errorf("QueryParams[q] = %q, want search", got[0].QueryParams["q"])
	}
}

func TestExtractForms_NonHTTPActionSkipped(t *testing.T) {
	body := `<form action="javascript:alert(1)"><input name="x"></form>`
	reqs := []crawl.ObservedRequest{htmlReq("https://host/", body)}
	got := ExtractForms(reqs)
	if len(got) != 0 {
		t.Errorf("expected 0 results for javascript: action, got %d", len(got))
	}
}

func TestExtractForms_PreservesExistingRequestsUnchanged(t *testing.T) {
	jsonReq := crawl.ObservedRequest{
		URL:    "https://host/api/data",
		Method: "GET",
		Response: crawl.ObservedResponse{
			ContentType: "application/json",
			Body:        []byte(`{"key":"val"}`),
		},
	}
	htmlRequest := htmlReq("https://host/page", `<form action="/x"><input name="q"></form>`)
	input := []crawl.ObservedRequest{jsonReq, htmlRequest}
	got := ExtractForms(input)
	// Only new synth entries are returned; original slice is unchanged.
	if len(got) != 1 {
		t.Fatalf("expected 1 synth result, got %d", len(got))
	}
	if got[0].Source != SourceStaticHTML {
		t.Errorf("Source = %q, want %q", got[0].Source, SourceStaticHTML)
	}
	// Original input slice is unmodified.
	if len(input) != 2 {
		t.Errorf("input slice mutated, want len 2, got %d", len(input))
	}
}

// --- parseForms white-box tests ---

func TestParseForms_HiddenFlag(t *testing.T) {
	body := []byte(`<form><input type="hidden" name="h"></form>`)
	forms := parseForms(body)
	if len(forms) != 1 {
		t.Fatalf("expected 1 form, got %d", len(forms))
	}
	if len(forms[0].Fields) != 1 {
		t.Fatalf("expected 1 field, got %d", len(forms[0].Fields))
	}
	f := forms[0].Fields[0]
	if !f.Hidden {
		t.Errorf("Hidden = false, want true")
	}
	if f.Type != "hidden" {
		t.Errorf("Type = %q, want hidden", f.Type)
	}
}

func TestParseForms_CSRFFlagAllVariants(t *testing.T) {
	cases := []struct {
		name   string
		isCSRF bool
	}{
		{"csrf_token", true},
		{"_token", true},
		{"authenticity_token", true},
		{"XSRF-Token", true},
		{"MY_CSRF", true},
		{"unrelated", false},
	}
	for _, tc := range cases {
		body := []byte(`<form><input name="` + tc.name + `"></form>`)
		forms := parseForms(body)
		if len(forms) != 1 || len(forms[0].Fields) != 1 {
			t.Errorf("name=%q: unexpected parse result", tc.name)
			continue
		}
		got := forms[0].Fields[0].CSRF
		if got != tc.isCSRF {
			t.Errorf("name=%q: CSRF=%v, want %v", tc.name, got, tc.isCSRF)
		}
	}
}

func TestParseForms_UnclosedFormFlushedAtEOF(t *testing.T) {
	body := []byte(`<form action="/a"><input name="x">`)
	forms := parseForms(body)
	if len(forms) != 1 {
		t.Fatalf("expected 1 form from unclosed form, got %d", len(forms))
	}
	if len(forms[0].Fields) != 1 || forms[0].Fields[0].Name != "x" {
		t.Errorf("unexpected fields: %v", forms[0].Fields)
	}
}

func TestParseForms_FormAttrCrossAssociationIgnored(t *testing.T) {
	body := []byte(`<form id="f1"></form><input form="f1" name="outside">`)
	forms := parseForms(body)
	if len(forms) != 1 {
		t.Fatalf("expected 1 form, got %d", len(forms))
	}
	if len(forms[0].Fields) != 0 {
		t.Errorf("expected 0 fields (cross-associated input ignored), got %d", len(forms[0].Fields))
	}
}

// --- resolveAction tests ---

func TestResolveAction_Empty(t *testing.T) {
	got, _, ok := resolveAction("https://h/p", "")
	if !ok {
		t.Fatalf("ok = false, want true")
	}
	if got != "https://h/p" {
		t.Errorf("got %q, want https://h/p", got)
	}
}

func TestResolveAction_RelativePath(t *testing.T) {
	got, _, ok := resolveAction("https://h/a/b", "c")
	if !ok {
		t.Fatalf("ok = false, want true")
	}
	if got != "https://h/a/c" {
		t.Errorf("got %q, want https://h/a/c", got)
	}
}

func TestResolveAction_AbsolutePath(t *testing.T) {
	got, _, ok := resolveAction("https://h/a/b", "/x")
	if !ok {
		t.Fatalf("ok = false, want true")
	}
	if got != "https://h/x" {
		t.Errorf("got %q, want https://h/x", got)
	}
}

func TestResolveAction_OffHostAbsoluteURLRejected(t *testing.T) {
	_, _, ok := resolveAction("https://h/", "https://other/y")
	if ok {
		t.Errorf("expected ok=false for off-host absolute URL, got true")
	}
}

func TestResolveAction_SameHostAbsoluteURLAllowed(t *testing.T) {
	got, _, ok := resolveAction("https://h/", "https://h/other")
	if !ok {
		t.Fatalf("ok = false, want true")
	}
	if got != "https://h/other" {
		t.Errorf("got %q, want https://h/other", got)
	}
}

func TestResolveAction_ProtocolRelativeCrossHostRejected(t *testing.T) {
	_, _, ok := resolveAction("https://h/", "//other/y")
	if ok {
		t.Errorf("expected ok=false for protocol-relative cross-host URL, got true")
	}
}

func TestResolveAction_DifferentPortRejected(t *testing.T) {
	_, _, ok := resolveAction("https://h:443/", "https://h:8080/")
	if ok {
		t.Errorf("expected ok=false for different port, got true")
	}
}

// CodeRabbit follow-up: implicit default port (omitted) and explicit default
// port must be treated as the same origin. https://h/ and https://h:443/ are
// the same origin per RFC 3986 §3.2.3; url.URL.Port() returns "" in the first
// case and "443" in the second, so a naive direct comparison would falsely
// reject these as off-host. Both directions of the substitution must hold.
func TestResolveAction_ExplicitDefaultPortMatchesImplicit_HTTPS(t *testing.T) {
	// base implicit, ref explicit :443
	got, _, ok := resolveAction("https://h/", "https://h:443/x")
	if !ok {
		t.Fatalf("ok = false, want true")
	}
	if got != "https://h:443/x" && got != "https://h/x" {
		t.Errorf("got %q, want https://h:443/x or https://h/x", got)
	}

	// base explicit :443, ref implicit
	got, _, ok = resolveAction("https://h:443/", "https://h/x")
	if !ok {
		t.Fatalf("reverse direction: ok = false, want true")
	}
	if got != "https://h/x" && got != "https://h:443/x" {
		t.Errorf("reverse direction: got %q", got)
	}
}

func TestResolveAction_ExplicitDefaultPortMatchesImplicit_HTTP(t *testing.T) {
	got, _, ok := resolveAction("http://h/", "http://h:80/x")
	if !ok {
		t.Fatalf("ok = false, want true")
	}
	if got != "http://h:80/x" && got != "http://h/x" {
		t.Errorf("got %q", got)
	}
}

// Negative guard: the effectivePort fix must not accidentally normalize
// non-default ports — :8443 is not the same origin as :443.
func TestResolveAction_NonDefaultPortStillDistinct(t *testing.T) {
	_, _, ok := resolveAction("https://h/", "https://h:8443/x")
	if ok {
		t.Errorf("expected ok=false for :8443 vs implicit :443, got true")
	}
}

func TestResolveAction_HostnameComparisonCaseInsensitive(t *testing.T) {
	got, _, ok := resolveAction("https://Host/", "https://host/x")
	if !ok {
		t.Fatalf("ok = false, want true")
	}
	if got != "https://host/x" {
		t.Errorf("got %q, want https://host/x", got)
	}
}

func TestExtractForms_OffHostActionSkipped(t *testing.T) {
	body := `<form action="https://evil.com/steal"><input name="x"></form>`
	reqs := []crawl.ObservedRequest{htmlReq("https://target.com/page", body)}
	got := ExtractForms(reqs)
	if len(got) != 0 {
		t.Errorf("expected 0 results for off-host form action, got %d", len(got))
	}
}

func TestResolveAction_JavascriptScheme(t *testing.T) {
	_, _, ok := resolveAction("https://h/", "javascript:void(0)")
	if ok {
		t.Errorf("expected ok=false for javascript: scheme")
	}
}

func TestResolveAction_FragmentStripped(t *testing.T) {
	got, _, ok := resolveAction("https://h/", "/x#frag")
	if !ok {
		t.Fatalf("ok = false, want true")
	}
	if strings.Contains(got, "#") {
		t.Errorf("fragment not stripped; got %q", got)
	}
}

// --- isHTMLResponse tests ---

func TestIsHTMLResponse_TextHtml(t *testing.T) {
	resp := crawl.ObservedResponse{ContentType: "text/html; charset=utf-8"}
	if !isHTMLResponse(resp) {
		t.Errorf("expected true for text/html")
	}
}

func TestIsHTMLResponse_XhtmlXml(t *testing.T) {
	resp := crawl.ObservedResponse{ContentType: "application/xhtml+xml"}
	if !isHTMLResponse(resp) {
		t.Errorf("expected true for application/xhtml+xml")
	}
}

func TestIsHTMLResponse_Json(t *testing.T) {
	resp := crawl.ObservedResponse{ContentType: "application/json"}
	if isHTMLResponse(resp) {
		t.Errorf("expected false for application/json")
	}
}

func TestIsHTMLResponse_EmptyWithDoctypeSniff(t *testing.T) {
	resp := crawl.ObservedResponse{
		ContentType: "",
		Body:        []byte("<!DOCTYPE html><html><body></body></html>"),
	}
	if !isHTMLResponse(resp) {
		t.Errorf("expected true via doctype sniff")
	}
}

func TestIsHTMLResponse_EmptyNoMarkers(t *testing.T) {
	resp := crawl.ObservedResponse{
		ContentType: "",
		Body:        []byte("random bytes without html markers"),
	}
	if isHTMLResponse(resp) {
		t.Errorf("expected false for non-html sniff")
	}
}

func TestIsHTMLResponse_ContentTypeInHeadersMap(t *testing.T) {
	resp := crawl.ObservedResponse{
		ContentType: "",
		Headers:     map[string]string{"Content-Type": "text/html"},
	}
	if !isHTMLResponse(resp) {
		t.Errorf("expected true when Content-Type is in Headers map")
	}
}

func TestExtractForms_GetMergesActionQueryString(t *testing.T) {
	body := `<form action="/search?lang=en"><input name="q" value="foo"></form>`
	reqs := []crawl.ObservedRequest{htmlReq("https://host/page", body)}
	got := ExtractForms(reqs)
	if len(got) != 1 {
		t.Fatalf("expected 1 result, got %d", len(got))
	}
	r := got[0]
	if r.QueryParams["lang"] != "en" {
		t.Errorf("QueryParams[lang] = %q, want en", r.QueryParams["lang"])
	}
	if r.QueryParams["q"] != "foo" {
		t.Errorf("QueryParams[q] = %q, want foo", r.QueryParams["q"])
	}
	if !strings.Contains(r.URL, "lang=en") {
		t.Errorf("URL missing lang=en; got %q", r.URL)
	}
	if !strings.Contains(r.URL, "q=foo") {
		t.Errorf("URL missing q=foo; got %q", r.URL)
	}
}

func TestExtractForms_GetFormFieldOverridesActionQueryDuplicate(t *testing.T) {
	body := `<form action="/search?q=default"><input name="q" value="new"></form>`
	reqs := []crawl.ObservedRequest{htmlReq("https://host/page", body)}
	got := ExtractForms(reqs)
	if len(got) != 1 {
		t.Fatalf("expected 1 result, got %d", len(got))
	}
	if got[0].QueryParams["q"] != "new" {
		t.Errorf("QueryParams[q] = %q, want new (form field should win)", got[0].QueryParams["q"])
	}
}

func TestExtractForms_PostPreservesActionQueryString(t *testing.T) {
	body := `<form method="post" action="/login?ref=home"><input name="user" value="alice"></form>`
	reqs := []crawl.ObservedRequest{htmlReq("https://host/page", body)}
	got := ExtractForms(reqs)
	if len(got) != 1 {
		t.Fatalf("expected 1 result, got %d", len(got))
	}
	r := got[0]
	if !strings.Contains(r.URL, "ref=home") {
		t.Errorf("URL missing ref=home; got %q", r.URL)
	}
	if r.QueryParams["ref"] != "home" {
		t.Errorf("QueryParams[ref] = %q, want home", r.QueryParams["ref"])
	}
	bodyStr := string(r.Body)
	if !strings.Contains(bodyStr, "user=alice") {
		t.Errorf("body missing user=alice; got %q", bodyStr)
	}
	if strings.Contains(bodyStr, "ref=") {
		t.Errorf("body should not contain ref=; got %q", bodyStr)
	}
}

func TestParseForms_NestedUnclosedFormsFlushedInnermostFirst(t *testing.T) {
	body := []byte(`<form action="/outer"><form action="/inner"><input name="x">`)
	forms := parseForms(body)
	if len(forms) != 2 {
		t.Fatalf("expected 2 forms, got %d", len(forms))
	}
	if forms[0].Action != "/inner" {
		t.Errorf("forms[0].Action = %q, want /inner", forms[0].Action)
	}
	if forms[1].Action != "/outer" {
		t.Errorf("forms[1].Action = %q, want /outer", forms[1].Action)
	}
}

func TestParseForms_TextareaDefaultValue(t *testing.T) {
	body := []byte(`<form><textarea name="bio">Some default text</textarea></form>`)
	forms := parseForms(body)
	if len(forms) != 1 || len(forms[0].Fields) != 1 {
		t.Fatalf("unexpected parse result: forms=%d", len(forms))
	}
	if forms[0].Fields[0].Value != "Some default text" {
		t.Errorf("Value = %q, want \"Some default text\"", forms[0].Fields[0].Value)
	}
}

func TestParseForms_TextareaWhitespaceOnlyValueIsEmpty(t *testing.T) {
	body := []byte("<form><textarea name=\"notes\">   \n\t  </textarea></form>")
	forms := parseForms(body)
	if len(forms) != 1 || len(forms[0].Fields) != 1 {
		t.Fatalf("unexpected parse result")
	}
	if forms[0].Fields[0].Value != "" {
		t.Errorf("Value = %q, want empty string for whitespace-only textarea", forms[0].Fields[0].Value)
	}
}

func TestParseForms_SelectSelectedOptionValue(t *testing.T) {
	body := []byte(`<form><select name="country"><option value="us">United States</option><option value="ca" selected>Canada</option></select></form>`)
	forms := parseForms(body)
	if len(forms) != 1 || len(forms[0].Fields) != 1 {
		t.Fatalf("unexpected parse result")
	}
	if forms[0].Fields[0].Value != "ca" {
		t.Errorf("Value = %q, want \"ca\" (selected option)", forms[0].Fields[0].Value)
	}
}

func TestParseForms_SelectNoSelectedUsesFirstOption(t *testing.T) {
	body := []byte(`<form><select name="size"><option value="sm">Small</option><option value="lg">Large</option></select></form>`)
	forms := parseForms(body)
	if len(forms) != 1 || len(forms[0].Fields) != 1 {
		t.Fatalf("unexpected parse result")
	}
	if forms[0].Fields[0].Value != "sm" {
		t.Errorf("Value = %q, want \"sm\" (first option)", forms[0].Fields[0].Value)
	}
}

func TestParseForms_SelectOptionNoValueAttrUsesText(t *testing.T) {
	body := []byte(`<form><select name="color"><option>Red</option><option>Blue</option></select></form>`)
	forms := parseForms(body)
	if len(forms) != 1 || len(forms[0].Fields) != 1 {
		t.Fatalf("unexpected parse result")
	}
	if forms[0].Fields[0].Value != "Red" {
		t.Errorf("Value = %q, want \"Red\" (option text fallback, first option)", forms[0].Fields[0].Value)
	}
}

func TestExtractForms_TextareaValueInGETQuery(t *testing.T) {
	body := `<form action="/submit"><textarea name="msg">hello world</textarea></form>`
	reqs := []crawl.ObservedRequest{htmlReq("https://host/page", body)}
	got := ExtractForms(reqs)
	if len(got) != 1 {
		t.Fatalf("expected 1 result, got %d", len(got))
	}
	if got[0].QueryParams["msg"] != "hello world" {
		t.Errorf("QueryParams[msg] = %q, want \"hello world\"", got[0].QueryParams["msg"])
	}
	if !strings.Contains(got[0].URL, "msg=hello+world") && !strings.Contains(got[0].URL, "msg=hello%20world") {
		t.Errorf("URL missing msg value; got %q", got[0].URL)
	}
}

func TestExtractForms_SelectValueInPOSTBody(t *testing.T) {
	body := `<form method="post" action="/submit"><select name="country"><option value="us">US</option><option value="ca" selected>Canada</option></select></form>`
	reqs := []crawl.ObservedRequest{htmlReq("https://host/page", body)}
	got := ExtractForms(reqs)
	if len(got) != 1 {
		t.Fatalf("expected 1 result, got %d", len(got))
	}
	bodyStr := string(got[0].Body)
	if !strings.Contains(bodyStr, "country=ca") {
		t.Errorf("body missing country=ca; got %q", bodyStr)
	}
}

// SEC-BE-004: resolveAction must strip userinfo from the resolved URL.
func TestResolveAction_UserinfoStripped(t *testing.T) {
	// Non-empty ref: userinfo in ref URL must be stripped.
	got, _, ok := resolveAction("https://h/", "https://admin:hunter2@h/x")
	if !ok {
		t.Fatalf("ok = false, want true")
	}
	if strings.Contains(got, "admin") || strings.Contains(got, "hunter2") {
		t.Errorf("userinfo not stripped from resolved URL; got %q", got)
	}
}

// SEC-BE-002: CSRF field values must not appear in synthesized requests.
func TestExtractForms_CSRFValueNotReplayed(t *testing.T) {
	body := `<form method="post" action="/submit"><input type="hidden" name="csrf_token" value="SECRET123"></form>`
	reqs := []crawl.ObservedRequest{htmlReq("https://host/", body)}
	got := ExtractForms(reqs)
	if len(got) != 1 {
		t.Fatalf("expected 1 result, got %d", len(got))
	}
	bodyStr := string(got[0].Body)
	// Field name must still be present (parameter discovery).
	if !strings.Contains(bodyStr, "csrf_token=") {
		t.Errorf("csrf_token field name missing from body; got %q", bodyStr)
	}
	// But the secret value must NOT be present.
	if strings.Contains(bodyStr, "SECRET123") {
		t.Errorf("CSRF value SECRET123 must not appear in synthesized body; got %q", bodyStr)
	}
}

// SEC-BE-001: parseForms must cap output at maxFormsPerBody forms and
// maxFieldsPerForm fields per form, and getAttr must cap attribute value length
// at maxAttrValueBytes.
func TestParseForms_CapsEnforced(t *testing.T) {
	t.Run("maxFormsPerBody", func(t *testing.T) {
		// Build 2000 sibling <form> elements.
		var b strings.Builder
		for i := 0; i < 2000; i++ {
			b.WriteString(`<form action="/x"><input name="q"></form>`)
		}
		forms := parseForms([]byte(b.String()))
		if len(forms) != maxFormsPerBody {
			t.Errorf("len(forms) = %d, want %d", len(forms), maxFormsPerBody)
		}
	})

	t.Run("maxFieldsPerForm", func(t *testing.T) {
		// Build one form with 1000 <input> fields.
		var b strings.Builder
		b.WriteString(`<form action="/x">`)
		for i := 0; i < 1000; i++ {
			b.WriteString(`<input name="f">`)
		}
		b.WriteString(`</form>`)
		forms := parseForms([]byte(b.String()))
		if len(forms) != 1 {
			t.Fatalf("expected 1 form, got %d", len(forms))
		}
		if len(forms[0].Fields) != maxFieldsPerForm {
			t.Errorf("len(Fields) = %d, want %d", len(forms[0].Fields), maxFieldsPerForm)
		}
	})

	t.Run("maxAttrValueBytes", func(t *testing.T) {
		// Build a single input with a value longer than maxAttrValueBytes.
		longVal := strings.Repeat("a", 5000)
		body := []byte(`<form><input name="x" value="` + longVal + `"></form>`)
		forms := parseForms(body)
		if len(forms) != 1 || len(forms[0].Fields) != 1 {
			t.Fatalf("unexpected parse result: %d forms", len(forms))
		}
		if len(forms[0].Fields[0].Value) > maxAttrValueBytes {
			t.Errorf("Value length = %d, want <= %d", len(forms[0].Fields[0].Value), maxAttrValueBytes)
		}
	})

	t.Run("maxFieldValueBytes_textarea", func(t *testing.T) {
		longText := strings.Repeat("a", 10000)
		body := []byte(`<form><textarea name="bio">` + longText + `</textarea></form>`)
		forms := parseForms(body)
		if len(forms) != 1 || len(forms[0].Fields) != 1 {
			t.Fatalf("unexpected parse result: %d forms", len(forms))
		}
		if len(forms[0].Fields[0].Value) > maxFieldValueBytes {
			t.Errorf("textarea Value length = %d, want <= %d", len(forms[0].Fields[0].Value), maxFieldValueBytes)
		}
	})

	t.Run("maxFieldValueBytes_optionText", func(t *testing.T) {
		// Option without value attribute uses option text as the value;
		// oversized option text must also be capped.
		longText := strings.Repeat("b", 10000)
		body := []byte(`<form><select name="x"><option selected>` + longText + `</option></select></form>`)
		forms := parseForms(body)
		if len(forms) != 1 || len(forms[0].Fields) != 1 {
			t.Fatalf("unexpected parse result: %d forms", len(forms))
		}
		if len(forms[0].Fields[0].Value) > maxFieldValueBytes {
			t.Errorf("select Value (from option text) length = %d, want <= %d", len(forms[0].Fields[0].Value), maxFieldValueBytes)
		}
	})
}

// QUAL-002: A JSON response body containing a <form> string must NOT be sniffed
// as HTML when ContentType is empty.
func TestIsHTMLResponse_JSONWithFormStringNotSniffedAsHTML(t *testing.T) {
	resp := crawl.ObservedResponse{
		ContentType: "",
		Body:        []byte(`{"msg":"<form action='/x'>"}`),
	}
	if isHTMLResponse(resp) {
		t.Errorf("expected false: JSON body with <form> string should not sniff as HTML")
	}
}

// SEC-BE-003: Scheme change on same host must be rejected (http to https is a
// different origin and must not produce a synthetic request).
func TestResolveAction_SchemeChangeSameHostRejected(t *testing.T) {
	_, _, ok := resolveAction("http://h/", "https://h/x")
	if ok {
		t.Errorf("expected ok=false for scheme change on same host, got true")
	}
}

// TEST-002: required attribute on <input> and <select> must set Required=true;
// absence must leave Required=false.
func TestParseForms_RequiredFlag(t *testing.T) {
	body := []byte(`<form><input name="email" required><input name="age"><select name="country" required></select><textarea name="bio"></textarea></form>`)
	forms := parseForms(body)
	if len(forms) != 1 {
		t.Fatalf("expected 1 form, got %d", len(forms))
	}
	fields := forms[0].Fields
	if len(fields) != 4 {
		t.Fatalf("expected 4 fields, got %d: %v", len(fields), fields)
	}
	cases := []struct {
		name     string
		required bool
	}{
		{"email", true},
		{"age", false},
		{"country", true},
		{"bio", false},
	}
	for i, tc := range cases {
		if fields[i].Name != tc.name {
			t.Errorf("fields[%d].Name = %q, want %q", i, fields[i].Name, tc.name)
		}
		if fields[i].Required != tc.required {
			t.Errorf("fields[%d] (%s).Required = %v, want %v", i, tc.name, fields[i].Required, tc.required)
		}
	}
}

// TEST-003a: protocol-relative URL on same host must resolve to the base scheme.
func TestResolveAction_ProtocolRelativeSameHost(t *testing.T) {
	got, _, ok := resolveAction("https://h/a", "//h/b")
	if !ok {
		t.Fatalf("ok = false, want true")
	}
	if got != "https://h/b" {
		t.Errorf("got %q, want https://h/b", got)
	}
}

// TEST-003b: ftp:// scheme in the ref must be rejected.
func TestResolveAction_FTPSchemeRejected(t *testing.T) {
	_, _, ok := resolveAction("https://h/a", "ftp://h/b")
	if ok {
		t.Errorf("expected ok=false for ftp:// scheme, got true")
	}
}

// TEST-001: PageURL on synthesized requests must have userinfo stripped.
// Parent requests imported from Burp/HAR captures may contain credentials
// (https://user:pass@host/path); those must not leak into capture.json.
func TestExtractForms_PageURLUserinfoStripped(t *testing.T) {
	req := crawl.ObservedRequest{ //nolint:gosec // G101: intentional test fixture for userinfo stripping
		URL: "https://admin:secret@host/page",
		Response: crawl.ObservedResponse{
			ContentType: "text/html",
			Body:        []byte(`<form action="/x"><input name="q"></form>`),
		},
	}
	got := ExtractForms([]crawl.ObservedRequest{req})
	if len(got) != 1 {
		t.Fatalf("expected 1 result, got %d", len(got))
	}
	if strings.Contains(got[0].PageURL, "admin") || strings.Contains(got[0].PageURL, "secret") {
		t.Errorf("userinfo not stripped from PageURL; got %q", got[0].PageURL)
	}
	// Sanity: URL field must also still be sanitized.
	if strings.Contains(got[0].URL, "admin") || strings.Contains(got[0].URL, "secret") {
		t.Errorf("userinfo present in URL; got %q", got[0].URL)
	}
}

// TEST-002: the outer range-loop over requests must invoke form parsing once
// per HTML request. Pins regressions that break after the first iteration.
func TestExtractForms_MultipleHTMLRequestsEachProduceForms(t *testing.T) {
	reqs := []crawl.ObservedRequest{
		htmlReq("https://host/login", `<form action="/login" method="post"><input name="username"></form>`),
		htmlReq("https://host/register", `<form action="/register" method="post"><input name="email"></form>`),
	}
	got := ExtractForms(reqs)
	if len(got) != 2 {
		t.Fatalf("expected 2 results, got %d", len(got))
	}
	// Each synthetic request carries its parent's PageURL.
	if got[0].PageURL != "https://host/login" {
		t.Errorf("got[0].PageURL = %q, want https://host/login", got[0].PageURL)
	}
	if got[1].PageURL != "https://host/register" {
		t.Errorf("got[1].PageURL = %q, want https://host/register", got[1].PageURL)
	}
	// Action URLs differ.
	if got[0].URL == got[1].URL {
		t.Errorf("URLs are equal, want distinct; both = %q", got[0].URL)
	}
	if got[0].URL != "https://host/login" {
		t.Errorf("got[0].URL = %q, want https://host/login", got[0].URL)
	}
	if got[1].URL != "https://host/register" {
		t.Errorf("got[1].URL = %q, want https://host/register", got[1].URL)
	}
}

// TEST-003: ExtractForms must tolerate nil and empty input without panic.
func TestExtractForms_EmptyInputReturnsEmpty(t *testing.T) {
	if got := ExtractForms(nil); len(got) != 0 {
		t.Errorf("ExtractForms(nil) len = %d, want 0", len(got))
	}
	if got := ExtractForms([]crawl.ObservedRequest{}); len(got) != 0 {
		t.Errorf("ExtractForms([]) len = %d, want 0", len(got))
	}
}

// TEST-004: duplicate field names (e.g. array-style "tags[]", multi-select
// checkboxes, repeated hidden fields) must be preserved, not collapsed. The
// comment on fieldsToValues explicitly promises url.Values.Add (not Set).
func TestExtractForms_DuplicateNamePreservedPOST(t *testing.T) {
	body := `<form method="post" action="/x"><input name="tags[]" value="a"><input name="tags[]" value="b"></form>`
	reqs := []crawl.ObservedRequest{htmlReq("https://host/", body)}
	got := ExtractForms(reqs)
	if len(got) != 1 {
		t.Fatalf("expected 1 result, got %d", len(got))
	}
	values, err := url.ParseQuery(string(got[0].Body))
	if err != nil {
		t.Fatalf("ParseQuery: %v", err)
	}
	tags := values["tags[]"]
	if len(tags) != 2 {
		t.Fatalf("len(tags[]) = %d, want 2; full values = %v", len(tags), values)
	}
	set := map[string]bool{tags[0]: true, tags[1]: true}
	if !set["a"] || !set["b"] {
		t.Errorf("tags[] = %v, want {a,b}", tags)
	}
}

func TestExtractForms_DuplicateNamePreservedGET(t *testing.T) {
	body := `<form action="/x"><input name="tags[]" value="a"><input name="tags[]" value="b"></form>`
	reqs := []crawl.ObservedRequest{htmlReq("https://host/", body)}
	got := ExtractForms(reqs)
	if len(got) != 1 {
		t.Fatalf("expected 1 result, got %d", len(got))
	}
	u, err := url.Parse(got[0].URL)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	tags := u.Query()["tags[]"]
	if len(tags) != 2 {
		t.Fatalf("len(tags[]) = %d, want 2; raw URL = %q", len(tags), got[0].URL)
	}
	set := map[string]bool{tags[0]: true, tags[1]: true}
	if !set["a"] || !set["b"] {
		t.Errorf("tags[] = %v, want {a,b}", tags)
	}
}

// --- TEST-002: forms inside table elements ---

// TestExtractForms_FormInsideTable verifies that a form nested inside table
// elements is correctly parsed and synthesized.
func TestExtractForms_FormInsideTable(t *testing.T) {
	body := `<table><tr><td><form action="/x"><input name="q"></form></td></tr></table>`
	reqs := []crawl.ObservedRequest{htmlReq("https://host/", body)}
	got := ExtractForms(reqs)
	if len(got) != 1 {
		t.Fatalf("expected 1 result, got %d", len(got))
	}
	if got[0].URL != "https://host/x?q=" {
		t.Errorf("URL = %q, want https://host/x?q=", got[0].URL)
	}
}

// TestExtractForms_FormSpanningTableRows pins the tokenizer-based behavior
// for the malformed-HTML case where <form> wraps <tr>/<td> inside a <table>.
// The Go html tokenizer does NOT apply HTML5 foster-parenting rules, so the
// form tag may be re-ordered relative to the table structure. This test locks
// whatever the current tokenizer produces so that a later switch to html.Parse
// (which applies foster-parenting) would be detected.
func TestExtractForms_FormSpanningTableRows(t *testing.T) {
	body := `<table><form action="/x"><tr><td><input name="q"></td></tr></form></table>`
	reqs := []crawl.ObservedRequest{htmlReq("https://host/", body)}
	got := ExtractForms(reqs)
	// The tokenizer-based parser does see the <form> and <input> tokens in
	// document order and emits one synthetic request. If this ever starts
	// producing 0 results, a switch to an HTML5-foster-parenting parser
	// was likely made and this test must be updated.
	if len(got) != 1 {
		t.Fatalf("expected 1 result (pin current tokenizer behavior), got %d", len(got))
	}
	if !strings.Contains(got[0].URL, "/x") {
		t.Errorf("URL %q does not reference /x action", got[0].URL)
	}
	if !strings.Contains(got[0].URL, "q=") {
		t.Errorf("URL %q missing q= field", got[0].URL)
	}
}

// --- TEST-003: fragment-only action tests ---

// TestExtractForms_FragmentOnlyActionSelfSubmits verifies that fragment-only
// actions (#section, #) resolve to the page URL (self-submit semantics).
func TestExtractForms_FragmentOnlyActionSelfSubmits(t *testing.T) {
	cases := []struct {
		action string
	}{
		{"#section"},
		{"#"},
	}
	for _, tc := range cases {
		body := `<form action="` + tc.action + `"><input name="q"></form>`
		reqs := []crawl.ObservedRequest{htmlReq("https://host/page", body)}
		got := ExtractForms(reqs)
		if len(got) != 1 {
			t.Errorf("action=%q: expected 1 result, got %d", tc.action, len(got))
			continue
		}
		if got[0].URL != "https://host/page?q=" {
			t.Errorf("action=%q: URL = %q, want https://host/page?q=", tc.action, got[0].URL)
		}
	}
}

// TestResolveAction_FragmentOnly verifies that resolveAction resolves a
// fragment-only ref to the base URL (with fragment stripped).
func TestResolveAction_FragmentOnly(t *testing.T) {
	got, _, ok := resolveAction("https://h/p", "#frag")
	if !ok {
		t.Fatalf("ok = false, want true")
	}
	if got != "https://h/p" {
		t.Errorf("got %q, want https://h/p", got)
	}
}

// --- TEST-004: entity-encoded attributes ---

// TestExtractForms_EntityEncodedAttributes verifies that HTML entity-encoded
// characters in action attributes and field names/values are decoded correctly.
func TestExtractForms_EntityEncodedAttributes(t *testing.T) {
	t.Run("ActionQueryAmpersandDecoded", func(t *testing.T) {
		body := `<form action="/search?a=1&amp;b=2"><input name="q"></form>`
		reqs := []crawl.ObservedRequest{htmlReq("https://host/", body)}
		got := ExtractForms(reqs)
		if len(got) != 1 {
			t.Fatalf("expected 1 result, got %d", len(got))
		}
		u, err := url.Parse(got[0].URL)
		if err != nil {
			t.Fatalf("url.Parse: %v", err)
		}
		if u.Query().Get("a") != "1" {
			t.Errorf("query a = %q, want 1", u.Query().Get("a"))
		}
		if u.Query().Get("b") != "2" {
			t.Errorf("query b = %q, want 2", u.Query().Get("b"))
		}
		if _, ok := u.Query()["q"]; !ok {
			t.Errorf("query missing q key; full query: %v", u.Query())
		}
		if strings.Contains(got[0].URL, "&amp;") {
			t.Errorf("URL contains raw &amp; entity; got %q", got[0].URL)
		}
	})

	t.Run("FieldNameAndValueEntityDecoded", func(t *testing.T) {
		body := `<form method="post" action="/x"><input name="user&amp;name" value="O&apos;Brien"></form>`
		reqs := []crawl.ObservedRequest{htmlReq("https://host/", body)}
		got := ExtractForms(reqs)
		if len(got) != 1 {
			t.Fatalf("expected 1 result, got %d", len(got))
		}
		vals, err := url.ParseQuery(string(got[0].Body))
		if err != nil {
			t.Fatalf("ParseQuery: %v", err)
		}
		// user&name is NOT a hidden field, so its value IS preserved per SEC-BE-005.
		if vals.Get("user&name") != "O'Brien" {
			t.Errorf(`vals["user&name"] = %q, want "O'Brien"; all vals: %v`, vals.Get("user&name"), vals)
		}
	})
}

// --- SEC-BE-005 regression tests ---

// TestExtractForms_HiddenSessionIDValueNotReplayed verifies that hidden input
// values are stripped (SEC-BE-005) for both POST and GET forms.
func TestExtractForms_HiddenSessionIDValueNotReplayed(t *testing.T) {
	t.Run("POST", func(t *testing.T) {
		body := `<form method="post" action="/go"><input type="hidden" name="sessionid" value="SECRET-SESSION-1234"></form>`
		reqs := []crawl.ObservedRequest{htmlReq("https://host/", body)}
		got := ExtractForms(reqs)
		if len(got) != 1 {
			t.Fatalf("expected 1 result, got %d", len(got))
		}
		bodyStr := string(got[0].Body)
		if !strings.Contains(bodyStr, "sessionid=") {
			t.Errorf("body missing sessionid= (name must be preserved); got %q", bodyStr)
		}
		if strings.Contains(bodyStr, "SECRET-SESSION-1234") {
			t.Errorf("body contains secret value SECRET-SESSION-1234 (must be stripped per SEC-BE-005); got %q", bodyStr)
		}
	})

	t.Run("GET", func(t *testing.T) {
		body := `<form action="/go"><input type="hidden" name="sessionid" value="SECRET-SESSION-1234"></form>`
		reqs := []crawl.ObservedRequest{htmlReq("https://host/", body)}
		got := ExtractForms(reqs)
		if len(got) != 1 {
			t.Fatalf("expected 1 result, got %d", len(got))
		}
		if !strings.Contains(got[0].URL, "sessionid=") {
			t.Errorf("URL missing sessionid= (name must be preserved); got %q", got[0].URL)
		}
		if strings.Contains(got[0].URL, "SECRET-SESSION-1234") {
			t.Errorf("URL contains secret value SECRET-SESSION-1234 (must be stripped per SEC-BE-005); got %q", got[0].URL)
		}
	})
}

// TestExtractForms_HiddenFieldVariousSecretNamesStripped verifies that
// SEC-BE-005 applies to ALL hidden fields regardless of field name — not just
// names that match the narrower CSRF-name heuristic. This proves that the
// default-strip-value-from-all-Hidden behavior is in effect.
func TestExtractForms_HiddenFieldVariousSecretNamesStripped(t *testing.T) {
	names := []string{
		"__RequestVerificationToken",
		"state",
		"nonce",
		"code_verifier",
		"RelayState",
		"SAMLRequest",
		"phpsessid",
		"jsessionid",
		"api_key",
		"access_token",
		"id_token",
		"bearer",
		"jwt",
	}
	for _, name := range names {
		secretVal := "SECRET-VAL-FOR-" + name
		body := `<form method="post" action="/x"><input type="hidden" name="` + name + `" value="` + secretVal + `"></form>`
		reqs := []crawl.ObservedRequest{htmlReq("https://host/", body)}
		got := ExtractForms(reqs)
		if len(got) != 1 {
			t.Errorf("name=%q: expected 1 result, got %d", name, len(got))
			continue
		}
		bodyStr := string(got[0].Body)
		if strings.Contains(bodyStr, secretVal) {
			t.Errorf("name=%q: secret value %q must not appear in body (SEC-BE-005); got %q", name, secretVal, bodyStr)
		}
	}
}

// --- SEC-BE-001 regression test ---

// TestExtractForms_OversizedBodyTruncated verifies that response bodies larger
// than maxBodyBytes (8 MiB) are truncated before tokenizing, so content past
// the cap is ignored.
func TestExtractForms_OversizedBodyTruncated(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping oversized body test in short mode")
	}
	// Build an HTML body that exceeds 8 MiB:
	//   - starts with an early form
	//   - padded with > 8 MiB of filler comments
	//   - ends with a late form that must NOT be found
	earlyForm := `<form action="/early"><input name="x"></form>`
	lateForm := `<form action="/late"><input name="late"></form>`

	// Each comment is ~40 bytes; we need > maxBodyBytes / 40 iterations.
	commentUnit := `<!-- padding padding padding padding -->`
	repeatsNeeded := (maxBodyBytes / len(commentUnit)) + 100

	var b strings.Builder
	b.WriteString(earlyForm)
	b.WriteString(strings.Repeat(commentUnit, repeatsNeeded))
	b.WriteString(lateForm)

	reqs := []crawl.ObservedRequest{htmlReq("https://host/", b.String())}
	got := ExtractForms(reqs)

	foundEarly := false
	foundLate := false
	for _, r := range got {
		if strings.Contains(r.URL, "/early") {
			foundEarly = true
		}
		if strings.Contains(r.URL, "/late") {
			foundLate = true
		}
	}

	if !foundEarly {
		t.Errorf("expected /early form to be found (it precedes the truncation point), but it was not; got %d results: %v",
			len(got), got)
	}
	if foundLate {
		t.Errorf("expected /late form to be absent (it follows the truncation point), but it was found; got %d results: %v",
			len(got), got)
	}
}

// --- SEC-BE-002 regression test ---

// TestExtractForms_FieldNameWithControlBytesDropped verifies that field names
// containing control bytes (< 0x20 or == 0x7f) are dropped entirely.
func TestExtractForms_FieldNameWithControlBytesDropped(t *testing.T) {
	// &#13; is CR (0x0D), a control byte that must be rejected.
	body := `<form action="/x"><input name="ok"><input name="bad&#13;name"></form>`
	reqs := []crawl.ObservedRequest{htmlReq("https://host/", body)}
	got := ExtractForms(reqs)
	if len(got) != 1 {
		t.Fatalf("expected 1 result, got %d", len(got))
	}
	if !strings.Contains(got[0].URL, "ok=") {
		t.Errorf("URL missing ok= (valid field must be present); got %q", got[0].URL)
	}
	// Verify no control bytes appear anywhere in the URL.
	for i := 0; i < len(got[0].URL); i++ {
		b := got[0].URL[i]
		if b < 0x20 || b == 0x7f {
			t.Errorf("URL contains control byte 0x%02x at position %d; got %q", b, i, got[0].URL)
		}
	}
	// QueryParams must not contain a key with control bytes.
	if got[0].QueryParams != nil {
		for k := range got[0].QueryParams {
			for i := 0; i < len(k); i++ {
				b := k[i]
				if b < 0x20 || b == 0x7f {
					t.Errorf("QueryParams key %q contains control byte 0x%02x", k, b)
				}
			}
		}
	}
	if _, ok := got[0].QueryParams["ok"]; !ok {
		t.Errorf("QueryParams missing ok key; got %v", got[0].QueryParams)
	}
}

// --- SEC-BE-003 regression test ---

// TestExtractForms_DirtyMethodFallsBackToGET verifies that form method
// attributes containing control characters or unknown verbs are normalised
// to GET.
func TestExtractForms_DirtyMethodFallsBackToGET(t *testing.T) {
	cases := []struct {
		input    string // method attribute value; "" means omit
		expected string
	}{
		{"GE&#13;&#10;T", "GET"},
		{"FROBNICATE", "GET"},
		{"&#0;POST", "GET"},
		{"POST", "POST"},
		{"", "GET"},
	}
	for _, tc := range cases {
		var body string
		if tc.input == "" {
			body = `<form action="/x"><input name="q"></form>`
		} else {
			body = `<form method="` + tc.input + `" action="/x"><input name="q"></form>`
		}
		reqs := []crawl.ObservedRequest{htmlReq("https://host/", body)}
		got := ExtractForms(reqs)
		if len(got) != 1 {
			t.Errorf("input=%q: expected 1 result, got %d", tc.input, len(got))
			continue
		}
		if got[0].Method != tc.expected {
			t.Errorf("input=%q: Method = %q, want %q", tc.input, got[0].Method, tc.expected)
		}
	}
}

// --- SEC-BE-004 regression test ---

// TestExtractForms_DirtyEnctypeFallsBackToDefault verifies that enctype values
// containing control characters (potential header-injection payloads) are
// rejected and fall back to application/x-www-form-urlencoded.
func TestExtractForms_DirtyEnctypeFallsBackToDefault(t *testing.T) {
	t.Run("InjectedEnctype", func(t *testing.T) {
		// &#13;&#10; is CRLF — a potential header-injection payload.
		body := `<form method="post" enctype="text/plain&#13;&#10;X-Inject: evil" action="/x"><input name="q"></form>`
		reqs := []crawl.ObservedRequest{htmlReq("https://host/", body)}
		got := ExtractForms(reqs)
		if len(got) != 1 {
			t.Fatalf("expected 1 result, got %d", len(got))
		}
		ct := got[0].Headers["content-type"]
		if ct != "application/x-www-form-urlencoded" {
			t.Errorf("content-type = %q, want application/x-www-form-urlencoded", ct)
		}
		// Verify the header value contains no control bytes.
		for i := 0; i < len(ct); i++ {
			b := ct[i]
			if b < 0x20 || b == 0x7f {
				t.Errorf("content-type contains control byte 0x%02x at position %d: %q", b, i, ct)
			}
		}
	})

	t.Run("UppercaseMultipartNormalised", func(t *testing.T) {
		// Uppercase enctype must be lowercased and accepted.
		body := `<form method="post" enctype="MULTIPART/FORM-DATA" action="/x"><input name="q"></form>`
		reqs := []crawl.ObservedRequest{htmlReq("https://host/", body)}
		got := ExtractForms(reqs)
		if len(got) != 1 {
			t.Fatalf("expected 1 result, got %d", len(got))
		}
		ct := got[0].Headers["content-type"]
		if ct != "multipart/form-data" {
			t.Errorf("content-type = %q, want multipart/form-data (lowercased)", ct)
		}
	})
}
