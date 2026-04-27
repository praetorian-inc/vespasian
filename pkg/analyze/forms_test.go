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
	bodyStr := string(r.Body)
	if !strings.Contains(bodyStr, "username=") {
		t.Errorf("body missing username=; got %q", bodyStr)
	}
	if !strings.Contains(bodyStr, "password=") {
		t.Errorf("body missing password=; got %q", bodyStr)
	}
	if !strings.Contains(bodyStr, "remember=") {
		t.Errorf("body missing remember=; got %q", bodyStr)
	}
	// submit and button should not appear
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

func TestExtractForms_HiddenFieldFlagged(t *testing.T) {
	body := `<form method="post" action="/go"><input type="hidden" name="return_to" value="/home"></form>`
	reqs := []crawl.ObservedRequest{htmlReq("https://host/page", body)}
	got := ExtractForms(reqs)
	if len(got) != 1 {
		t.Fatalf("expected 1 result, got %d", len(got))
	}
	if !strings.Contains(string(got[0].Body), "return_to=") {
		t.Errorf("body missing return_to=; got %q", string(got[0].Body))
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

func TestExtractForms_UppercasedMethodNormalised(t *testing.T) {
	body := `<form method="post" action="/x"><input name="a"></form>`
	reqs := []crawl.ObservedRequest{htmlReq("https://host/", body)}
	got := ExtractForms(reqs)
	if len(got) != 1 {
		t.Fatalf("expected 1 result, got %d", len(got))
	}
	if got[0].Method != "POST" {
		t.Errorf("Method = %q, want POST", got[0].Method)
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
	bodyStr := string(got[0].Body)
	if !strings.Contains(bodyStr, "valid=yes") {
		t.Errorf("body missing valid=yes; got %q", bodyStr)
	}
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
