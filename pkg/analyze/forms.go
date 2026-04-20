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
	"bytes"
	"net/url"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"

	"github.com/praetorian-inc/vespasian/pkg/crawl"
)

// SourceStaticHTML is the Source value assigned to ObservedRequests
// synthesized from static HTML form analysis.
const SourceStaticHTML = "static:html"

// staticForm is the intermediate representation of a parsed <form>.
type staticForm struct {
	Action  string            // raw action attribute (unresolved)
	Method  string            // raw method attribute (unresolved)
	Enctype string            // raw enctype (possibly empty)
	Fields  []staticFormField // preserves discovery order; duplicates allowed
}

type staticFormField struct {
	Name        string
	Type        string // lowercased; empty if absent ("" treated as "text")
	Value       string
	Placeholder string
	Required    bool
	Hidden      bool // type=="hidden"
	CSRF        bool // heuristic match on Name
}

// ExtractForms scans each request's HTML response body for <form> elements
// and returns one synthetic ObservedRequest per form. Non-HTML responses and
// responses with empty bodies are skipped. The returned slice can be appended
// directly to the captured requests slice before classification.
func ExtractForms(requests []crawl.ObservedRequest) []crawl.ObservedRequest {
	var out []crawl.ObservedRequest
	for _, req := range requests {
		if !isHTMLResponse(req.Response) {
			continue
		}
		if len(req.Response.Body) == 0 {
			continue
		}
		forms := parseForms(req.Response.Body)
		for _, f := range forms {
			synth, ok := synthesizeRequest(f, req.URL)
			if !ok {
				continue
			}
			out = append(out, synth)
		}
	}
	return out
}

// isHTMLResponse returns true if the response is likely HTML. It checks the
// Content-Type (case-insensitive, tolerant of "; charset=..." suffix) and,
// if that's empty/ambiguous, falls back to sniffing for a DOCTYPE or <html>
// within the first 512 bytes.
func isHTMLResponse(resp crawl.ObservedResponse) bool {
	ct := strings.ToLower(strings.TrimSpace(resp.ContentType))
	if ct == "" {
		// Also check the Headers map — Content-Type may live there instead.
		for k, v := range resp.Headers {
			if strings.EqualFold(k, "content-type") {
				ct = strings.ToLower(strings.TrimSpace(v))
				break
			}
		}
	}
	if strings.HasPrefix(ct, "text/html") ||
		strings.HasPrefix(ct, "application/xhtml+xml") {
		return true
	}
	if ct != "" {
		// Known non-HTML content type — skip, don't sniff.
		return false
	}
	// No content-type at all: sniff the first 512 bytes.
	n := len(resp.Body)
	if n > 512 {
		n = 512
	}
	head := strings.ToLower(string(resp.Body[:n]))
	return strings.Contains(head, "<!doctype html") ||
		strings.Contains(head, "<html") ||
		strings.Contains(head, "<form")
}

// parseForms tokenizes body and returns every <form> element found, including
// leftovers left open at EOF and recoverable nested forms.
func parseForms(body []byte) []staticForm {
	z := html.NewTokenizer(bytes.NewReader(body))
	var stack []*staticForm
	var results []staticForm

	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			// EOF or malformed — flush unclosed forms innermost-first to match
			// normal close-tag order (</form> pops from the top of the stack).
			for i := len(stack) - 1; i >= 0; i-- {
				results = append(results, *stack[i])
			}
			return results

		case html.StartTagToken, html.SelfClosingTagToken:
			stack = handleStartTag(z.Token(), stack)

		case html.EndTagToken:
			tok := z.Token()
			if tok.DataAtom == atom.Form && len(stack) > 0 {
				f := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				results = append(results, *f)
			}
		}
	}
}

// handleStartTag processes a start/self-closing tag token and updates the
// form stack. Returns the updated stack.
func handleStartTag(tok html.Token, stack []*staticForm) []*staticForm {
	switch tok.DataAtom {
	case atom.Form:
		f := &staticForm{
			Action:  getAttr(tok, "action"),
			Method:  getAttr(tok, "method"),
			Enctype: getAttr(tok, "enctype"),
		}
		stack = append(stack, f)

	case atom.Input:
		if len(stack) == 0 {
			break
		}
		// Skip form="..." cross-association per ticket scope note.
		if _, hasFormAttr := getAttrOK(tok, "form"); hasFormAttr {
			break
		}
		name := getAttr(tok, "name")
		if name == "" {
			break
		}
		typ := strings.ToLower(getAttr(tok, "type"))
		if isSkippableType(typ) {
			break
		}
		f := stack[len(stack)-1]
		f.Fields = append(f.Fields, staticFormField{
			Name:        name,
			Type:        typ,
			Value:       getAttr(tok, "value"),
			Placeholder: getAttr(tok, "placeholder"),
			Required:    hasAttr(tok, "required"),
			Hidden:      typ == "hidden",
			CSRF:        isCSRFName(name),
		})

	case atom.Select, atom.Textarea:
		if len(stack) == 0 {
			break
		}
		if _, hasFormAttr := getAttrOK(tok, "form"); hasFormAttr {
			break
		}
		name := getAttr(tok, "name")
		if name == "" {
			break
		}
		f := stack[len(stack)-1]
		f.Fields = append(f.Fields, staticFormField{
			Name:        name,
			Type:        tok.Data, // "select" or "textarea" — not a real input type
			Placeholder: getAttr(tok, "placeholder"),
			Required:    hasAttr(tok, "required"),
			CSRF:        isCSRFName(name),
		})
	}
	return stack
}

// synthesizeRequest converts a parsed form into an ObservedRequest. It
// resolves the action against baseURL and populates Method/URL/Headers/Body/
// QueryParams/Source/PageURL. Returns (_, false) if the action cannot be
// resolved to an http(s) URL.
func synthesizeRequest(f staticForm, baseURL string) (crawl.ObservedRequest, bool) {
	resolved, ok := resolveAction(baseURL, f.Action)
	if !ok {
		return crawl.ObservedRequest{}, false
	}

	method := strings.ToUpper(strings.TrimSpace(f.Method))
	if method == "" {
		method = "GET"
	}

	enctype := strings.TrimSpace(f.Enctype)
	if enctype == "" {
		enctype = "application/x-www-form-urlencoded"
	}

	obs := crawl.ObservedRequest{
		Method:  method,
		URL:     resolved,
		Source:  SourceStaticHTML,
		PageURL: baseURL,
	}

	values := fieldsToValues(f.Fields)

	if method == "GET" {
		u, err := url.Parse(resolved)
		if err != nil {
			return crawl.ObservedRequest{}, false
		}
		q := u.Query()
		// Form fields take precedence over pre-existing action-URL query values
		// on key conflict; all duplicate form-field values are preserved.
		for k, vs := range values {
			q.Del(k)
			for _, v := range vs {
				q.Add(k, v)
			}
		}
		u.RawQuery = q.Encode()
		obs.URL = u.String()
		obs.QueryParams = flattenQuery(u.Query())
	} else {
		// NOTE: Even when the form declares multipart/form-data, we URL-encode
		// the body. The goal of ExtractForms is parameter discovery for spec
		// generation, not faithful request replay. Mirrors crawl.formsToObservedRequests
		// for consistency.
		obs.Headers = map[string]string{"content-type": enctype}
		obs.Body = []byte(values.Encode())
		// Preserve any pre-existing query in the action URL.
		if u, err := url.Parse(resolved); err == nil {
			obs.QueryParams = flattenQuery(u.Query())
		}
	}

	return obs, true
}

// resolveAction resolves a form action against baseURL. Empty/missing action
// ("") returns baseURL unchanged (self-submit). Non-http(s) schemes and
// unparseable URLs return ("", false).
func resolveAction(base, ref string) (string, bool) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		u, err := url.Parse(base)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return "", false
		}
		u.Fragment = ""
		return u.String(), true
	}
	lower := strings.ToLower(ref)
	if strings.HasPrefix(lower, "javascript:") ||
		strings.HasPrefix(lower, "mailto:") ||
		strings.HasPrefix(lower, "data:") ||
		strings.HasPrefix(lower, "tel:") ||
		strings.HasPrefix(lower, "blob:") {
		return "", false
	}
	baseU, err := url.Parse(base)
	if err != nil {
		return "", false
	}
	refU, err := url.Parse(ref)
	if err != nil {
		return "", false
	}
	resolved := baseU.ResolveReference(refU)
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return "", false
	}
	resolved.Fragment = ""
	return resolved.String(), true
}

// isCSRFName matches common CSRF parameter names (case-insensitive substring):
// "csrf", "_token", "authenticity_token", "xsrf".
func isCSRFName(name string) bool {
	n := strings.ToLower(name)
	return strings.Contains(n, "csrf") ||
		strings.Contains(n, "xsrf") ||
		n == "_token" ||
		strings.Contains(n, "authenticity_token")
}

// isSkippableType reports whether an <input type="..."> carries no
// parameter-discovery data. Matches crawl.isSkippableInputType exactly:
// submit, button, image, reset, file (all lowercased).
func isSkippableType(inputType string) bool {
	switch inputType {
	case "submit", "button", "image", "file", "reset":
		return true
	}
	return false
}

// fieldValue returns value, or placeholder if value is empty, or "".
func fieldValue(f staticFormField) string {
	if f.Value != "" {
		return f.Value
	}
	return f.Placeholder
}

// fieldsToValues converts staticFormField slice into url.Values, preserving
// insertion order and all duplicates. url.Values.Add is used (not Set) because
// staticForm.Fields explicitly allows duplicate names (e.g. multi-select
// checkboxes, array-style names like tags[], repeated hidden fields).
func fieldsToValues(fields []staticFormField) url.Values {
	values := url.Values{}
	for _, fld := range fields {
		values.Add(fld.Name, fieldValue(fld))
	}
	return values
}

// flattenQuery converts url.Values to a map[string]string taking the first
// value for each key. Returns nil for empty input.
func flattenQuery(v url.Values) map[string]string {
	if len(v) == 0 {
		return nil
	}
	out := make(map[string]string, len(v))
	for k, vs := range v {
		if len(vs) > 0 {
			out[k] = vs[0]
		}
	}
	return out
}

func getAttr(t html.Token, key string) string {
	for _, a := range t.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}

func getAttrOK(t html.Token, key string) (string, bool) {
	for _, a := range t.Attr {
		if a.Key == key {
			return a.Val, true
		}
	}
	return "", false
}

func hasAttr(t html.Token, key string) bool {
	_, ok := getAttrOK(t, key)
	return ok
}
