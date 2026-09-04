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

// SourceStaticHTML tags requests synthesized from static HTML form analysis.
const SourceStaticHTML = "static:html"

const (
	maxFormsPerBody    = 1000
	maxFieldsPerForm   = 500
	maxAttrValueBytes  = 4096
	maxFieldValueBytes = 4096    // textarea and <option> text
	maxBodyBytes       = 8 << 20 // HTML bodies handed to parseForms
)

type staticForm struct {
	Action  string            // raw, unresolved
	Method  string            // raw, unresolved
	Enctype string            // may be empty
	Fields  []staticFormField // discovery order; duplicates allowed
}

type staticFormField struct {
	Name        string
	Type        string // lowercased; "" means "text"
	Value       string
	Placeholder string
	Required    bool
	Hidden      bool
	Sensitive   bool // isSensitiveName matched
}

// sentinelSelectedOption marks a <option selected> seen before its value
// resolved. x/net/html replaces NUL with U+FFFD in parsed attribute values and
// text, so the prefix distinguishes the marker from a real value.
const sentinelSelectedOption = "\x00selected"

// ExtractForms returns at most one synthetic ObservedRequest per <form>, ready to
// append to the captured slice: forms whose action is unparseable, non-http(s) or
// off-host are dropped. Bodies over maxBodyBytes are truncated first.
func ExtractForms(requests []crawl.ObservedRequest) []crawl.ObservedRequest {
	var out []crawl.ObservedRequest
	for _, req := range requests {
		if !isHTMLResponse(req.Response) {
			continue
		}
		if len(req.Response.Body) == 0 {
			continue
		}
		body := req.Response.Body
		if len(body) > maxBodyBytes {
			body = body[:maxBodyBytes]
		}
		forms := parseForms(body)
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

// isHTMLResponse checks Content-Type, then sniffs the first 512 bytes for a
// doctype or <html> when it is absent.
func isHTMLResponse(resp crawl.ObservedResponse) bool {
	ct := strings.ToLower(strings.TrimSpace(resp.ContentType))
	if ct == "" {
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
	// A known non-HTML type is authoritative; only sniff when there is none.
	if ct != "" {
		return false
	}
	n := len(resp.Body)
	if n > 512 {
		n = 512
	}
	head := strings.ToLower(string(resp.Body[:n]))
	return strings.Contains(head, "<!doctype html") ||
		strings.Contains(head, "<html")
}

// pendingFieldState covers elements whose value spans several tokens.
type pendingFieldState struct {
	field       *staticFormField // into the parent form's Fields
	inTextarea  bool
	inSelect    bool
	inOption    bool
	optionValue string // empty means fall back to optionText
	optionText  string
	firstOption *string // non-nil once the first option resolved
}

// parseForms returns every <form>, including ones left open at EOF and
// recoverable nested ones.
func parseForms(body []byte) []staticForm {
	z := html.NewTokenizer(bytes.NewReader(body))
	var stack []*staticForm
	var results []staticForm
	var pending *pendingFieldState

	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			return flushUnclosedForms(stack, results, pending)

		case html.StartTagToken, html.SelfClosingTagToken:
			tok := z.Token()
			if pending != nil {
				handlePendingStartTag(tok, pending)
				continue
			}
			// Keep tokenizing past the cap so forms already on the stack still
			// flush at EOF.
			if tok.DataAtom == atom.Form && len(results)+len(stack) >= maxFormsPerBody {
				continue
			}
			stack = handleStartTag(tok, stack, &pending)

		case html.TextToken:
			if pending != nil {
				handlePendingText(string(z.Raw()), pending)
			}

		case html.EndTagToken:
			tok := z.Token()
			if pending != nil {
				handlePendingEndTag(tok, &pending)
				continue
			}
			if tok.DataAtom == atom.Form && len(stack) > 0 {
				f := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				results = append(results, *f)
			}
		}
	}
}

// flushUnclosedForms drains the stack innermost-first, resolving any in-flight
// select.
func flushUnclosedForms(stack []*staticForm, results []staticForm, pending *pendingFieldState) []staticForm {
	if pending != nil && pending.inSelect {
		resolveSelectValue(pending)
	}
	for i := len(stack) - 1; i >= 0; i-- {
		results = append(results, *stack[i])
	}
	return results
}

// handlePendingStartTag only cares about <option> inside a select.
func handlePendingStartTag(tok html.Token, pending *pendingFieldState) {
	if !pending.inSelect || tok.DataAtom != atom.Option {
		return
	}
	pending.inOption = true
	pending.optionValue = getAttr(tok, "value")
	pending.optionText = ""
	if hasAttr(tok, "selected") && pending.field.Value == "" {
		pending.field.Value = sentinelSelectedOption
	}
}

// handlePendingText accumulates up to maxFieldValueBytes, so attacker-controlled
// HTML cannot grow a synthesized body without bound.
func handlePendingText(text string, pending *pendingFieldState) {
	switch {
	case pending.inTextarea:
		pending.field.Value = appendCapped(pending.field.Value, text, maxFieldValueBytes)
	case pending.inSelect && pending.inOption:
		pending.optionText = appendCapped(pending.optionText, text, maxFieldValueBytes)
	}
}

// appendCapped truncates to limit without materializing the join when prefix is
// already there.
func appendCapped(prefix, suffix string, limit int) string {
	if len(prefix) >= limit {
		return prefix
	}
	remaining := limit - len(prefix)
	if len(suffix) > remaining {
		suffix = suffix[:remaining]
	}
	return prefix + suffix
}

// handlePendingEndTag updates or clears pending through the double pointer.
func handlePendingEndTag(tok html.Token, pending **pendingFieldState) {
	p := *pending
	switch tok.DataAtom {
	case atom.Option:
		if p.inSelect && p.inOption {
			commitOption(p)
		}
	case atom.Select:
		resolveSelectValue(p)
		*pending = nil
	case atom.Textarea:
		p.field.Value = strings.TrimSpace(p.field.Value)
		*pending = nil
	}
}

// commitOption resolves the sentinel and records the first-option fallback.
func commitOption(p *pendingFieldState) {
	optVal := p.optionValue
	if optVal == "" {
		optVal = strings.TrimSpace(p.optionText)
	}
	if p.field.Value == sentinelSelectedOption {
		p.field.Value = optVal
	}
	if p.firstOption == nil {
		v := optVal
		p.firstOption = &v
	}
	p.inOption = false
	p.optionValue = ""
	p.optionText = ""
}

// resolveSelectValue prefers the selected option, else the first.
func resolveSelectValue(p *pendingFieldState) {
	if p.field.Value == sentinelSelectedOption {
		p.field.Value = ""
	}
	if p.field.Value == "" && p.firstOption != nil {
		p.field.Value = *p.firstOption
	}
}

// handleStartTag updates the form stack, setting pending on textarea or select so
// later tokens route to the right field.
func handleStartTag(tok html.Token, stack []*staticForm, pending **pendingFieldState) []*staticForm {
	switch tok.DataAtom {
	case atom.Form:
		f := &staticForm{
			Action:  getAttr(tok, "action"),
			Method:  getAttr(tok, "method"),
			Enctype: getAttr(tok, "enctype"),
		}
		stack = append(stack, f)

	case atom.Input:
		handleInputTag(tok, stack)

	case atom.Textarea:
		handleTextareaTag(tok, stack, pending)

	case atom.Select:
		handleSelectTag(tok, stack, pending)
	}
	return stack
}

// currentFormForField is the shared guard: ok=false for no current form, a
// cross-form form= attribute, a missing or control-byte-bearing name, or the
// per-form field cap.
func currentFormForField(tok html.Token, stack []*staticForm) (*staticForm, string, bool) {
	if len(stack) == 0 {
		return nil, "", false
	}
	if _, hasFormAttr := getAttrOK(tok, "form"); hasFormAttr {
		return nil, "", false
	}
	name := getAttr(tok, "name")
	if name == "" || containsControlByte(name) {
		return nil, "", false
	}
	f := stack[len(stack)-1]
	if len(f.Fields) >= maxFieldsPerForm {
		return nil, "", false
	}
	return f, name, true
}

// handleInputTag appends when the <input> passes currentFormForField and is not a
// skippable type.
func handleInputTag(tok html.Token, stack []*staticForm) {
	f, name, ok := currentFormForField(tok, stack)
	if !ok {
		return
	}
	typ := strings.ToLower(getAttr(tok, "type"))
	if isSkippableType(typ) {
		return
	}
	value := getAttr(tok, "value")
	if typ == "hidden" || typ == "password" {
		value = ""
	}
	f.Fields = append(f.Fields, staticFormField{
		Name:        name,
		Type:        typ,
		Value:       value,
		Placeholder: getAttr(tok, "placeholder"),
		Required:    hasAttr(tok, "required"),
		Hidden:      typ == "hidden",
		Sensitive:   isSensitiveName(name) || typ == "password",
	})
}

// handleTextareaTag sets pending so text accumulates until </textarea>.
func handleTextareaTag(tok html.Token, stack []*staticForm, pending **pendingFieldState) {
	f, name, ok := currentFormForField(tok, stack)
	if !ok {
		return
	}
	f.Fields = append(f.Fields, staticFormField{
		Name:        name,
		Type:        "textarea",
		Placeholder: getAttr(tok, "placeholder"),
		Required:    hasAttr(tok, "required"),
		Sensitive:   isSensitiveName(name),
	})
	// Points INTO f.Fields, so it survives only while nothing appends to that
	// slice. Safe because parseForms routes every tag through
	// handlePendingStartTag while pending is set, and no path there adds a field
	// today.
	fieldPtr := &f.Fields[len(f.Fields)-1]
	*pending = &pendingFieldState{
		field:      fieldPtr,
		inTextarea: true,
	}
}

// handleSelectTag sets pending so <option> tokens are read until </select>.
func handleSelectTag(tok html.Token, stack []*staticForm, pending **pendingFieldState) {
	f, name, ok := currentFormForField(tok, stack)
	if !ok {
		return
	}
	f.Fields = append(f.Fields, staticFormField{
		Name:        name,
		Type:        "select",
		Placeholder: getAttr(tok, "placeholder"),
		Required:    hasAttr(tok, "required"),
		Sensitive:   isSensitiveName(name),
	})
	// See handleTextareaTag for the invariant that keeps this pointer valid.
	fieldPtr := &f.Fields[len(f.Fields)-1]
	*pending = &pendingFieldState{
		field:    fieldPtr,
		inSelect: true,
	}
}

// synthesizeRequest resolves the action against baseURL and fills the request.
// (_, false) when the action is not an http(s) URL.
func synthesizeRequest(f staticForm, baseURL string) (crawl.ObservedRequest, bool) {
	resolved, sanitizedBase, ok := resolveAction(baseURL, f.Action)
	if !ok {
		return crawl.ObservedRequest{}, false
	}

	method := strings.ToUpper(strings.TrimSpace(f.Method))
	if method == "" {
		method = "GET"
	}
	if _, allowed := allowedFormMethods[method]; !allowed {
		method = "GET"
	}

	enctype := strings.ToLower(strings.TrimSpace(f.Enctype))
	if enctype == "" {
		enctype = "application/x-www-form-urlencoded"
	}
	if _, allowed := allowedFormEnctypes[enctype]; !allowed {
		enctype = "application/x-www-form-urlencoded"
	}

	obs := crawl.ObservedRequest{
		Method:  method,
		URL:     resolved,
		Source:  SourceStaticHTML,
		PageURL: sanitizedBase,
	}

	values := fieldsToValues(f.Fields)

	if method == "GET" {
		u, err := url.Parse(resolved)
		if err != nil {
			return crawl.ObservedRequest{}, false
		}
		q := u.Query()
		// Fields win over the action URL's own query on key conflict; duplicates
		// are preserved.
		for k, vs := range values {
			q.Del(k)
			for _, v := range vs {
				q.Add(k, v)
			}
		}
		// Cap before encoding or the URL and QueryParams disagree.
		crawl.CapQueryValues(q)
		u.RawQuery = q.Encode()
		obs.URL = u.String()
		obs.QueryParams = q
	} else {
		// multipart/form-data is URL-encoded anyway: this is parameter discovery
		// for spec generation, not faithful replay. Matches
		// crawl.formsToObservedRequests.
		obs.Headers = map[string]string{"content-type": enctype}
		obs.Body = []byte(values.Encode())
		if u, err := url.Parse(resolved); err == nil {
			// Bound per-key memory from an untrusted action URL.
			obs.QueryParams = crawl.CapQueryValues(u.Query())
		}
	}

	return obs, true
}

// resolveAction returns the resolved action and a sanitized base (userinfo and
// fragment stripped), both safe for capture.json. Empty action self-submits;
// non-http(s), unparseable and off-host actions return ok=false so synthesized
// requests stay in the parent's scope.
func resolveAction(base, ref string) (string, string, bool) {
	ref = strings.TrimSpace(ref)
	baseU, err := url.Parse(base)
	if err != nil || (baseU.Scheme != "http" && baseU.Scheme != "https") {
		return "", "", false
	}
	// Or credentials land in capture.json.
	baseU.User = nil
	baseU.Fragment = ""
	sanitizedBase := baseU.String()
	if ref == "" {
		return sanitizedBase, sanitizedBase, true
	}
	if isUnsupportedSchemeRef(ref) {
		return "", "", false
	}
	refU, err := url.Parse(ref)
	if err != nil {
		return "", "", false
	}
	resolved := baseU.ResolveReference(refU)
	if !validateResolvedURL(baseU, resolved) {
		return "", "", false
	}
	// Same, plus they would be sent in the synthetic request.
	resolved.User = nil
	resolved.Fragment = ""
	return resolved.String(), sanitizedBase, true
}

// isUnsupportedSchemeRef covers javascript:, mailto:, data:, tel: and blob:.
func isUnsupportedSchemeRef(ref string) bool {
	lower := strings.ToLower(ref)
	return strings.HasPrefix(lower, "javascript:") ||
		strings.HasPrefix(lower, "mailto:") ||
		strings.HasPrefix(lower, "data:") ||
		strings.HasPrefix(lower, "tel:") ||
		strings.HasPrefix(lower, "blob:")
}

// effectivePort expands an omitted port to the scheme default. url.URL.Port()
// returns "" in that case, so without this validateResolvedURL rejects
// "https://host:443/x" against base "https://host/" as off-host (RFC 3986).
func effectivePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	switch u.Scheme {
	case "http":
		return "80"
	case "https":
		return "443"
	}
	return ""
}

// validateResolvedURL requires the same scheme, hostname and effective port.
func validateResolvedURL(baseU, resolved *url.URL) bool {
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return false
	}
	if resolved.Scheme != baseU.Scheme {
		return false
	}
	if !strings.EqualFold(resolved.Hostname(), baseU.Hostname()) ||
		effectivePort(resolved) != effectivePort(baseU) {
		return false
	}
	return true
}

// Anything outside allowedFormMethods becomes "GET".
var allowedFormMethods = map[string]struct{}{
	"GET":     {},
	"POST":    {},
	"PUT":     {},
	"PATCH":   {},
	"DELETE":  {},
	"HEAD":    {},
	"OPTIONS": {},
}

// Anything outside allowedFormEnctypes becomes application/x-www-form-urlencoded.
var allowedFormEnctypes = map[string]struct{}{
	"application/x-www-form-urlencoded": {},
	"multipart/form-data":               {},
	"text/plain":                        {},
}

// containsControlByte rejects field names carrying CR, LF, NUL or other control
// bytes, which enable header injection and log forging.
func containsControlByte(s string) bool {
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b < 0x20 || b == 0x7f {
			return true
		}
	}
	return false
}

var sensitiveSubstrings = []string{
	"csrf", "xsrf", "authenticity_token",
	"session", "access_token", "refresh_token",
	"bearer", "jwt", "oauth",
	"apikey", "api_key", "api-key",
	"samlrequest", "samlresponse", "relaystate",
}

// isSensitiveName substring-matches sensitiveSubstrings, plus an exact "_token".
// fieldValue blanks whatever matches, so the value never reaches the synthesized
// request that becomes capture.json and the probe input.
// TestExtractForms_SensitiveNonHiddenValueNotReplayed pins that for the POST body;
// the GET branch puts values in obs.URL and obs.QueryParams instead and has no
// equivalent assertion for a non-hidden sensitive field.
//
// "nonce" and "state" are deliberately absent: they collide with ordinary
// parameters, e.g. state=California in an address form.
// TestParseForms_SensitiveFlagAllVariants pins the list in both directions.
func isSensitiveName(name string) bool {
	n := strings.ToLower(name)
	if n == "_token" {
		return true
	}
	for _, s := range sensitiveSubstrings {
		if strings.Contains(n, s) {
			return true
		}
	}
	return false
}

// isSkippableType matches crawl.isSkippableInputType exactly.
func isSkippableType(inputType string) bool {
	switch inputType {
	case "submit", "button", "image", "file", "reset":
		return true
	}
	return false
}

// fieldValue falls back to placeholder. Sensitive (see isSensitiveName) and
// hidden fields always return "": both routinely carry secrets, and spec
// generation needs only the NAME.
func fieldValue(f staticFormField) string {
	if f.Sensitive || f.Hidden {
		return ""
	}
	if f.Value != "" {
		return f.Value
	}
	return f.Placeholder
}

// fieldsToValues uses Add, not Set: duplicate names are legitimate — multi-select
// checkboxes, tags[]-style arrays, repeated hidden fields.
func fieldsToValues(fields []staticFormField) url.Values {
	values := url.Values{}
	for _, fld := range fields {
		values.Add(fld.Name, fieldValue(fld))
	}
	return values
}

func getAttr(t html.Token, key string) string {
	for _, a := range t.Attr {
		if a.Key == key {
			if len(a.Val) > maxAttrValueBytes {
				return a.Val[:maxAttrValueBytes]
			}
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
