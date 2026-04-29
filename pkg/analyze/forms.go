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

const (
	maxFormsPerBody    = 1000
	maxFieldsPerForm   = 500
	maxAttrValueBytes  = 4096
	maxFieldValueBytes = 4096    // cap textarea text content and <option> text
	maxBodyBytes       = 8 << 20 // 8 MiB cap on HTML response bodies passed to parseForms
)

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
	Sensitive   bool // heuristic match on Name (CSRF, session, token, API key, etc.)
}

// sentinelSelectedOption marks a select field whose <option selected> was
// observed before its value was resolved. The NUL prefix ensures the marker
// cannot collide with any real form value parsed from HTML.
const sentinelSelectedOption = "\x00selected"

// ExtractForms scans each request's HTML response body for <form> elements
// and returns one synthetic ObservedRequest per form. Non-HTML responses and
// responses with empty bodies are skipped. Response bodies larger than
// maxBodyBytes (8 MiB) are truncated before parsing to bound memory usage.
// The returned slice can be appended directly to the captured requests slice
// before classification.
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
		strings.Contains(head, "<html")
}

// pendingFieldState tracks state for elements whose value spans multiple tokens
// (textarea text content and select option values).
type pendingFieldState struct {
	field       *staticFormField // pointer into the parent form's Fields slice
	inTextarea  bool
	inSelect    bool
	inOption    bool
	optionValue string  // value attr of current <option> (may be empty → use text)
	optionText  string  // accumulated text content of current <option>
	firstOption *string // non-nil once the first option's value is determined
}

// parseForms tokenizes body and returns every <form> element found, including
// leftovers left open at EOF and recoverable nested forms.
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
			// Cap: once we have reached the maximum number of forms, skip new
			// <form> start tags but continue tokenizing so unclosed forms on the
			// stack are still flushed at EOF.
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

// flushUnclosedForms appends all forms remaining on the stack (innermost-first)
// to results and returns the final slice. Any in-flight select is resolved first.
func flushUnclosedForms(stack []*staticForm, results []staticForm, pending *pendingFieldState) []staticForm {
	if pending != nil && pending.inSelect {
		resolveSelectValue(pending)
	}
	for i := len(stack) - 1; i >= 0; i-- {
		results = append(results, *stack[i])
	}
	return results
}

// handlePendingStartTag handles a start tag token while inside a textarea or
// select element. Only <option> tags inside a select are relevant.
func handlePendingStartTag(tok html.Token, pending *pendingFieldState) {
	if !pending.inSelect || tok.DataAtom != atom.Option {
		return
	}
	pending.inOption = true
	pending.optionValue = getAttr(tok, "value")
	pending.optionText = ""
	if hasAttr(tok, "selected") && pending.field.Value == "" {
		// Sentinel marks that a selected option was found; resolved at </option>.
		pending.field.Value = sentinelSelectedOption
	}
}

// handlePendingText accumulates text tokens while inside a textarea or select.
// Accumulation is capped at maxFieldValueBytes to prevent attacker-controlled
// HTML (imported captures, stored content on target) from growing synthesized
// request bodies without bound.
func handlePendingText(text string, pending *pendingFieldState) {
	switch {
	case pending.inTextarea:
		pending.field.Value = appendCapped(pending.field.Value, text, maxFieldValueBytes)
	case pending.inSelect && pending.inOption:
		pending.optionText = appendCapped(pending.optionText, text, maxFieldValueBytes)
	}
}

// appendCapped returns prefix+suffix truncated to limit bytes. It avoids
// materializing the combined string when the prefix is already at or above limit.
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

// handlePendingEndTag processes an end tag while pending is active. It updates
// or clears the pending pointer via the pointer-to-pointer parameter.
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

// commitOption finalizes the current <option> inside a select: resolves the
// selected-sentinel if present and tracks the first-option fallback.
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

// resolveSelectValue finalizes the Value on a pending select field. It uses the
// selected option's value if one was found, otherwise falls back to the first
// option's value.
func resolveSelectValue(p *pendingFieldState) {
	if p.field.Value == sentinelSelectedOption {
		p.field.Value = ""
	}
	if p.field.Value == "" && p.firstOption != nil {
		p.field.Value = *p.firstOption
	}
}

// handleStartTag processes a start/self-closing tag token and updates the
// form stack. pending is set when a textarea or select element is opened so
// that subsequent text tokens and option tags can be routed to the right field.
// Returns the updated stack.
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

// currentFormForField runs the common entry guards every handle*Tag function
// needs: returns the current (innermost) form pointer along with the field
// name if the field should be appended. Returns ok=false when the tag should
// be ignored (no current form, cross-form association via form-attr, missing
// name, control bytes in name, or per-form field cap reached).
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

// handleInputTag appends a field to the current form when the <input> is valid
// (has a name, is within a form, is not cross-associated, is not a
// skippable type such as submit/button/image/file/reset, and the name contains
// no control bytes).
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
	if typ == "hidden" {
		value = ""
	}
	f.Fields = append(f.Fields, staticFormField{
		Name:        name,
		Type:        typ,
		Value:       value,
		Placeholder: getAttr(tok, "placeholder"),
		Required:    hasAttr(tok, "required"),
		Hidden:      typ == "hidden",
		Sensitive:   isSensitiveName(name),
	})
}

// handleTextareaTag appends a textarea field to the current form and sets
// pending so that subsequent text tokens accumulate into its Value until
// the matching </textarea>.
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
	// Record a pointer to the newly appended field so text tokens can
	// accumulate into its Value until </textarea>.
	fieldPtr := &f.Fields[len(f.Fields)-1]
	*pending = &pendingFieldState{
		field:      fieldPtr,
		inTextarea: true,
	}
}

// handleSelectTag appends a select field to the current form and sets pending
// so that <option> tokens can be examined until the matching </select>.
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
	// Record a pointer to the newly appended field so option tokens can
	// be examined until </select>.
	fieldPtr := &f.Fields[len(f.Fields)-1]
	*pending = &pendingFieldState{
		field:    fieldPtr,
		inSelect: true,
	}
}

// synthesizeRequest converts a parsed form into an ObservedRequest. It
// resolves the action against baseURL and populates Method/URL/Headers/Body/
// QueryParams/Source/PageURL. Returns (_, false) if the action cannot be
// resolved to an http(s) URL.
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
// unparseable URLs return ("", "", false). Off-host actions (different hostname
// or port from base) are rejected to keep synthesized requests within the
// parent request's scope.
//
// Returns the resolved action URL and a sanitized copy of the base URL (userinfo
// stripped, fragment stripped). Both are safe to persist into capture.json.
func resolveAction(base, ref string) (string, string, bool) {
	ref = strings.TrimSpace(ref)
	baseU, err := url.Parse(base)
	if err != nil || (baseU.Scheme != "http" && baseU.Scheme != "https") {
		return "", "", false
	}
	// Strip userinfo and fragment from base URL to prevent credentials from being
	// persisted into capture.json.
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
	// Strip userinfo from the resolved URL to prevent credentials from being
	// persisted into capture.json or sent in synthetic requests.
	resolved.User = nil
	resolved.Fragment = ""
	return resolved.String(), sanitizedBase, true
}

// isUnsupportedSchemeRef reports whether ref begins with a scheme that cannot
// produce a valid HTTP(S) action URL (javascript:, mailto:, data:, tel:, blob:).
func isUnsupportedSchemeRef(ref string) bool {
	lower := strings.ToLower(ref)
	return strings.HasPrefix(lower, "javascript:") ||
		strings.HasPrefix(lower, "mailto:") ||
		strings.HasPrefix(lower, "data:") ||
		strings.HasPrefix(lower, "tel:") ||
		strings.HasPrefix(lower, "blob:")
}

// effectivePort returns the URL's port, expanding empty values to the scheme's
// default (80 for http, 443 for https). Required so that "https://host/" and
// "https://host:443/x" compare as the same origin in validateResolvedURL —
// url.URL.Port() returns "" when the default port is omitted, which would
// otherwise cause same-origin form actions that include the explicit default
// port to be incorrectly rejected as off-host.
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

// validateResolvedURL checks that the resolved URL is an HTTP(S) URL on the
// same scheme, hostname, and port as the base URL. Returns false if any
// constraint is violated.
func validateResolvedURL(baseU, resolved *url.URL) bool {
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return false
	}
	// Reject scheme changes: different scheme = different origin.
	if resolved.Scheme != baseU.Scheme {
		return false
	}
	// Reject off-host actions: hostname and port must both match the base URL.
	// effectivePort normalises omitted default ports so that "https://host/" and
	// "https://host:443/x" are treated as the same origin (RFC 3986 §3.2.3).
	if !strings.EqualFold(resolved.Hostname(), baseU.Hostname()) ||
		effectivePort(resolved) != effectivePort(baseU) {
		return false
	}
	return true
}

// allowedFormMethods is the set of HTTP method strings accepted by synthesizeRequest.
// Any form method not in this set is normalised to "GET".
var allowedFormMethods = map[string]struct{}{
	"GET":     {},
	"POST":    {},
	"PUT":     {},
	"PATCH":   {},
	"DELETE":  {},
	"HEAD":    {},
	"OPTIONS": {},
}

// allowedFormEnctypes is the set of MIME types accepted as form enctype values.
// Any enctype not in this set is normalised to "application/x-www-form-urlencoded".
var allowedFormEnctypes = map[string]struct{}{
	"application/x-www-form-urlencoded": {},
	"multipart/form-data":               {},
	"text/plain":                        {},
}

// containsControlByte returns true if s contains any byte below 0x20 (space)
// or equal to 0x7f (DEL). Used to reject field names that contain CR, LF, NUL,
// or other control characters that could enable header injection or log forging.
func containsControlByte(s string) bool {
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b < 0x20 || b == 0x7f {
			return true
		}
	}
	return false
}

// isSensitiveName matches form-field names that commonly carry secrets or
// anti-CSRF tokens. Matched names have their values blanked by fieldValue so
// they are never persisted into capture.json or replayed during probing.
// Matching is a case-insensitive substring check against a known list:
//
//   - CSRF / XSRF tokens: "csrf", "xsrf", "_token", "authenticity_token"
//   - Session and auth tokens: "session" (matches "sessionid" by substring),
//     "access_token", "refresh_token", "bearer", "jwt", "oauth"
//   - API keys: "apikey", "api_key", "api-key"
//   - SAML markers: "samlrequest", "samlresponse", "relaystate"
//
// "nonce" and "state" are intentionally excluded from the substring list
// because they collide with common non-sensitive parameter names (e.g.,
// `state=California` in address forms).
func isSensitiveName(name string) bool {
	n := strings.ToLower(name)
	if n == "_token" {
		return true
	}
	sensitiveSubstrings := []string{
		"csrf", "xsrf", "authenticity_token",
		"session", "access_token", "refresh_token",
		"bearer", "jwt", "oauth",
		"apikey", "api_key", "api-key",
		"samlrequest", "samlresponse", "relaystate",
	}
	for _, s := range sensitiveSubstrings {
		if strings.Contains(n, s) {
			return true
		}
	}
	return false
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
// Sensitive fields (CSRF tokens, session IDs, API keys, JWTs, OAuth tokens,
// SAML state — see isSensitiveName) always return "" regardless of
// Value/Placeholder to prevent secrets from being persisted into capture.json
// or replayed during probing.
// Hidden fields also always return "" because hidden inputs commonly bear
// secrets that must not be persisted or replayed; the field NAME alone is what
// spec generation needs.
func fieldValue(f staticFormField) string {
	if f.Sensitive || f.Hidden {
		return ""
	}
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
