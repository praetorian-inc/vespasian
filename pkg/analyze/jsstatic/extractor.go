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
	"sort"
	"strings"

	"github.com/BishopFox/jsluice"
)

// assetExtensions are file-like URL suffixes that indicate non-API resources.
var assetExtensions = []string{
	".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tiff",
	".css", ".svg", ".woff", ".woff2", ".ttf", ".eot",
	".map", ".js", ".ico", ".pdf", ".zip",
}

// filteredSchemes are URL schemes that are never API calls.
var filteredSchemes = []string{
	"javascript:", "data:", "blob:", "mailto:", "tel:", "chrome-extension:",
}

// filterURL returns true if the URL should be dropped.
func filterURL(rawURL string) bool {
	if rawURL == "" {
		return true
	}

	lower := strings.ToLower(rawURL)

	// Drop non-API schemes.
	for _, scheme := range filteredSchemes {
		if strings.HasPrefix(lower, scheme) {
			return true
		}
	}

	// Drop asset file extensions by checking path portion.
	// Strip query/fragment for extension check.
	pathPart := rawURL
	if idx := strings.IndexAny(pathPart, "?#"); idx != -1 {
		pathPart = pathPart[:idx]
	}
	lowerPath := strings.ToLower(pathPart)
	for _, ext := range assetExtensions {
		if strings.HasSuffix(lowerPath, ext) {
			return true
		}
	}

	return false
}

// isExprOnly returns true if the URL consists only of EXPR placeholders and
// path separators — these are fully dynamic and carry no structural info.
func isExprOnly(rawURL string) bool {
	// Strip query/fragment.
	u := rawURL
	if idx := strings.IndexAny(u, "?#"); idx != -1 {
		u = u[:idx]
	}
	// Strip scheme+authority for absolute URLs.
	if i := strings.Index(u, "://"); i != -1 {
		rest := u[i+3:]
		if slash := strings.Index(rest, "/"); slash != -1 {
			u = rest[slash:]
		} else {
			return false
		}
	}
	// Remove path separators and EXPR — if nothing remains, it's EXPR-only.
	cleaned := strings.ReplaceAll(u, "/", "")
	cleaned = strings.ReplaceAll(cleaned, jsluice.ExpressionPlaceholder, "")
	return cleaned == ""
}

// collapseTemplateLiteral parses a tree-sitter template_string node and
// returns the collapsed URL string with EXPR placeholders and the list of
// identifier tokens collected from the substitutions.
func collapseTemplateLiteral(n *jsluice.Node) (string, []string) {
	raw := n.Content()
	if len(raw) < 2 || raw[0] != '`' {
		return "", nil
	}
	inner := raw[1 : len(raw)-1] // strip backticks

	// Collect tokens from substitution child nodes.
	var tokens []string
	for i := 0; i < n.ChildCount(); i++ {
		child := n.Child(i)
		if child.Type() != "template_substitution" {
			continue
		}
		for j := 0; j < child.ChildCount(); j++ {
			sub := child.Child(j)
			switch sub.Type() {
			case "identifier":
				tokens = append(tokens, sub.Content())
			case "member_expression":
				prop := sub.ChildByFieldName("property")
				if prop != nil {
					tokens = append(tokens, prop.Content())
				}
			}
		}
	}

	// Replace ${...} patterns with EXPR placeholder.
	var result strings.Builder
	i := 0
	for i < len(inner) {
		if i+2 <= len(inner) && inner[i] == '$' && inner[i+1] == '{' {
			j := i + 2
			for j < len(inner) && inner[j] != '}' {
				j++
			}
			result.WriteString(jsluice.ExpressionPlaceholder)
			i = j + 1
		} else {
			result.WriteByte(inner[i])
			i++
		}
	}
	return result.String(), tokens
}

// extractMethodFromOptions extracts the HTTP method string from an options
// object argument like {method: "POST"}.
func extractMethodFromOptions(optNode *jsluice.Node) string {
	if optNode == nil || optNode.Type() != "object" {
		return ""
	}
	obj := optNode.AsObject()
	methodNode := obj.GetNode("method")
	if methodNode == nil || !methodNode.IsValid() {
		return ""
	}
	// Strip surrounding quotes.
	val := strings.Trim(methodNode.Content(), "\"'`")
	return strings.ToUpper(strings.TrimSpace(val))
}

// fetchHTTPMethods is the set of valid HTTP methods we recognize.
var fetchHTTPMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "PATCH": true,
	"DELETE": true, "HEAD": true, "OPTIONS": true,
}

// extractTemplateLiteralFetches walks the AST for fetch(...) calls whose
// first argument is a template_string and returns extracted endpoints.
// recoverTokens controls whether identifier tokens are recovered from
// template substitutions (false in Task 3, true after Task 4).
func extractTemplateLiteralFetches(analyzer *jsluice.Analyzer, baseURL string, recoverTokens bool) []ExtractedEndpoint {
	var endpoints []ExtractedEndpoint

	// Walk call_expressions directly.
	analyzer.Query("(call_expression) @call", func(n *jsluice.Node) {
		fn := n.ChildByFieldName("function")
		if fn == nil || fn.Content() != "fetch" {
			return
		}
		args := n.ChildByFieldName("arguments")
		if args == nil {
			return
		}

		urlArg := args.NamedChild(0)
		if urlArg == nil || urlArg.Type() != "template_string" {
			return
		}

		rawURL, tokens := collapseTemplateLiteral(urlArg)
		if rawURL == "" || filterURL(rawURL) || isExprOnly(rawURL) {
			return
		}

		var useTokens []string
		if recoverTokens {
			useTokens = tokens
		}

		normalized, err := NormalizeEXPRPath(rawURL, useTokens)
		if err != nil {
			normalized = rawURL
		}

		// Extract method from second argument options object.
		method := "GET"
		optArg := args.NamedChild(1)
		if optArg != nil {
			if m := extractMethodFromOptions(optArg); m != "" && fetchHTTPMethods[m] {
				method = m
			}
		}

		endpoints = append(endpoints, ExtractedEndpoint{
			Method:       method,
			URL:          normalized,
			SourceTag:    SourceJS,
			OriginBundle: baseURL,
		})
	})

	return endpoints
}

// axiosMethods maps axios.<method> names to HTTP methods.
var axiosMethods = map[string]string{
	"get":     "GET",
	"post":    "POST",
	"put":     "PUT",
	"patch":   "PATCH",
	"delete":  "DELETE",
	"request": "", // method comes from config, handled separately
	"head":    "HEAD",
}

// collectObjectKeys returns the top-level keys of a tree-sitter object node,
// sorted lexicographically. Handles both pair nodes and shorthand_property_identifier.
func collectObjectKeys(objNode *jsluice.Node) []string {
	if objNode == nil || !objNode.IsValid() || objNode.Type() != "object" {
		return nil
	}
	var keys []string
	for i := 0; i < objNode.ChildCount(); i++ {
		child := objNode.Child(i)
		switch child.Type() {
		case "pair":
			keyNode := child.ChildByFieldName("key")
			if keyNode != nil && keyNode.IsValid() {
				keys = append(keys, keyNode.Content())
			}
		case "shorthand_property_identifier":
			keys = append(keys, child.Content())
		}
	}
	sort.Strings(keys)
	return keys
}

// extractJSONStringifyKeys returns the top-level keys from a JSON.stringify(obj) call.
// Returns nil if the node isn't JSON.stringify or the argument isn't an object literal.
func extractJSONStringifyKeys(n *jsluice.Node) []string {
	if n == nil || !n.IsValid() || n.Type() != "call_expression" {
		return nil
	}
	fn := n.ChildByFieldName("function")
	if fn == nil || fn.Content() != "JSON.stringify" {
		return nil
	}
	args := n.ChildByFieldName("arguments")
	if args == nil {
		return nil
	}
	obj := args.NamedChild(0)
	if obj == nil || obj.Type() != "object" {
		return nil
	}
	return collectObjectKeys(obj)
}

// extractStringLiteral returns the unquoted content of a string node.
func extractStringLiteral(n *jsluice.Node) string {
	if n == nil || !n.IsValid() {
		return ""
	}
	if n.Type() != "string" {
		return ""
	}
	return strings.Trim(n.Content(), "\"'`")
}

// extractAxiosCalls walks the AST and extracts endpoints from axios.method() and
// axios({config}) call forms.
func extractAxiosCalls(analyzer *jsluice.Analyzer, baseURL string) []ExtractedEndpoint {
	var endpoints []ExtractedEndpoint

	analyzer.Query("(call_expression) @call", func(n *jsluice.Node) {
		fn := n.ChildByFieldName("function")
		if fn == nil || !fn.IsValid() {
			return
		}
		args := n.ChildByFieldName("arguments")
		if args == nil {
			return
		}

		switch fn.Type() {
		case "member_expression":
			if ep, ok := extractAxiosMemberCall(fn, args, baseURL); ok {
				endpoints = append(endpoints, ep)
			}
		case "identifier":
			if ep, ok := extractAxiosConfigCall(fn, args, baseURL); ok {
				endpoints = append(endpoints, ep)
			}
		}
	})

	return endpoints
}

// extractAxiosMemberCall handles `axios.<method>(url, [data], [config])` form.
func extractAxiosMemberCall(fn, args *jsluice.Node, baseURL string) (ExtractedEndpoint, bool) {
	obj := fn.ChildByFieldName("object")
	prop := fn.ChildByFieldName("property")
	if obj == nil || prop == nil || obj.Content() != "axios" {
		return ExtractedEndpoint{}, false
	}
	methodName := strings.ToLower(prop.Content())
	httpMethod, ok := axiosMethods[methodName]
	if !ok {
		return ExtractedEndpoint{}, false
	}
	if httpMethod == "" {
		// axios.request(config) — pick up method from config.
		httpMethod = methodFromFirstObjectArg(args)
	}

	urlArg := args.NamedChild(0)
	if urlArg == nil {
		return ExtractedEndpoint{}, false
	}
	normalized, ok := normalizedURLFromLiteral(urlArg)
	if !ok {
		return ExtractedEndpoint{}, false
	}

	// Collect body fields from second argument (data object) for body methods.
	var bodyFields []string
	if axiosMethodHasBody(methodName) {
		if dataArg := args.NamedChild(1); dataArg != nil && dataArg.Type() == "object" {
			bodyFields = collectObjectKeys(dataArg)
		}
	}

	return ExtractedEndpoint{
		Method:       httpMethod,
		URL:          normalized,
		BodyFields:   bodyFields,
		SourceTag:    SourceJS,
		OriginBundle: baseURL,
	}, true
}

// extractAxiosConfigCall handles `axios({url, method, data, ...})` form.
func extractAxiosConfigCall(fn, args *jsluice.Node, baseURL string) (ExtractedEndpoint, bool) {
	if fn.Content() != "axios" {
		return ExtractedEndpoint{}, false
	}
	configArg := args.NamedChild(0)
	if configArg == nil || configArg.Type() != "object" {
		return ExtractedEndpoint{}, false
	}
	obj := configArg.AsObject()

	urlNode := obj.GetNode("url")
	if urlNode == nil || !urlNode.IsValid() {
		return ExtractedEndpoint{}, false
	}
	normalized, ok := normalizedURLFromLiteral(urlNode)
	if !ok {
		return ExtractedEndpoint{}, false
	}

	httpMethod := "GET"
	if m := extractMethodFromOptions(configArg); m != "" && fetchHTTPMethods[m] {
		httpMethod = m
	}

	var bodyFields []string
	if dataNode := obj.GetNode("data"); dataNode != nil && dataNode.IsValid() && dataNode.Type() == "object" {
		bodyFields = collectObjectKeys(dataNode)
	}

	return ExtractedEndpoint{
		Method:       httpMethod,
		URL:          normalized,
		BodyFields:   bodyFields,
		SourceTag:    SourceJS,
		OriginBundle: baseURL,
	}, true
}

// normalizedURLFromLiteral pulls a string literal out of a node, applies
// scheme/asset and EXPR-only filtering, and runs EXPR normalisation. Returns
// ok=false when the node is not a usable URL literal.
func normalizedURLFromLiteral(n *jsluice.Node) (string, bool) {
	rawURL := extractStringLiteral(n)
	if rawURL == "" || filterURL(rawURL) || isExprOnly(rawURL) {
		return "", false
	}
	normalized, err := NormalizeEXPRPath(rawURL, nil)
	if err != nil || normalized == "" {
		normalized = rawURL
	}
	return normalized, true
}

// methodFromFirstObjectArg reads the HTTP method from the first config-object
// argument of an axios.request(config) call. Falls back to "GET".
func methodFromFirstObjectArg(args *jsluice.Node) string {
	configArg := args.NamedChild(0)
	if configArg == nil || configArg.Type() != "object" {
		return "GET"
	}
	if m := extractMethodFromOptions(configArg); m != "" {
		return m
	}
	return "GET"
}

// axiosMethodHasBody reports whether the named axios method may carry a body.
func axiosMethodHasBody(methodName string) bool {
	switch methodName {
	case "post", "put", "patch", "delete":
		return true
	}
	return false
}

// augmentFetchBodyFields walks the AST for fetch(url, {body: JSON.stringify({...})}) calls
// and returns a map from (method, url) -> bodyFields for later merging.
func augmentFetchBodyFields(analyzer *jsluice.Analyzer) map[endpointKey][]string {
	result := make(map[endpointKey][]string)

	analyzer.Query("(call_expression) @call", func(n *jsluice.Node) {
		fn := n.ChildByFieldName("function")
		if fn == nil || fn.Content() != "fetch" {
			return
		}
		args := n.ChildByFieldName("arguments")
		if args == nil {
			return
		}

		// URL is first arg.
		urlArg := args.NamedChild(0)
		if urlArg == nil {
			return
		}
		rawURL := extractStringLiteral(urlArg)
		if rawURL == "" {
			return
		}
		// NormalizeEXPRPath only errors on malformed URLs; the assert at the
		// start of axios extraction has already validated rawURL. Treat any
		// error as "leave the URL untouched."
		normalized, normErr := NormalizeEXPRPath(rawURL, nil)
		if normErr != nil || normalized == "" {
			normalized = rawURL
		}

		// Options object is second arg.
		optArg := args.NamedChild(1)
		if optArg == nil || optArg.Type() != "object" {
			return
		}

		// Find body key.
		obj := optArg.AsObject()
		bodyNode := obj.GetNode("body")
		if bodyNode == nil || !bodyNode.IsValid() {
			return
		}

		fields := extractJSONStringifyKeys(bodyNode)
		if len(fields) == 0 {
			return
		}

		method := "POST" // fetch with body defaults to POST
		if m := extractMethodFromOptions(optArg); m != "" && fetchHTTPMethods[m] {
			method = m
		}

		key := endpointKey{method, normalized}
		result[key] = fields
	})

	return result
}

// endpointKey is a dedup key for ExtractedEndpoints.
type endpointKey struct {
	method string
	url    string
}

// ExtractFromBundle wraps jsluice.NewAnalyzer(b).GetURLs() and applies
// URL filtering, EXPR normalization, and body-field collection.
// baseURL is the URL the bundle was served from.
func ExtractFromBundle(jsSource []byte, baseURL string, opts Options) ([]ExtractedEndpoint, error) {
	if len(jsSource) == 0 {
		return nil, nil
	}

	// opts is accepted for future use (e.g., filtering thresholds); unused today.
	_ = opts

	analyzer := jsluice.NewAnalyzer(jsSource)

	var endpoints []ExtractedEndpoint
	seen := make(map[endpointKey]bool)

	// 1. Collect high-fidelity axios endpoints first (proper method + body fields).
	//    These take priority over jsluice's lower-fidelity axios matches.
	for _, ep := range extractAxiosCalls(analyzer, baseURL) {
		k := endpointKey{ep.Method, ep.URL}
		if seen[k] {
			continue
		}
		seen[k] = true
		endpoints = append(endpoints, ep)
	}

	// 2. Collect body-field augmentation map for fetch calls.
	fetchBodyFields := augmentFetchBodyFields(analyzer)

	// 3. Add endpoints from template-literal fetch calls (not found by jsluice).
	for _, ep := range extractTemplateLiteralFetches(analyzer, baseURL, true) {
		k := endpointKey{ep.Method, ep.URL}
		if seen[k] {
			continue
		}
		seen[k] = true
		if fields, ok := fetchBodyFields[k]; ok {
			ep.BodyFields = fields
		}
		endpoints = append(endpoints, ep)
	}

	// 4. Collect endpoints from jsluice's built-in URL matchers.
	for _, u := range analyzer.GetURLs() {
		ep, ok := jsluiceURLToEndpoint(u, baseURL, fetchBodyFields, seen)
		if !ok {
			continue
		}
		endpoints = append(endpoints, ep)
	}

	if len(endpoints) == 0 {
		return nil, nil
	}
	return endpoints, nil
}

// jsluiceURLToEndpoint converts a single jsluice.URL into an ExtractedEndpoint,
// applying scheme/asset filtering, EXPR normalisation, and dedup against the
// seen map. Returns ok=false to indicate the URL should be dropped (already
// captured by a higher-fidelity walker above, filtered, or duplicate).
func jsluiceURLToEndpoint(
	u *jsluice.URL,
	baseURL string,
	fetchBodyFields map[endpointKey][]string,
	seen map[endpointKey]bool,
) (ExtractedEndpoint, bool) {
	// Skip jsluice's axios matches — our extractAxiosCalls handles these with
	// higher fidelity. Skip stringLiteral matches — they are low-fidelity
	// duplicates of typed matcher hits, and they also surface bare strings
	// inside non-API calls like axios.unknown("/x"), producing false positives.
	if strings.HasPrefix(u.Type, "axios.") || u.Type == "stringLiteral" {
		return ExtractedEndpoint{}, false
	}

	raw := strings.TrimSpace(u.URL)
	if raw == "" || filterURL(raw) || isExprOnly(raw) {
		return ExtractedEndpoint{}, false
	}

	// Identifier-token recovery for jsluice's built-in URL matches isn't
	// implemented (only the template-literal walker in extractTemplateLiteralFetches
	// has the AST context to do it). Pass nil; NormalizeEXPRPath falls back to
	// {param}, {param1}, ... numbering.
	normalized, err := NormalizeEXPRPath(raw, nil)
	if err != nil || normalized == "" {
		normalized = raw
	}

	method := strings.ToUpper(u.Method)
	if method == "" {
		method = "GET"
	}

	k := endpointKey{method, normalized}
	if seen[k] {
		return ExtractedEndpoint{}, false
	}
	seen[k] = true

	ep := ExtractedEndpoint{
		Method:       method,
		URL:          normalized,
		ContentType:  u.ContentType,
		SourceTag:    SourceJS,
		OriginBundle: baseURL,
	}
	if fields, ok := fetchBodyFields[k]; ok {
		ep.BodyFields = fields
	}
	return ep, true
}
