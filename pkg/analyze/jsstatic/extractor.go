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
	"net/url"
	"sort"
	"strings"

	"github.com/BishopFox/jsluice"

	"github.com/praetorian-inc/vespasian/pkg/crawl"
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

	tokens := collectTemplateTokens(n)
	collapsed := replaceTemplateSubs(inner)
	return collapsed, tokens
}

// collectTemplateTokens walks template_substitution children and returns
// recovered identifier names (including the .property of member_expression
// substitutions).
func collectTemplateTokens(n *jsluice.Node) []string {
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
				if prop := sub.ChildByFieldName("property"); prop != nil {
					tokens = append(tokens, prop.Content())
				}
			}
		}
	}
	return tokens
}

// replaceTemplateSubs replaces every ${...} substitution in inner with the
// jsluice EXPR placeholder. Brace-depth counting handles nested braces like
// ${fn({a:1})} — a naive first-`}` scan would corrupt the URL.
func replaceTemplateSubs(inner string) string {
	var result strings.Builder
	for i := 0; i < len(inner); {
		if i+2 <= len(inner) && inner[i] == '$' && inner[i+1] == '{' {
			j := skipBalancedBraces(inner, i+2)
			result.WriteString(jsluice.ExpressionPlaceholder)
			i = j
			continue
		}
		result.WriteByte(inner[i])
		i++
	}
	return result.String()
}

// skipBalancedBraces returns the index just past the matching '}' starting
// from start (which points at the byte AFTER the opening '${').
func skipBalancedBraces(s string, start int) int {
	depth := 1
	for j := start; j < len(s); j++ {
		switch s[j] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return j + 1
			}
		}
	}
	return len(s)
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
// first argument is a template_string and returns extracted endpoints with
// identifier tokens recovered from template substitutions (e.g., ${userId}
// → token "userId" used to name the path parameter).
func extractTemplateLiteralFetches(analyzer *jsluice.Analyzer, baseURL string) []ExtractedEndpoint {
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

		normalized := NormalizeEXPRPath(rawURL, tokens)

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
//
// Special cases handled outside the axiosMethodHasBody data-arg path:
//   - "request": httpMethod=="", so extractAxiosMemberCall delegates to
//     endpointFromAxiosConfigObject — URL, method, and body all come from
//     the first positional config object.
//   - "delete": in axios v1.x, axios.delete(url, config) — the second
//     positional arg is a CONFIG object (keys like headers/params/data), NOT
//     a body. Body lives in config.data. Handled by a dedicated branch in
//     extractAxiosMemberCall so config keys are never misreported as body fields.
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
				k := keyNode.Content()
				// String-literal keys (type "string") have surrounding quotes;
				// strip leading/trailing " ' ` so the body field names are bare.
				if keyNode.Type() == "string" {
					k = strings.Trim(k, "\"'`")
				}
				keys = append(keys, k)
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
		// axios.request(config) — URL, method, and body all come from the
		// config object (the first positional arg), not from positional URL
		// args. Delegate to the shared config-object parser.
		return endpointFromAxiosConfigObject(args.NamedChild(0), baseURL)
	}

	urlArg := args.NamedChild(0)
	if urlArg == nil {
		return ExtractedEndpoint{}, false
	}
	normalized, ok := normalizedURLFromLiteral(urlArg)
	if !ok {
		return ExtractedEndpoint{}, false
	}

	// Collect body fields.
	//   - post/put/patch: second arg IS the body object; collect its keys directly.
	//   - delete: second arg is a CONFIG object (headers/params/data/…); body lives
	//     in config.data only. Collecting the config object's own keys would
	//     misreport "headers", "params", etc. as body field names.
	var bodyFields []string
	if axiosMethodHasBody(methodName) {
		if dataArg := args.NamedChild(1); dataArg != nil && dataArg.Type() == "object" {
			bodyFields = collectObjectKeys(dataArg)
		}
	} else if methodName == "delete" {
		bodyFields = axiosDeleteBodyFields(args)
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
	return endpointFromAxiosConfigObject(args.NamedChild(0), baseURL)
}

// endpointFromAxiosConfigObject builds an endpoint from an axios config object
// literal ({url, method, data, ...}). Shared by the axios({config}) identifier
// form and the axios.request({config}) member form.
func endpointFromAxiosConfigObject(configArg *jsluice.Node, baseURL string) (ExtractedEndpoint, bool) {
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

// normalizedURLFromLiteral pulls a URL out of a node (string or template_string),
// applies scheme/asset and EXPR-only filtering, and runs EXPR normalisation.
// Returns ok=false when the node is not a usable URL literal.
func normalizedURLFromLiteral(n *jsluice.Node) (string, bool) {
	var rawURL string
	var tokens []string
	if n != nil && n.Type() == "template_string" {
		rawURL, tokens = collapseTemplateLiteral(n)
	} else {
		rawURL = extractStringLiteral(n)
	}
	if rawURL == "" || filterURL(rawURL) || isExprOnly(rawURL) {
		return "", false
	}
	normalized := NormalizeEXPRPath(rawURL, tokens)
	if normalized == "" {
		normalized = rawURL
	}
	return normalized, true
}

// axiosMethodHasBody reports whether the named axios method passes the body as
// the second positional argument (the data-arg pattern). True for post/put/patch
// only. delete is excluded because axios.delete(url, config) takes a CONFIG
// object as its second arg, not a body — body lives in config.data and is
// handled by a separate branch in extractAxiosMemberCall.
func axiosMethodHasBody(methodName string) bool {
	switch methodName {
	case "post", "put", "patch":
		return true
	}
	return false
}

// axiosDeleteBodyFields extracts body field names from the axios.delete(url, config)
// call's config argument. In axios v1.x the second positional arg is a CONFIG
// object whose own keys (headers, params, …) must NOT become body fields; the
// actual body lives in config.data. Returns nil when no data key is present.
func axiosDeleteBodyFields(args *jsluice.Node) []string {
	configArg := args.NamedChild(1)
	if configArg == nil || configArg.Type() != "object" {
		return nil
	}
	dataNode := configArg.AsObject().GetNode("data")
	if dataNode == nil || !dataNode.IsValid() || dataNode.Type() != "object" {
		return nil
	}
	return collectObjectKeys(dataNode)
}

// augmentFetchBodyFields walks the AST for fetch(url, {body: JSON.stringify({...})}) calls
// and returns a map from (method, url) -> bodyFields for later merging.
func augmentFetchBodyFields(analyzer *jsluice.Analyzer) map[endpointKey][]string {
	result := make(map[endpointKey][]string)

	analyzer.Query("(call_expression) @call", func(n *jsluice.Node) {
		if k, fields, ok := fetchBodyFromCall(n); ok {
			result[k] = fields
		}
	})

	return result
}

// fetchBodyFromCall extracts the (key, body fields) pair for a fetch() call
// node. It returns the (method, normalized-URL) key and the top-level keys
// of the JSON.stringify({...}) body object. Returns ok=false if the node is
// not a fetch() call, has no options object, or has no JSON.stringify body.
func fetchBodyFromCall(n *jsluice.Node) (endpointKey, []string, bool) {
	var k endpointKey
	fn := n.ChildByFieldName("function")
	if fn == nil || fn.Content() != "fetch" {
		return k, nil, false
	}
	args := n.ChildByFieldName("arguments")
	if args == nil {
		return k, nil, false
	}

	urlArg := args.NamedChild(0)
	if urlArg == nil {
		return k, nil, false
	}
	rawURL, tokens := urlFromArg(urlArg)
	if rawURL == "" {
		return k, nil, false
	}
	normalized := NormalizeEXPRPath(rawURL, tokens)
	if normalized == "" {
		normalized = rawURL
	}

	optArg := args.NamedChild(1)
	if optArg == nil || optArg.Type() != "object" {
		return k, nil, false
	}
	obj := optArg.AsObject()
	bodyNode := obj.GetNode("body")
	if bodyNode == nil || !bodyNode.IsValid() {
		return k, nil, false
	}
	fields := extractJSONStringifyKeys(bodyNode)
	if len(fields) == 0 {
		return k, nil, false
	}

	method := "POST" // fetch with body defaults to POST
	if m := extractMethodFromOptions(optArg); m != "" && fetchHTTPMethods[m] {
		method = m
	}

	k = endpointKey{method, normalized}
	return k, fields, true
}

// urlFromArg extracts (rawURL, tokens) from either a string literal or a
// template_string node. Returns ("", nil) for any other node type.
func urlFromArg(n *jsluice.Node) (string, []string) {
	if n.Type() == "template_string" {
		return collapseTemplateLiteral(n)
	}
	return extractStringLiteral(n), nil
}

// endpointKey is a dedup key for ExtractedEndpoints.
type endpointKey struct {
	method string
	url    string
}

// ExtractFromBundle wraps jsluice.NewAnalyzer(b).GetURLs() and applies
// URL filtering, EXPR normalization, and body-field collection.
// baseURL is the URL the bundle was served from.
func ExtractFromBundle(jsSource []byte, baseURL string) ([]ExtractedEndpoint, error) {
	if len(jsSource) == 0 {
		return nil, nil
	}

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
	for _, ep := range extractTemplateLiteralFetches(analyzer, baseURL) {
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
	//
	// jsluice emits a redundant method-less "fetch" match alongside every
	// method-bearing "fetch" match for the same URL. Keeping the method-less
	// duplicate defaults it to GET and synthesizes a phantom GET endpoint for
	// any non-GET fetch (e.g. fetch(u,{method:"POST"}) would yield BOTH POST
	// and a GET that never occurs). Pre-scan the method-bearing fetch URLs so
	// jsluiceURLToEndpoint can drop the redundant companion.
	jsluiceURLs := analyzer.GetURLs()
	fetchURLsWithMethod := make(map[string]bool)
	for _, u := range jsluiceURLs {
		if u.Type == "fetch" && u.Method != "" {
			fetchURLsWithMethod[strings.TrimSpace(u.URL)] = true
		}
	}
	astURLs := make(map[string]bool)
	for _, u := range jsluiceURLs {
		ep, ok := jsluiceURLToEndpoint(u, baseURL, fetchBodyFields, seen, fetchURLsWithMethod)
		if !ok {
			continue
		}
		endpoints = append(endpoints, ep)
	}
	// Record every URL the AST walkers emitted, method-agnostic, so step 5 can
	// suppress phantom endpoints for URLs already recovered with a known method.
	// Keys are canonicalized (concatDedupKey) so a concat reconstruction that
	// substitutes the numeric sentinel "0" for a dynamic operand, or omits the
	// leading slash on a relative path, still matches the AST form of the same
	// endpoint ({param} placeholders, host-relative paths). The key is
	// origin-scoped (see concatDedupKey) so a cross-host AST URL that merely
	// shares a path cannot suppress a same-origin concat candidate.
	baseHost := hostOfURL(baseURL)
	for _, ep := range endpoints {
		astURLs[concatDedupKey(ep.URL, baseHost)] = true
	}

	// 5. Reconstruct concat / +-chain / service-prefix paths that jsluice's AST
	//    analysis cannot resolve (LAB-4992). Shares crawl's extractor so the
	//    fully-offline static path recovers the same forms as the active
	//    JS-replay path. Non-literal concat operands arrive as the numeric
	//    sentinel "0" (e.g. /api/users/0/orders); pkg/generate/rest turns those
	//    numeric segments into named params downstream.
	endpoints = append(endpoints, extractConcatEndpoints(jsSource, baseURL, baseHost, seen, astURLs)...)

	if len(endpoints) == 0 {
		return nil, nil
	}
	return endpoints, nil
}

// extractConcatEndpoints reconstructs concat / +-chain / service-prefix API
// paths from the raw bundle bytes via crawl.ExtractStaticConcatPaths and
// converts each surviving path into a GET ExtractedEndpoint. A bare path string
// carries no HTTP method, so these candidates default to GET.
//
// crawl returns raw reconstructions, so relative paths get a leading slash here
// before filtering (mirroring addPath in the active crawl path). Two dedup
// guards keep this additive rather than noisy:
//   - astURLs: skip any path the AST walkers already emitted for ANY method, so
//     a concat reconstruction that collides with a jsluice-recovered URL does
//     not synthesize a phantom GET companion (mirrors the method-less fetch
//     guard in jsluiceURLToEndpoint). The lookup is keyed on concatDedupKey so
//     the sentinel-"0"/{param} and relative-slash representation gaps between the
//     two extractors do not defeat the guard.
//   - seen: skip exact (GET, url) duplicates and register survivors.
func extractConcatEndpoints(jsSource []byte, baseURL, baseHost string, seen map[endpointKey]bool, astURLs map[string]bool) []ExtractedEndpoint {
	var endpoints []ExtractedEndpoint
	for _, raw := range crawl.ExtractStaticConcatPaths(jsSource) {
		p := strings.TrimSpace(raw)
		if p == "" {
			continue
		}
		// Relative reconstructions arrive without a leading slash (e.g.
		// "identity/api/auth/login"); normalize so they resolve as
		// document-root paths rather than bundle-relative ones.
		if !strings.HasPrefix(p, "http://") && !strings.HasPrefix(p, "https://") && !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		if filterURL(p) || isExprOnly(p) || astURLs[concatDedupKey(p, baseHost)] {
			continue
		}
		k := endpointKey{"GET", p}
		if seen[k] {
			continue
		}
		seen[k] = true
		endpoints = append(endpoints, ExtractedEndpoint{
			Method: "GET",
			URL:    p,
			// Distinct source: these are speculative, never-probed concat
			// reconstructions (LAB-4992 / SEC-BE-001), tagged apart from
			// AST-recovered literals so consumers can weight them.
			SourceTag:    SourceJSConcat,
			OriginBundle: baseURL,
		})
	}
	return endpoints
}

// concatDedupKey canonicalizes a URL/path into an origin-scoped key so the
// concat extractor's reconstructions compare equal to the AST walkers' output
// for the same logical endpoint — and ONLY for the same origin. The two
// extractors describe dynamic and relative paths differently: concat substitutes
// the numeric sentinel "0" for non-literal operands and always carries a leading
// slash, whereas the AST walkers emit {param}-style placeholders
// (NormalizeEXPRPath) and leave relative paths without a leading slash. Both
// collapse to one key here: query/fragment dropped, leading slash ensured, and
// every dynamic segment (the concat sentinel or a {...} placeholder) rewritten
// to a single "{}" token. Concrete literal segments other than the sentinel are
// left intact, so distinct concrete paths are NOT over-merged (e.g.
// "/api/items/5" stays distinct from "/api/items/{param}").
//
// The key is prefixed with the endpoint's origin (host): an absolute URL uses
// its own host; a relative URL (no scheme+host) is same-origin by construction
// and uses baseHost (the bundle's host). This prevents a cross-host AST URL that
// merely shares a path (e.g. "https://beacon.other.com/api/track") from
// suppressing a same-origin concat candidate ("/api/track" on the bundle host) —
// they are genuinely different endpoints and must both survive.
//
// One deliberate exception: a literal segment equal to the sentinel value
// (crawl.ConcatPathSentinel, "0") is indistinguishable offline from a dynamic
// operand the concat extractor substituted, so "/api/items/0" DOES collapse
// onto "/api/items/{param}" on the same origin. This is intentional for dedup —
// treating a lone "0" segment as dynamic errs toward suppressing a phantom
// companion, the safe direction for this guard.
//
// The sentinel is sourced from crawl.ConcatPathSentinel (not a local literal)
// so the two packages cannot drift.
//
// Host and path are extracted with net/url.Parse — the same routine hostOfURL
// uses for baseHost — so the two host extractions cannot disagree (url.Host
// excludes userinfo, so "https://u:p@h/x" and a relative path on host "h" agree).
// The host is lower-cased because hostnames are case-insensitive.
func concatDedupKey(u, baseHost string) string {
	// A relative URL keeps baseHost (it is same-origin by construction); an
	// absolute URL uses its own host. url.Parse also drops query/fragment
	// (parsed.Path excludes them) and tolerates {param} placeholders in the path.
	host := baseHost
	path := u
	if parsed, err := url.Parse(u); err == nil {
		if parsed.Host != "" {
			host = parsed.Host
		}
		path = parsed.Path
	} else if i := strings.IndexAny(u, "?#"); i >= 0 {
		// Defensive: url.Parse effectively never fails on these inputs, but if it
		// did, still strip query/fragment before keying.
		path = u[:i]
	}
	host = strings.ToLower(host)
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	segments := strings.Split(path, "/")
	for i, seg := range segments {
		if seg == crawl.ConcatPathSentinel || (len(seg) >= 2 && strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}")) {
			segments[i] = "{}"
		}
	}
	return host + "|" + strings.Join(segments, "/")
}

// hostOfURL returns the lower-cased host component of rawURL, or "" when it has
// none or is unparseable (e.g. a relative or empty base). Used to origin-scope
// concatDedupKey.
func hostOfURL(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Host)
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
	fetchURLsWithMethod map[string]bool,
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

	// Drop jsluice's redundant method-less "fetch" duplicate when a
	// method-bearing fetch match exists for the same URL (see ExtractFromBundle
	// step 4). This prevents a phantom GET for non-GET fetches while preserving
	// a lone method-less fetch (kept as GET) and genuine multi-method URLs
	// (each method-bearing match survives on its own (method, url) dedup key).
	if u.Type == "fetch" && u.Method == "" && fetchURLsWithMethod[raw] {
		return ExtractedEndpoint{}, false
	}

	// Identifier-token recovery for jsluice's built-in URL matches isn't
	// implemented (only the template-literal walker in extractTemplateLiteralFetches
	// has the AST context to do it). Pass nil; NormalizeEXPRPath falls back to
	// {param}, {param1}, ... numbering.
	normalized := NormalizeEXPRPath(raw, nil)
	if normalized == "" {
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
