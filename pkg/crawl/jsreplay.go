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

// Threat model: every URL here comes from an attacker-controlled JS bundle.
// Three defenses, each opt-out-able: same-origin gate (probes and headers stay on
// the scan target; AllowCrossOrigin), SSRF validation plus SafeDialContext
// against DNS rebinding (AllowPrivate), and bounds on attempts (MaxEndpoints)
// and wall-clock (MaxTotalTime).

package crawl

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/praetorian-inc/vespasian/pkg/mediatype"
	"github.com/praetorian-inc/vespasian/pkg/ssrf"
)

// JSReplayConfig configures the JS API path extraction and probing step.
type JSReplayConfig struct {
	// Same-origin only, regardless of AllowCrossOrigin. See doRequest.
	Headers map[string]string

	// Empty means derive the origin from the capture: first HTML response,
	// else first non-empty URL.
	TargetURL string

	// Disables SSRF protection. Mirrors --dangerous-allow-private.
	AllowPrivate bool

	// Probe off-target origins. Off by default: it exposes the operator's IP to
	// attacker-chosen hosts and makes Vespasian a request reflector. Does NOT
	// widen Headers — those stay same-origin either way.
	AllowCrossOrigin bool

	Timeout time.Duration // per request; 0 -> 10s

	// Whole-step wall-clock. 0 -> MaxEndpoints*Timeout, capped at 10 min.
	MaxTotalTime time.Duration

	MaxEndpoints int          // probe attempts, successful or not; 0 -> 500
	Client       *http.Client // nil -> SSRF-safe client unless AllowPrivate
	Verbose      bool

	// 0 -> io.Discard. Warnings write here even when Verbose is false.
	Stderr io.Writer
}

const (
	defaultMaxEndpoints = 500
	defaultTimeout      = 10 * time.Second
	maxTotalTimeCap     = 10 * time.Minute // ceiling on MaxEndpoints*Timeout
)

// withDefaults fills zero fields and installs an SSRF-safe transport unless
// AllowPrivate.
func (cfg JSReplayConfig) withDefaults() JSReplayConfig {
	if cfg.Timeout == 0 {
		cfg.Timeout = defaultTimeout
	}
	if cfg.MaxEndpoints == 0 {
		cfg.MaxEndpoints = defaultMaxEndpoints
	}
	if cfg.MaxTotalTime == 0 {
		// Worst case is every probe timing out.
		cfg.MaxTotalTime = time.Duration(cfg.MaxEndpoints) * cfg.Timeout
		if cfg.MaxTotalTime > maxTotalTimeCap {
			cfg.MaxTotalTime = maxTotalTimeCap
		}
	}
	if cfg.Stderr == nil {
		cfg.Stderr = io.Discard
	}
	if cfg.Client == nil {
		cfg.Client = newSSRFSafeClient(cfg.Timeout, cfg.AllowPrivate)
	} else {
		if !cfg.AllowPrivate {
			cfg.Client = wrapClientWithSSRF(cfg.Client, cfg.Timeout, cfg.Stderr)
		} else {
			// Copy so the caller's CheckRedirect is not mutated.
			clone := *cfg.Client
			cfg.Client = &clone
			if cfg.Client.Timeout == 0 {
				cfg.Client.Timeout = cfg.Timeout
			}
		}
		cfg.Client.CheckRedirect = noRedirect
	}
	return cfg
}

// noRedirect returns 3xx verbatim: probeURL must record the response from the
// URL it asked for, and fetchJSBody follows redirects itself with per-hop
// SSRF and same-origin re-validation.
func noRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

// wrapClientWithSSRF copies caller and installs ssrf.SafeDialContext on a cloned
// transport. Never mutates the caller's Client or Transport — other holders of
// those pointers would silently get new dial behavior.
//
// An opaque RoundTripper cannot have its dialer wrapped, so it falls back to
// request-time validation, which leaves a narrow DNS-rebinding window.
func wrapClientWithSSRF(caller *http.Client, timeout time.Duration, stderr io.Writer) *http.Client {
	clone := *caller
	switch t := caller.Transport.(type) {
	case *http.Transport:
		tc := t.Clone()
		tc.DialContext = ssrf.SafeDialContext
		clone.Transport = tc
	case nil:
		// Reuse the no-client path so the defaults (TLSHandshakeTimeout etc.)
		// come along, rather than a bare &http.Transport{}.
		clone.Transport = newSSRFSafeClient(timeout, false).Transport
	default:
		fmt.Fprintf(stderr, //nolint:errcheck // best-effort warning
			"js-extract: warning: caller-supplied http.Client.Transport is %T (not *http.Transport); "+
				"dial-time SSRF pinning cannot be installed (a narrow DNS-rebinding window remains). "+
				"Falling back to request-time ssrf.ValidateURLContext on every request.\n", t)
		clone.Transport = ssrfValidatingRoundTripper{base: caller.Transport}
	}
	if clone.Timeout == 0 {
		clone.Timeout = timeout
	}
	return &clone
}

// ssrfValidatingRoundTripper re-checks every request URL against the SSRF
// blocklist before delegating. Fallback for transports that cannot take a
// dial-time SafeDialContext.
type ssrfValidatingRoundTripper struct {
	base http.RoundTripper
}

// RoundTrip rejects private/internal destinations without sending the request.
func (rt ssrfValidatingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := ssrf.ValidateURLContext(req.Context(), req.URL.String()); err != nil {
		return nil, fmt.Errorf("js-extract: SSRF validation rejected %s: %w", req.URL.Redacted(), err)
	}
	return rt.base.RoundTrip(req)
}

// newSSRFSafeClient clones DefaultTransport with SafeDialContext (unless
// allowPrivate), a timeout, and noRedirect.
func newSSRFSafeClient(timeout time.Duration, allowPrivate bool) *http.Client {
	var transport *http.Transport
	if t, ok := http.DefaultTransport.(*http.Transport); ok {
		transport = t.Clone()
	} else {
		transport = &http.Transport{}
	}
	if !allowPrivate {
		transport.DialContext = ssrf.SafeDialContext
	}
	return &http.Client{
		Timeout:       timeout,
		Transport:     transport,
		CheckRedirect: noRedirect,
	}
}

const maxReplayBodySize = 1 << 20 // probe response body cap

// 10x the crawl's MaxResponseBodySize: SPA bundles routinely exceed 1 MB and the
// API paths can sit past that truncation point.
const maxJSBodySize = 10 << 20

var jsContentTypes = []string{
	"application/javascript",
	"text/javascript",
	"application/x-javascript",
}

var htmlContentTypes = []string{
	"text/html",
	"application/xhtml+xml",
}

// matchesContentType canonicalizes via mediatype.Base, shared with the classify
// and generate stages.
func matchesContentType(contentType string, types []string) bool {
	ct := mediatype.Base(contentType)
	for _, t := range types {
		if ct == t {
			return true
		}
	}
	return false
}

func isHTMLResponse(contentType string) bool {
	return matchesContentType(contentType, htmlContentTypes)
}

func isJSResponse(contentType string) bool {
	return matchesContentType(contentType, jsContentTypes)
}

// scriptSrcPattern takes any src, not just *.js, so cache-busted URLs like
// /main.js?v=123 match; isJSURL filters the resolved URL afterwards.
var scriptSrcPattern = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+)["']`)

// extractScriptURLs returns absolute JS URLs from <script src> tags, dropping
// non-JS srcs such as importmaps.
func extractScriptURLs(htmlBody []byte, pageURL string) []string {
	base, err := url.Parse(pageURL)
	if err != nil {
		return nil
	}

	seen := make(map[string]bool)
	var urls []string
	for _, match := range scriptSrcPattern.FindAllSubmatch(htmlBody, -1) {
		if len(match) < 2 {
			continue
		}
		src := string(match[1])
		ref, err := url.Parse(src)
		if err != nil {
			continue
		}
		resolved := base.ResolveReference(ref).String()
		if !isJSURL(resolved) {
			continue
		}
		if !seen[resolved] {
			seen[resolved] = true
			urls = append(urls, resolved)
		}
	}
	return urls
}

// --- Extraction patterns ---
//
// Regex extraction cannot tell a real path literal from an error string or a
// locale message containing "/api/". False positives are expected: the probe
// loop's 404 filter drops them and MaxEndpoints bounds their cost.

// apiPathPattern matches API-like paths in quoted JS strings.
var apiPathPattern = regexp.MustCompile(
	`["']` +
		`(/?` +
		`(?:[a-zA-Z0-9_-]+/)*` +
		apiIndicatorAlternation +
		`[a-zA-Z0-9/_\{}.:-]*)` +
		`["']`,
)

// templateLiteralPattern is the no-interpolation fallback;
// extractTemplateLiteralPaths handles ${...}.
var templateLiteralPattern = regexp.MustCompile(
	"`" +
		`(/?` +
		`(?:[a-zA-Z0-9_-]+/)*` +
		apiIndicatorAlternation +
		`[a-zA-Z0-9/_\{}.:-]*)` +
		"`",
)

// fullURLPattern matches absolute API URLs, e.g. "https://api.example.com/v1/users".
var fullURLPattern = regexp.MustCompile(
	`["'` + "`]" +
		`(https?://[a-zA-Z0-9._-]+(?::[0-9]+)?` +
		`/(?:[a-zA-Z0-9_-]+/)*` +
		apiIndicatorAlternation +
		`[a-zA-Z0-9/_\{}.:-]*)` +
		`["'` + "`]",
)

// apiIndicatorAlternation is the single source for API-signaling path segments;
// every extraction regex and apiIndicatorPattern embed it, so they cannot drift.
const apiIndicatorAlternation = `(?:api/|v[1-9][0-9]*/|rest/|rpc/|graphql)`

// servicePrefixPattern matches literal+literal `+`, e.g. "identity/" +
// "api/auth/login" captures "identity/". Backticks and non-literal operands go
// to extractTemplateLiteralPaths and extractConcatPaths (LAB-1368).
var servicePrefixPattern = regexp.MustCompile(
	`["']([a-zA-Z][a-zA-Z0-9_-]{1,30}/)["']\s*\+\s*["']` + apiIndicatorAlternation,
)

// concatMethodPattern matches a quoted receiver before `.concat(`, group 1 the
// receiver. The arg list is not in the regex: regexes cannot balance nested
// parens, so findConcatArgListEnd scans for the closing `)`. Non-literal
// receivers (`obj.url.concat(...)`) would need an AST and are out of scope.
// LAB-1368.
//
// The receiver class adds `?=&%~` over concatPlusHeadPattern deliberately: a
// `.concat()` receiver is sometimes a query fragment (`"/api/users?id=".concat`)
// while a `+`-chain head is a clean path. emit()'s hasAPIIndicator filter makes
// the wider class safe.
var concatMethodPattern = regexp.MustCompile(
	`["']` +
		`(/?[a-zA-Z0-9/_{}.:?=&%~-]+)` +
		`["']\.concat\(`,
)

// concatPlusHeadPattern matches the head of a `+` chain, e.g. "/api/users/" + id
// + "/posts" (LAB-1368). parsePlusChain walks the rest — a regex cannot bound an
// arbitrary chain without runaway backtracking. The API-indicator anchor stops
// random `"a" + b` from triggering the walker.
//
// Group 1 is the head literal; the match ends just past the `+`, where
// parsePlusChain starts.
var concatPlusHeadPattern = regexp.MustCompile(
	`["']` +
		`(/?` +
		`(?:[a-zA-Z0-9_-]+/)*` +
		apiIndicatorAlternation +
		`[a-zA-Z0-9/_{}.:-]*)` +
		`["']\s*\+`,
)

// concatPathSentinel replaces non-literal concat operands. Numeric so
// rest.NormalizePathWithNames turns it into a named {param}, and "0" rather than
// "{}" keeps the path valid enough to actually probe.
const concatPathSentinel = "0"

// maxConcatChainOperands bounds a `+` chain walk. Real URL chains are a handful
// of segments; past this it is noise. Unmeasured.
const maxConcatChainOperands = 16

// maxConcatChainSpan bounds parsePlusChain's byte span, enforced by clamping its
// working slice so every per-operand scan is bounded regardless of bracket depth.
// Without it, a `"/api/" +` anchor in front of a megabytes-long bracketed
// expression whose terminators sit at end-of-bundle costs a full-span walk per
// match.
//
// 1024 exceeds any realistic URL chain and bounds aggregate work at O(M * 1024)
// over M matches. maxConcatChainOperands does not multiply it: all operand walks
// in one invocation share the clamped slice and pos only advances.
const maxConcatChainSpan = 1024

// maxConcatArgList bounds findConcatArgListEnd's paren-aware scan. 500 bytes is
// wider than any real arg list, since only literal segments and
// identifier-shaped operands matter here.
const maxConcatArgList = 500

// maxConcatPathsPerBundle bounds pre-probe fan-out from one bundle, complementing
// the cross-bundle MaxEndpoints backstop. Unmeasured.
const maxConcatPathsPerBundle = 256

var apiIndicatorPattern = regexp.MustCompile(`(?i)` + apiIndicatorAlternation)

// standalonePrefixPattern matches bare prefix literals like "identity/", for
// bundles that do `const SVC = "identity/"; fetch(SVC + "api/auth/login")` rather
// than the literal+literal form servicePrefixPattern needs.
//
// It also matches asset folders ("images/", "static/"), so extractServicePrefixes
// filters on: no API indicator, at least standalonePrefixMinFrequency
// occurrences, and maxBundlePrefixCap total.
var standalonePrefixPattern = regexp.MustCompile(
	`["']([a-z][a-z0-9_-]{1,30}/)["']`,
)

// standalonePrefixMinFrequency is 1 because production SPAs (OWASP crAPI)
// declare a prefix once as a constant and use the variable after, so requiring 2
// literal matches rejects real prefixes. Noise is caught by the other filters,
// the 404 filter, and MaxEndpoints.
const standalonePrefixMinFrequency = 1

// maxBundlePrefixCap is the TOTAL prefix budget per bundle across all three
// strategies, bounding worst-case paths × prefixes probe expansion. Unmeasured.
const maxBundlePrefixCap = 8

var staticFileExts = []string{".js", ".css", ".map", ".html", ".htm", ".png", ".jpg", ".svg"}

// --- Helper functions ---

func isJSURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	lower := strings.ToLower(u.Path)
	return strings.HasSuffix(lower, ".js") || strings.HasSuffix(lower, ".mjs")
}

func isStaticFile(path string) bool {
	lower := strings.ToLower(path)
	for _, ext := range staticFileExts {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

func hasAPIIndicator(path string) bool {
	return apiIndicatorPattern.MatchString(path)
}

// hasInlinePrefix reports a non-API segment before the first API indicator, i.e.
// the path already carries a service prefix ("identity/api/..."). "api/v2/users"
// does not: "api/" is itself an indicator.
func hasInlinePrefix(trimmedPath string) bool {
	loc := apiIndicatorPattern.FindStringIndex(trimmedPath)
	return loc != nil && loc[0] > 0
}

// defaultPortForScheme lets originOf compare implicit and explicit default ports
// as equal.
func defaultPortForScheme(scheme string) string {
	switch strings.ToLower(scheme) {
	case "http":
		return "80"
	case "https":
		return "443"
	}
	return ""
}

// originOf canonicalizes to scheme://host:port, lower-cased with the default port
// made explicit, so https://example.com and https://example.com:443 collapse to
// one string. Without it isSameOrigin skips valid same-origin probes. Returns ""
// if unparseable or hostless.
func originOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port == "" {
		port = defaultPortForScheme(scheme)
	}
	if port == "" {
		// Unknown scheme without an explicit port: fall back to the raw
		// host string so non-http(s) URLs still compare consistently.
		return scheme + "://" + host
	}
	return scheme + "://" + host + ":" + port
}

// firstHTMLOrigin binds replay to the real app page rather than the first capture
// entry, which in an imported mixed-origin capture may be a third-party asset.
func firstHTMLOrigin(requests []ObservedRequest) string {
	for _, req := range requests {
		if req.URL == "" {
			continue
		}
		if !isHTMLResponse(req.Response.ContentType) && !looksLikeHTML(req.Response.Body) {
			continue
		}
		if origin := originOf(req.URL); origin != "" {
			return origin
		}
	}
	return ""
}

// isSameOrigin compares both sides through originOf.
func isSameOrigin(rawURL, targetOrigin string) bool {
	if targetOrigin == "" {
		return false
	}
	return originOf(rawURL) == originOf(targetOrigin)
}

// sanitizeForLog stops an attacker-controlled bundle string injecting ANSI
// sequences or NULs into the operator's terminal.
func sanitizeForLog(s string) string {
	if s == "" {
		return s
	}
	return strconv.Quote(s)
}

// warnDerivedOrigin names the origin replay will hit, and the credentials going
// with it, when --target-url is unset. Never gated on Verbose: the operator did
// not choose this origin, the capture did. Interim; redesign is LAB-4998.
func warnDerivedOrigin(w io.Writer, targetOrigin string, hasHeaders bool) {
	origin := sanitizeForLog(targetOrigin)
	if hasHeaders {
		fmt.Fprintf(w, "WARNING: --target-url not set; JS-replay derived origin %s from the capture — requests AND your --header credentials will be sent there. Pass --target-url to pin it.\n", origin) //nolint:errcheck // operator-facing warning
		return
	}
	fmt.Fprintf(w, "WARNING: --target-url not set; JS-replay derived origin %s from the capture — requests will be sent there. Pass --target-url to pin it.\n", origin) //nolint:errcheck // operator-facing warning
}

// copyHeaders stops recorded ObservedRequests sharing the caller's map.
func copyHeaders(h map[string]string) map[string]string {
	if h == nil {
		return nil
	}
	out := make(map[string]string, len(h))
	for k, v := range h {
		out[k] = v
	}
	return out
}

// validateFullURL rejects embedded credentials, non-http(s) schemes, and empty
// hosts. It does NOT reject private IP literals — callers MUST also run
// ssrf.ValidateURL before issuing a request.
func validateFullURL(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", false
	}
	if u.Host == "" {
		return "", false
	}
	// Otherwise the bundle can force arbitrary basic auth on the operator's behalf.
	if u.User != nil {
		return "", false
	}
	return u.String(), true
}

// --- Extraction logic ---

// extractServicePrefixes discovers prefixes three ways: literal+literal `+`;
// crawl results whose URL is one segment under a JS file's directory
// (/static/js/identity/); and addStandaloneCandidates.
func extractServicePrefixes(jsBody []byte, requests []ObservedRequest) []string { //nolint:gocyclo // multi-strategy prefix discovery
	seen := make(map[string]bool)
	var prefixes []string

	add := func(prefix string) {
		if !seen[prefix] {
			seen[prefix] = true
			prefixes = append(prefixes, prefix)
		}
	}

	for _, match := range servicePrefixPattern.FindAllSubmatch(jsBody, -1) {
		if len(match) >= 2 {
			add(string(match[1]))
		}
	}

	jsURLs := make(map[string]bool)
	for _, req := range requests {
		if isJSURL(req.URL) {
			jsURLs[req.URL] = true
		}
	}

	for _, req := range requests {
		if !isJSURL(req.Source) {
			continue
		}
		if !jsURLs[req.Source] {
			continue
		}

		srcURL, err1 := url.Parse(req.Source)
		reqURL, err2 := url.Parse(req.URL)
		if err1 != nil || err2 != nil {
			continue
		}

		jsDir := srcURL.Path[:strings.LastIndex(srcURL.Path, "/")+1]
		reqPath := reqURL.Path

		if !strings.HasPrefix(reqPath, jsDir) {
			continue
		}
		suffix := strings.TrimPrefix(reqPath, jsDir)
		suffix = strings.TrimSuffix(suffix, "/")

		if suffix == "" || strings.Contains(suffix, "/") || strings.Contains(suffix, ".") {
			continue
		}

		// Lowercase-alphanumeric and short, like a service name.
		valid := true
		for _, c := range suffix {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
				valid = false
				break
			}
		}
		if valid && len(suffix) >= 2 && len(suffix) <= 30 {
			add(suffix + "/")
		}
	}

	addStandaloneCandidates(jsBody, add, seen)

	return prefixes
}

// addStandaloneCandidates emits bare prefix literals: filter, count, cap, sort.
//
// len(seen) on entry is what the earlier strategies emitted, so the remaining
// budget must be taken before adding — that is what holds the bundle under
// maxBundlePrefixCap regardless of how they fared.
func addStandaloneCandidates(jsBody []byte, add func(string), seen map[string]bool) {
	existing := len(seen)
	if existing >= maxBundlePrefixCap {
		return
	}
	budget := maxBundlePrefixCap - existing

	freq := make(map[string]int)
	for _, match := range standalonePrefixPattern.FindAllSubmatch(jsBody, -1) {
		if len(match) < 2 {
			continue
		}
		candidate := string(match[1])
		if apiIndicatorPattern.MatchString(candidate) {
			continue
		}
		// Skipped before freq++, so already-emitted prefixes stay out of this
		// frequency count; they are already charged to the cap via `existing`.
		if seen[candidate] {
			continue
		}
		freq[candidate]++
	}

	type cand struct {
		name  string
		count int
	}
	candidates := make([]cand, 0, len(freq))
	for name, n := range freq {
		// Admits everything while the constant is 1. Kept as the tuning point.
		if n < standalonePrefixMinFrequency {
			continue
		}
		candidates = append(candidates, cand{name, n})
	}

	// Descending count then ascending name: deterministic across runs, and
	// prefers frequently-used prefixes.
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].count != candidates[j].count {
			return candidates[i].count > candidates[j].count
		}
		return candidates[i].name < candidates[j].name
	})

	limit := budget
	if len(candidates) < limit {
		limit = len(candidates)
	}
	for i := 0; i < limit; i++ {
		add(candidates[i].name)
	}
}

// extractTemplateLiteralPaths turns `/api/users/${id}/profile` into
// /api/users/{param}/profile. Backticks inside a ${...} are nested literals, not
// the outer closer — otherwise `outer ${`inner`}` mispairs.
func extractTemplateLiteralPaths(jsBody []byte) []string {
	var paths []string
	for i := 0; i < len(jsBody); i++ {
		if jsBody[i] != '`' {
			continue
		}
		end := findTemplateLiteralEnd(jsBody, i+1)
		if end < 0 {
			break // unterminated literal
		}
		segment := jsBody[i+1 : end]
		if path, ok := reconstructTemplateLiteral(segment); ok {
			paths = append(paths, path)
		}
		i = end
	}
	return paths
}

// findTemplateLiteralEnd returns the matching closing backtick, walking past
// ${...} and nested literals. -1 if unmatched.
func findTemplateLiteralEnd(jsBody []byte, start int) int { //nolint:gocyclo // template-literal state machine — splitting hurts readability
	exprDepth := 0 // brace depth inside ${...} on the current literal
	for i := start; i < len(jsBody); i++ {
		c := jsBody[i]
		if exprDepth == 0 {
			if c == '`' {
				return i
			}
			if c == '$' && i+1 < len(jsBody) && jsBody[i+1] == '{' {
				exprDepth = 1
				i++ // skip the '{'
				continue
			}
			if c == '\\' && i+1 < len(jsBody) {
				i++ // skip the escaped byte
				continue
			}
			continue
		}
		switch c {
		case '`':
			nested := findTemplateLiteralEnd(jsBody, i+1)
			if nested < 0 {
				return -1
			}
			i = nested
		case '{':
			exprDepth++
		case '}':
			exprDepth--
			if exprDepth < 0 {
				// Malformed JS: unbalanced '}' inside a ${...}
				// interpolation. Without this guard, exprDepth stays
				// negative and the top-level branch (which recognizes
				// the closing backtick) is never re-entered, so we'd
				// silently scan to end-of-input. Bail explicitly.
				return -1
			}
		case '\\':
			if i+1 < len(jsBody) {
				i++
			}
		}
	}
	return -1
}

// reconstructTemplateLiteral replaces ${...} with {param}. ok=false unless the
// result has an API indicator and looks path-like.
func reconstructTemplateLiteral(segment []byte) (string, bool) {
	var b strings.Builder
	depth := 0
	for i := 0; i < len(segment); i++ {
		c := segment[i]
		if depth == 0 {
			if c == '$' && i+1 < len(segment) && segment[i+1] == '{' {
				b.WriteString("{param}")
				depth = 1
				i++ // skip the '{'
				continue
			}
			b.WriteByte(c)
			continue
		}
		switch c {
		case '{':
			depth++
		case '}':
			depth--
		}
	}
	// Template literals embed paths inside larger expressions; keep the core.
	candidate := b.String()
	candidate = strings.TrimSpace(candidate)
	if !strings.HasPrefix(candidate, "/") && !strings.HasPrefix(candidate, "http://") && !strings.HasPrefix(candidate, "https://") {
		if idx := strings.Index(candidate, "/"); idx > 0 {
			candidate = candidate[idx:]
		}
	}
	if candidate == "" || !hasAPIIndicator(candidate) {
		return "", false
	}
	// Embedded whitespace means this is not one path.
	if strings.ContainsAny(candidate, " \t\r\n") {
		return "", false
	}
	return candidate, true
}

// extractConcatPaths handles both concat forms, substituting concatPathSentinel
// for non-literal operands:
//
//	"/api/posts/".concat(id, "/comment")  -> /api/posts/0/comment
//	"/api/users/" + id + "/posts"         -> /api/users/0/posts
//
// All-literal chains match here too and may also match servicePrefixPattern or
// apiPathPattern; emit()'s seen-map dedupes the collision.
func extractConcatPaths(jsBody []byte) []string { //nolint:gocyclo // emit() state machine (slash-collapse + indicator filter + dedup + per-bundle cap); splitting hurts readability and matches the sibling parser convention in this file
	seen := make(map[string]bool)
	var paths []string

	emit := func(p string) {
		if len(paths) >= maxConcatPathsPerBundle {
			return
		}
		// `"/api/posts/" + "/comment"` yields a `//` run. addPath only trims
		// leading and trailing slashes, and the REST normalizer treats `//{id}`
		// as a distinct malformed segment. Collapse the path side only, so `://`
		// survives; loop for 3+ slash runs.
		if scheme, rest, hasScheme := strings.Cut(p, "://"); hasScheme {
			for strings.Contains(rest, "//") {
				rest = strings.ReplaceAll(rest, "//", "/")
			}
			p = scheme + "://" + rest
		} else {
			for strings.Contains(p, "//") {
				p = strings.ReplaceAll(p, "//", "/")
			}
		}
		if p == "" || !hasAPIIndicator(p) {
			return
		}
		if strings.ContainsAny(p, " \t\r\n") {
			return
		}
		if seen[p] {
			return
		}
		seen[p] = true
		paths = append(paths, p)
	}

	// [0,1] full match including `.concat(`, [2,3] receiver.
	for _, match := range concatMethodPattern.FindAllSubmatchIndex(jsBody, -1) {
		if len(match) < 4 || match[2] < 0 {
			continue
		}
		receiver := string(jsBody[match[2]:match[3]])
		argEnd := findConcatArgListEnd(jsBody, match[1])
		if argEnd < 0 {
			continue
		}
		// Already <= maxConcatArgList: findConcatArgListEnd caps its own scan.
		argList := string(jsBody[match[1]:argEnd])
		emit(receiver + parseConcatArgs(argList))
	}

	// [0,1] full match including the trailing `+`, [2,3] head literal.
	for _, match := range concatPlusHeadPattern.FindAllSubmatchIndex(jsBody, -1) {
		if len(match) < 4 || match[2] < 0 {
			continue
		}
		head := string(jsBody[match[2]:match[3]])
		suffix := parsePlusChain(jsBody, match[1])
		emit(head + suffix)
	}

	return paths
}

// parseConcatArgs reconstructs the suffix from a .concat() arg list: literals
// verbatim, anything else concatPathSentinel. argList is the raw source between
// the parens; commas inside quotes are not separators.
func parseConcatArgs(argList string) string {
	args := splitConcatArgs(argList)
	var b strings.Builder
	for _, arg := range args {
		arg = strings.TrimSpace(arg)
		if arg == "" {
			continue
		}
		if lit, ok := stringLiteralValue(arg); ok {
			b.WriteString(lit)
			continue
		}
		b.WriteString(concatPathSentinel)
	}
	return b.String()
}

// findConcatArgListEnd finds the closing `)`, tracking bracket depth and string
// literals so `.concat(foo(a, b), "/x")` does not terminate early. -1 if
// malformed or beyond maxConcatArgList.
func findConcatArgListEnd(jsBody []byte, start int) int { //nolint:gocyclo // small state machine
	depthRound, depthSquare, depthCurly := 0, 0, 0
	limit := start + maxConcatArgList
	if limit > len(jsBody) {
		limit = len(jsBody)
	}
	// Clamping bounds any string scan at `limit`; a backtick opening near it
	// routes through findTemplateLiteralEnd, which has no newline termination and
	// would otherwise walk megabytes.
	//
	// Defensive only, no behavioral signature: the loop is already capped at
	// `i < limit`, so the return value never changes and a 3.1 MB / 5000-match
	// worst case measures ~76ms either way. Before deleting it, know that no test
	// can fail — the DoS-bound tests pin parsePlusChain's clamp, not this one.
	body := jsBody[:limit]
	for i := start; i < limit; i++ {
		c := body[i]
		switch c {
		case '"', '\'', '`':
			end := scanStringLiteral(body, i)
			if end < 0 {
				return -1
			}
			i = end
		case '(':
			depthRound++
		case ')':
			if depthRound == 0 && depthSquare == 0 && depthCurly == 0 {
				return i
			}
			if depthRound > 0 {
				depthRound--
			}
		case '[':
			depthSquare++
		case ']':
			if depthSquare > 0 {
				depthSquare--
			}
		case '{':
			depthCurly++
		case '}':
			if depthCurly > 0 {
				depthCurly--
			}
		}
	}
	return -1
}

// splitConcatArgs splits on top-level commas only, untrimmed. Delegates string
// scanning to scanStringLiteral so nested ${} behaves as elsewhere.
func splitConcatArgs(argList string) []string { //nolint:gocyclo // small string-state machine; splitting hurts readability
	data := []byte(argList)
	var args []string
	var b strings.Builder
	depthRound, depthSquare, depthCurly := 0, 0, 0
scan:
	for i := 0; i < len(data); i++ {
		c := data[i]
		switch c {
		case '"', '\'', '`':
			end := scanStringLiteral(data, i)
			if end < 0 {
				// Take the remainder verbatim so stray commas in the tail do not
				// become extra arguments. Labeled: a bare break exits the switch.
				b.Write(data[i:])
				break scan
			}
			b.Write(data[i : end+1])
			i = end
		case '(':
			depthRound++
			b.WriteByte(c)
		case ')':
			if depthRound > 0 {
				depthRound--
			}
			b.WriteByte(c)
		case '[':
			depthSquare++
			b.WriteByte(c)
		case ']':
			if depthSquare > 0 {
				depthSquare--
			}
			b.WriteByte(c)
		case '{':
			depthCurly++
			b.WriteByte(c)
		case '}':
			if depthCurly > 0 {
				depthCurly--
			}
			b.WriteByte(c)
		case ',':
			if depthRound == 0 && depthSquare == 0 && depthCurly == 0 {
				args = append(args, b.String())
				b.Reset()
				continue
			}
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	if b.Len() > 0 {
		args = append(args, b.String())
	}
	return args
}

// stringLiteralValue returns the unquoted text of a literal with no ${}.
// Escapes are NOT decoded: they are rare in URL paths and decoding risks
// characters that will not round-trip through the prober.
func stringLiteralValue(s string) (string, bool) {
	if len(s) < 2 {
		return "", false
	}
	first, last := s[0], s[len(s)-1]
	if first != last {
		return "", false
	}
	switch first {
	case '"', '\'':
		return s[1 : len(s)-1], true
	case '`':
		inner := s[1 : len(s)-1]
		if strings.Contains(inner, "${") {
			return "", false
		}
		return inner, true
	}
	return "", false
}

// parsePlusChain walks a `+` chain from just after the head's `+`, alternating
// operand and `+`, taking literals verbatim and concatPathSentinel for the rest.
// Bails on a malformed operand or missing `+`.
//
// Bounded by maxConcatChainOperands and maxConcatChainSpan. The span cap is a
// slice clamp applied BEFORE any per-operand scan, so it covers iteration 0 and
// cannot be bypassed by a future operand type. Without it, a `"/api/"+` anchor
// before a long bracketed expression makes scanIdentifierOperand walk to
// end-of-body hunting a depth-0 terminator.
func parsePlusChain(jsBody []byte, start int) string {
	limit := start + maxConcatChainSpan
	if limit > len(jsBody) {
		limit = len(jsBody)
	}
	body := jsBody[:limit]

	var b strings.Builder
	pos := start
	for op := 0; op < maxConcatChainOperands; op++ {
		pos = skipPlusChainWhitespace(body, pos)
		if pos >= len(body) {
			return b.String()
		}
		lit, end, ok := readChainOperand(body, pos)
		if !ok {
			return b.String()
		}
		b.WriteString(lit)
		pos = skipPlusChainWhitespace(body, end)
		if pos >= len(body) || body[pos] != '+' {
			return b.String()
		}
		pos++
	}
	return b.String()
}

// readChainOperand reads one operand. Boundary is the next top-level `+`, `;`,
// `,`, newline, or closing bracket. Returns (text, end, ok).
func readChainOperand(jsBody []byte, pos int) (string, int, bool) {
	if pos >= len(jsBody) {
		return "", pos, false
	}
	c := jsBody[pos]
	if c == '"' || c == '\'' || c == '`' {
		end := scanStringLiteral(jsBody, pos)
		if end < 0 {
			return "", pos, false
		}
		raw := string(jsBody[pos : end+1])
		if lit, ok := stringLiteralValue(raw); ok {
			return lit, end + 1, true
		}
		return concatPathSentinel, end + 1, true
	}
	end := scanIdentifierOperand(jsBody, pos)
	if end == pos {
		return "", pos, false
	}
	return concatPathSentinel, end, true
}

// scanStringLiteral returns the matching closing quote, or -1. For backticks it
// walks past ${} so a nested `+` is not read as a chain separator.
func scanStringLiteral(jsBody []byte, start int) int {
	if start >= len(jsBody) {
		return -1
	}
	quote := jsBody[start]
	if quote == '`' {
		end := findTemplateLiteralEnd(jsBody, start+1)
		return end
	}
	for i := start + 1; i < len(jsBody); i++ {
		c := jsBody[i]
		if c == '\\' && i+1 < len(jsBody) {
			i++
			continue
		}
		if c == quote {
			return i
		}
		if c == '\n' {
			return -1
		}
	}
	return -1
}

// scanIdentifierOperand returns the exclusive end of a non-literal operand,
// skipping bracketed sub-expressions so their commas do not split it.
func scanIdentifierOperand(jsBody []byte, pos int) int { //nolint:gocyclo // small state machine
	depthRound, depthSquare, depthCurly := 0, 0, 0
	i := pos
	for ; i < len(jsBody); i++ {
		c := jsBody[i]
		if depthRound == 0 && depthSquare == 0 && depthCurly == 0 {
			switch c {
			case '+', ';', ',', '\n', '\r':
				return i
			case ')', ']', '}':
				return i
			}
		}
		switch c {
		case '(':
			depthRound++
		case ')':
			if depthRound > 0 {
				depthRound--
			}
		case '[':
			depthSquare++
		case ']':
			if depthSquare > 0 {
				depthSquare--
			}
		case '{':
			depthCurly++
		case '}':
			if depthCurly > 0 {
				depthCurly--
			}
		case '"', '\'', '`':
			end := scanStringLiteral(jsBody, i)
			if end < 0 {
				return i
			}
			i = end
		}
	}
	return i
}

// skipPlusChainWhitespace also skips newlines, safe because it is only called
// between operands where JS formatting may wrap. scanIdentifierOperand stops at
// `\n`, so an operand still cannot swallow the next statement.
func skipPlusChainWhitespace(jsBody []byte, pos int) int {
	for pos < len(jsBody) {
		c := jsBody[pos]
		if c != ' ' && c != '\t' && c != '\n' && c != '\r' {
			return pos
		}
		pos++
	}
	return pos
}

// extractAPIPaths runs every extraction strategy and dedupes. Unprefixed paths
// are expanded against each discovered service prefix; already-prefixed and
// full-URL paths are kept as-is.
func extractAPIPaths(jsBody []byte, requests []ObservedRequest) []string { //nolint:gocyclo // multi-strategy path extraction
	prefixes := extractServicePrefixes(jsBody, requests)

	seen := make(map[string]bool)
	var paths []string

	addPath := func(raw string) {
		if isStaticFile(raw) {
			return
		}

		if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
			cleaned, ok := validateFullURL(raw)
			if !ok {
				return
			}
			cleaned = strings.TrimRight(cleaned, "/")
			if !seen[cleaned] {
				seen[cleaned] = true
				paths = append(paths, cleaned)
			}
			return
		}

		if !strings.HasPrefix(raw, "/") {
			raw = "/" + raw
		}
		raw = strings.TrimRight(raw, "/")
		if raw == "" {
			return
		}

		trimmed := strings.TrimPrefix(raw, "/")

		knownPrefix := false
		for _, prefix := range prefixes {
			if strings.HasPrefix(trimmed, prefix) {
				knownPrefix = true
				break
			}
		}

		if knownPrefix || hasInlinePrefix(trimmed) || len(prefixes) == 0 {
			if !seen[raw] {
				seen[raw] = true
				paths = append(paths, raw)
			}
		} else {
			// Wrong combinations 404 and are dropped by the probe loop.
			for _, prefix := range prefixes {
				fullPath := "/" + prefix + trimmed
				if !seen[fullPath] {
					seen[fullPath] = true
					paths = append(paths, fullPath)
				}
			}
		}
	}

	// These Strategy numbers are local; they do not match the sub-numbering in
	// extractServicePrefixes.

	// Strategy 1: quoted API paths.
	for _, match := range apiPathPattern.FindAllSubmatch(jsBody, -1) {
		if len(match) >= 2 {
			addPath(string(match[1]))
		}
	}

	// Strategy 2a: template literals with ${...}.
	for _, p := range extractTemplateLiteralPaths(jsBody) {
		addPath(p)
	}

	// Strategy 2b: template literals without interpolation.
	for _, match := range templateLiteralPattern.FindAllSubmatch(jsBody, -1) {
		if len(match) >= 2 {
			addPath(string(match[1]))
		}
	}

	// Strategy 3: full URLs.
	for _, match := range fullURLPattern.FindAllSubmatch(jsBody, -1) {
		if len(match) >= 2 {
			addPath(string(match[1]))
		}
	}

	// Strategy 5: .concat() and `+` chains (LAB-1368). Last, so the more precise
	// strategies win the dedup race. Strategy 4, literal+literal prefix concat,
	// has no block of its own — extractServicePrefixes plus the addPath fan-out
	// above does it.
	for _, p := range extractConcatPaths(jsBody) {
		addPath(p)
	}

	return paths
}

// --- Main pipeline ---

// ReplayJSExtracted extracts API paths from captured JS bodies, probes them over
// raw HTTP, and appends what answers to the returned slice.
//
// It exists because a headless crawl cannot exercise paths that need user
// interaction or auth state, or that jsluice cannot resolve; raw HTTP also
// bypasses SPA catch-all routing. Defenses are in the file header.
func ReplayJSExtracted(ctx context.Context, requests []ObservedRequest, cfg JSReplayConfig) []ObservedRequest { //nolint:gocyclo // top-level JS extraction orchestration
	cfg = cfg.withDefaults()

	logf := func(format string, args ...interface{}) {
		if cfg.Verbose {
			fmt.Fprintf(cfg.Stderr, format, args...) //nolint:errcheck // debug logging to stderr
		}
	}
	warnf := func(format string, args ...interface{}) {
		fmt.Fprintf(cfg.Stderr, format, args...) //nolint:errcheck // operator-facing warning
	}

	// Origin priority: cfg.TargetURL, then the first HTML response, then the first
	// URL. HTML wins over first-entry because an imported mixed-origin capture may
	// open with a CDN font or analytics beacon, and binding to that leaves the
	// app's own bundles cross-origin and skipped (LAB-3892).
	targetOrigin := originOf(cfg.TargetURL)
	if targetOrigin == "" {
		targetOrigin = firstHTMLOrigin(requests)
	}
	if targetOrigin == "" {
		for _, req := range requests {
			if req.URL != "" {
				targetOrigin = originOf(req.URL)
				if targetOrigin != "" {
					break
				}
			}
		}
	}
	if targetOrigin == "" {
		return requests
	}

	if cfg.TargetURL == "" {
		warnDerivedOrigin(cfg.Stderr, targetOrigin, len(cfg.Headers) > 0)
	}

	loopCtx, cancel := context.WithTimeout(ctx, cfg.MaxTotalTime)
	defer cancel()

	// Parsed here rather than reused from the crawl because Katana mangles
	// relative JS paths when resolving them against SPA routes.
	htmlJSURLs := make(map[string]bool)
	for _, req := range requests {
		body := req.Response.Body
		if len(body) == 0 {
			continue
		}
		if !isHTMLResponse(req.Response.ContentType) && !looksLikeHTML(body) {
			continue
		}
		for _, jsURL := range extractScriptURLs(body, req.URL) {
			htmlJSURLs[jsURL] = true
		}
	}
	if len(htmlJSURLs) > 0 {
		logf("js-extract: discovered %d JS URLs from HTML <script> tags\n", len(htmlJSURLs))
		for u := range htmlJSURLs {
			logf("  %s\n", sanitizeForLog(u))
		}
	}

	allPaths := make(map[string]bool)
	processedJSURLs := make(map[string]bool)

	processJS := func(jsURL string, jsBody []byte) {
		paths := extractAPIPaths(jsBody, requests)
		logf("js-extract: extracted %d API paths from %s\n", len(paths), sanitizeForLog(jsURL))
		for _, p := range paths {
			logf("  %s\n", sanitizeForLog(p))
		}
		for _, p := range paths {
			allPaths[p] = true
		}
	}

	for _, req := range requests {
		if !isJSURL(req.URL) && !isJSResponse(req.Response.ContentType) {
			continue
		}
		processedJSURLs[req.URL] = true
		logf("js-extract: found JS file %s (ct=%s, body=%d bytes)\n",
			sanitizeForLog(req.URL), sanitizeForLog(req.Response.ContentType), len(req.Response.Body))

		jsBody := req.Response.Body

		// Katana often reports a JS URL with no body, and the crawl truncates at
		// MaxResponseBodySize, past which API paths are invisible.
		if len(jsBody) == 0 || len(jsBody) >= MaxResponseBodySize {
			if len(jsBody) == 0 {
				logf("js-extract: empty body, fetching %s\n", sanitizeForLog(req.URL))
			} else {
				logf("js-extract: body truncated at %d bytes, re-fetching %s\n",
					MaxResponseBodySize, sanitizeForLog(req.URL))
			}
			fullBody := fetchJSBody(loopCtx, cfg, req.URL, targetOrigin)
			if fullBody != nil {
				jsBody = fullBody
				logf("js-extract: fetched %d bytes from %s\n", len(jsBody), sanitizeForLog(req.URL))
			}
		}

		if len(jsBody) == 0 {
			logf("js-extract: skipping %s (empty body after fetch attempt)\n", sanitizeForLog(req.URL))
			continue
		}

		processJS(req.URL, jsBody)
	}

	for jsURL := range htmlJSURLs {
		if processedJSURLs[jsURL] {
			continue
		}
		processedJSURLs[jsURL] = true
		logf("js-extract: fetching HTML-discovered JS %s\n", sanitizeForLog(jsURL))
		jsBody := fetchJSBody(loopCtx, cfg, jsURL, targetOrigin)
		if jsBody == nil {
			logf("js-extract: skipping %s (fetch failed)\n", sanitizeForLog(jsURL))
			continue
		}
		logf("js-extract: fetched %d bytes from %s\n", len(jsBody), sanitizeForLog(jsURL))
		processJS(jsURL, jsBody)
	}

	logf("js-extract: %d unique API paths found across all JS files\n", len(allPaths))

	if len(allPaths) == 0 {
		return requests
	}

	// Without sorting, MaxEndpoints truncation probes a different set every run.
	sortedPaths := make([]string, 0, len(allPaths))
	for p := range allPaths {
		sortedPaths = append(sortedPaths, p)
	}
	sort.Strings(sortedPaths)

	result := make([]ObservedRequest, len(requests))
	copy(result, requests)

	probed := 0
	for _, path := range sortedPaths {
		if probed >= cfg.MaxEndpoints {
			break
		}

		fullURL := path
		if !strings.HasPrefix(path, "http://") && !strings.HasPrefix(path, "https://") {
			fullURL = targetOrigin + path
		}

		// doRequest deliberately re-derives this for header forwarding instead of
		// taking it, so forwarding cannot be widened by this loop's control flow.
		// Do not collapse the two; keep them in sync. Pinned by
		// TestReplayJSExtracted_DoesNotForwardHeadersCrossOrigin.
		sameOrigin := isSameOrigin(fullURL, targetOrigin)

		// Skipped URLs must NOT consume the MaxEndpoints budget, or an attacker
		// salts the bundle with cross-origin URLs to suppress real discovery.
		if !cfg.AllowCrossOrigin && !sameOrigin {
			warnf("js-extract: skipping cross-origin URL %s (use AllowCrossOrigin to allow)\n",
				sanitizeForLog(fullURL))
			continue
		}

		// loopCtx, so a bundle full of black-holed hostnames cannot stall
		// validation past MaxTotalTime. Skips do not consume the budget.
		if !cfg.AllowPrivate {
			if err := ssrf.ValidateURLContext(loopCtx, fullURL); err != nil {
				warnf("js-extract: skipping %s: %v\n", sanitizeForLog(fullURL), err)
				continue
			}
		}

		probed++

		resp := probeURL(loopCtx, cfg, fullURL, targetOrigin)
		if resp == nil {
			continue
		}

		// 404 means a wrong prefix combination; keeping them pollutes the spec
		// with endpoints that do not exist.
		if resp.StatusCode == http.StatusNotFound {
			continue
		}

		// Snapshot per result: cfg.Headers is shared, and recorded headers must
		// reflect what the wire carried — empty for cross-origin probes.
		var recorded map[string]string
		if sameOrigin {
			recorded = copyHeaders(cfg.Headers)
		}

		result = append(result, ObservedRequest{
			Method:   "GET",
			URL:      fullURL,
			Headers:  recorded,
			Response: *resp,
			Source:   "js-extract",
		})
	}

	if probed >= cfg.MaxEndpoints && len(sortedPaths) > cfg.MaxEndpoints {
		warnf("js-extract: warning: probed %d/%d discovered paths (MaxEndpoints limit reached; raise MaxEndpoints to scan more)\n",
			probed, len(sortedPaths))
	}

	return result
}

// --- HTTP helpers ---

// jsExtractUserAgent lets destinations attribute the traffic. No version, so it
// cannot drift from the binary.
const jsExtractUserAgent = "vespasian-js-extract"

// doRequest GETs rawURL. cfg.Headers attach only same-origin, independent of
// AllowCrossOrigin. The caller MUST call the returned cleanup.
func doRequest(ctx context.Context, cfg JSReplayConfig, rawURL, targetOrigin string) (*http.Response, func(), error) {
	reqCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, rawURL, nil)
	if err != nil {
		cancel()
		return nil, func() {}, err
	}

	// Set before cfg.Headers so an operator --header User-Agent overrides it.
	req.Header.Set("User-Agent", jsExtractUserAgent)

	// Never send Authorization / Cookie / X-API-Key off-target, even when
	// AllowCrossOrigin allowed the probe. Re-derived rather than passed in so a
	// caller's gating mistake cannot widen forwarding. Pinned by
	// TestReplayJSExtracted_DoesNotForwardHeadersCrossOrigin.
	if isSameOrigin(rawURL, targetOrigin) {
		for k, v := range cfg.Headers {
			req.Header.Set(k, v)
		}
	}

	resp, err := cfg.Client.Do(req) //nolint:gosec // G704: intentional outbound request to discovered URL
	if err != nil {
		cancel()
		return nil, func() {}, err
	}

	cleanup := func() {
		// Bounded drain so the connection can be reused. Errors ignored: the
		// response is discarded either way.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)) //nolint:errcheck,gosec // best-effort drain
		_ = resp.Body.Close()                                       //nolint:errcheck,gosec // best-effort close
		cancel()
	}
	return resp, cleanup, nil
}

// maxJSRedirects: production CDNs chain 1-2 (versioned to immutable URL); 5
// matches browser behavior.
const maxJSRedirects = 5

// fetchJSBody re-fetches a JS file under maxJSBodySize. nil on error, HTML (SPA
// catch-all), or unreadable. Off-origin skipped unless AllowCrossOrigin.
//
// The shared client refuses redirects, so 3xx are followed here — every hop
// re-validated against the same-origin gate and SSRF, or a malicious JS URL
// redirects into a private destination.
func fetchJSBody(ctx context.Context, cfg JSReplayConfig, rawURL, targetOrigin string) []byte {
	// hop 0 is the initial fetch, so <= permits one request plus maxJSRedirects
	// follows.
	for hop := 0; hop <= maxJSRedirects; hop++ {
		if !canFetchURL(ctx, cfg, rawURL, targetOrigin) {
			return nil
		}
		body, redirectTo, terminal := fetchJSBodyHop(ctx, cfg, rawURL, targetOrigin)
		if terminal {
			return body
		}
		if redirectTo == "" || hop == maxJSRedirects {
			return nil
		}
		rawURL = redirectTo
	}
	return nil
}

// canFetchURL gates on same-origin and SSRF before any request is issued.
func canFetchURL(ctx context.Context, cfg JSReplayConfig, rawURL, targetOrigin string) bool {
	// Re-fetching cross-origin scripts makes Vespasian a CDN reflector for the
	// bundle author.
	if !cfg.AllowCrossOrigin && !isSameOrigin(rawURL, targetOrigin) {
		return false
	}
	if !cfg.AllowPrivate {
		if err := ssrf.ValidateURLContext(ctx, rawURL); err != nil {
			return false
		}
	}
	return true
}

// fetchJSBodyHop returns (body, "", true) when terminal, or
// (nil, next, false) when the caller should follow a 3xx.
func fetchJSBodyHop(ctx context.Context, cfg JSReplayConfig, rawURL, targetOrigin string) (body []byte, redirectTo string, terminal bool) {
	resp, cleanup, err := doRequest(ctx, cfg, rawURL, targetOrigin)
	if err != nil {
		return nil, "", true
	}
	defer cleanup()

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		loc := resp.Header.Get("Location")
		if loc == "" {
			return nil, "", true
		}
		next, err := resolveRedirect(rawURL, loc)
		if err != nil {
			return nil, "", true
		}
		return nil, next, false
	}

	if resp.StatusCode >= 400 {
		return nil, "", true
	}

	// HTML means an SPA catch-all served index.html for an unknown path.
	if isHTMLResponse(resp.Header.Get("Content-Type")) {
		return nil, "", true
	}

	read, err := io.ReadAll(io.LimitReader(resp.Body, maxJSBodySize))
	if err != nil {
		return nil, "", true
	}

	// Same, for servers that set no Content-Type.
	if len(read) > 0 && looksLikeHTML(read) {
		return nil, "", true
	}

	return read, "", true
}

// resolveRedirect resolves Location against currentURL. An empty Location would
// return currentURL unchanged per url.ResolveReference, but fetchJSBody rejects
// those before calling, so that case is documentary.
func resolveRedirect(currentURL, location string) (string, error) {
	cur, err := url.Parse(currentURL)
	if err != nil {
		return "", err
	}
	loc, err := url.Parse(location)
	if err != nil {
		return "", err
	}
	return cur.ResolveReference(loc).String(), nil
}

// looksLikeHTML sniffs the leading bytes for a doctype or <html>.
func looksLikeHTML(body []byte) bool {
	trimmed := bytes.TrimLeft(body, " \t\r\n\xef\xbb\xbf")
	if len(trimmed) == 0 {
		return false
	}
	lower := bytes.ToLower(trimmed[:min(len(trimmed), 50)])
	return bytes.HasPrefix(lower, []byte("<!doctype")) ||
		bytes.HasPrefix(lower, []byte("<html"))
}

func probeURL(ctx context.Context, cfg JSReplayConfig, rawURL, targetOrigin string) *ObservedResponse {
	resp, cleanup, err := doRequest(ctx, cfg, rawURL, targetOrigin)
	if err != nil {
		return nil
	}
	defer cleanup()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxReplayBodySize))
	if err != nil {
		return nil
	}

	return &ObservedResponse{
		StatusCode:  resp.StatusCode,
		Headers:     flattenHeaders(resp.Header),
		ContentType: resp.Header.Get("Content-Type"),
		Body:        body,
	}
}

// flattenHeaders keeps the first value per key.
func flattenHeaders(h http.Header) map[string]string {
	result := make(map[string]string, len(h))
	for k, vals := range h {
		if len(vals) > 0 {
			result[k] = vals[0]
		}
	}
	return result
}
