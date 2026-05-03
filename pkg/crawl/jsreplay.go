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

// JS replay threat model:
//
// ReplayJSExtracted issues outbound HTTP requests to URLs derived from the
// target SPA's JavaScript bundles. Those bundles are attacker-controlled
// when the target is hostile, so this code treats every extracted URL as
// untrusted input and applies three defenses:
//
//  1. Same-origin gate: by default, only URLs whose scheme/host/port match
//     the scan target are probed and only those requests carry the user's
//     headers (e.g., Authorization). AllowCrossOrigin opts out for
//     trusted-tenant scans.
//  2. SSRF validation: every URL is checked against ssrf.ValidateURL
//     and the underlying transport uses ssrf.SafeDialContext to defeat
//     DNS rebinding. AllowPrivate disables both for explicit local testing.
//  3. Bounded execution: MaxEndpoints caps probe attempts (not just results)
//     and MaxTotalTime caps wall-clock time across the whole step.

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

	"github.com/praetorian-inc/vespasian/pkg/ssrf"
)

// JSReplayConfig configures the JS API path extraction and probing step.
type JSReplayConfig struct {
	// Headers are injected into probe requests that target the same origin
	// as the scan target (e.g., Authorization). They are NOT forwarded to
	// cross-origin URLs unless AllowCrossOrigin is true.
	Headers map[string]string

	// TargetURL is the scan's intended target. It is used to derive the
	// same-origin host for header forwarding and probe filtering. If
	// empty, the first non-empty request URL is used as a fallback.
	TargetURL string

	// AllowPrivate disables SSRF protection (ValidateProbeURL and
	// SSRFSafeDialContext). Mirrors --dangerous-allow-private.
	AllowPrivate bool

	// AllowCrossOrigin allows probing and JS-fetching of URLs whose origin
	// does not match the scan target. Default false: cross-origin URLs are
	// skipped to avoid using Vespasian as a request reflector and to avoid
	// leaking auth headers. Even when AllowCrossOrigin is true, user-supplied
	// Headers are NEVER forwarded to off-origin destinations — the same-origin
	// gate on Headers is independent of AllowCrossOrigin and only relaxed by
	// using a different scan target. Enabling this exposes the operator's IP
	// to attacker-chosen hosts (subject to SSRF and MaxEndpoints) and is
	// appropriate only for trusted-tenant or multi-host scans.
	AllowCrossOrigin bool

	// Timeout is the per-request timeout. Defaults to 10 seconds.
	Timeout time.Duration

	// MaxTotalTime caps the wall-clock time of the whole replay step.
	// Defaults to MaxEndpoints * Timeout, capped at 10 minutes.
	MaxTotalTime time.Duration

	// MaxEndpoints limits the number of probe attempts (successful or not).
	// Defaults to 500.
	MaxEndpoints int

	// Client is the HTTP client. If nil, a default client is created with
	// SSRF-safe transport when !AllowPrivate.
	Client *http.Client

	// Verbose enables debug logging to Stderr.
	Verbose bool

	// Stderr is the writer for debug output. Defaults to io.Discard.
	// Warnings (cap reached, cross-origin skipped) are emitted regardless
	// of Verbose, but still go to this writer.
	Stderr io.Writer
}

const (
	// defaultMaxEndpoints is the default cap on probe attempts.
	defaultMaxEndpoints = 500

	// defaultTimeout is the default per-request timeout.
	defaultTimeout = 10 * time.Second

	// maxTotalTimeCap caps MaxTotalTime regardless of MaxEndpoints*Timeout.
	maxTotalTimeCap = 10 * time.Minute
)

// withDefaults fills in zero-value fields with sensible defaults and installs
// an SSRF-safe HTTP transport when AllowPrivate is false.
func (cfg JSReplayConfig) withDefaults() JSReplayConfig {
	if cfg.Timeout == 0 {
		cfg.Timeout = defaultTimeout
	}
	if cfg.MaxEndpoints == 0 {
		cfg.MaxEndpoints = defaultMaxEndpoints
	}
	if cfg.MaxTotalTime == 0 {
		// Worst-case: every probe times out. Cap at maxTotalTimeCap to
		// keep predictable wall-clock behavior even with large MaxEndpoints.
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
		// Caller supplied a client. SSRF-wrap when AllowPrivate is false,
		// and always enforce our redirect policy: probeURL records the
		// status we asked for (no auto-follow), and fetchJSBody follows
		// 3xx manually with bounded depth + per-hop SSRF/same-origin
		// re-validation.
		if !cfg.AllowPrivate {
			cfg.Client = wrapClientWithSSRF(cfg.Client, cfg.Timeout, cfg.Stderr)
		} else {
			// AllowPrivate path: still need a copy so we don't mutate the
			// caller's CheckRedirect.
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

// noRedirect is the redirect policy used by ReplayJSExtracted's HTTP client.
// It causes Go's http.Client to return 3xx responses verbatim instead of
// auto-following them; probeURL needs the actual response from the URL we
// asked for, and fetchJSBody manages its own bounded redirect-follow loop.
func noRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

// wrapClientWithSSRF returns a copy of caller with its transport replaced by
// a clone that has ssrf.SafeDialContext installed. We never mutate the
// caller's *http.Client or *http.Transport: doing so would silently change
// the dial behavior of every other holder of those pointers (a logging
// middleware, a connection-pool, a test harness). Instead:
//
//   - *http.Transport: cloned, then SafeDialContext installed on the clone.
//   - nil Transport: replaced with a clone of the well-tuned default
//     transport (which carries TLSHandshakeTimeout/IdleConnTimeout/etc.)
//     plus SafeDialContext.
//   - any other RoundTripper (logging/retry/recording middleware, custom
//     transport): we cannot wrap the dialer, so we leave the transport
//     alone and emit a warning to stderr — pre-dial ssrf.ValidateURLContext
//     remains the only line of defense for this caller (which is still a
//     correct SSRF guard in default config but loses the DNS-rebinding
//     mitigation that the dial-time check provides).
//
// Timeout is set on the returned client copy if the caller left it unset,
// so a slow-loris response body cannot stall the replay loop indefinitely.
func wrapClientWithSSRF(caller *http.Client, timeout time.Duration, stderr io.Writer) *http.Client {
	clone := *caller // shallow copy — we'll only mutate the local clone
	switch t := caller.Transport.(type) {
	case *http.Transport:
		tc := t.Clone()
		tc.DialContext = ssrf.SafeDialContext
		clone.Transport = tc
	case nil:
		// Build a fresh transport with sensible defaults rather than a
		// bare &http.Transport{}; reuse the same construction path as
		// the no-client case.
		clone.Transport = newSSRFSafeClient(timeout, false).Transport
	default:
		fmt.Fprintf(stderr, //nolint:errcheck // best-effort warning
			"js-extract: warning: caller-supplied http.Client.Transport is %T (not *http.Transport); "+
				"dial-time SSRF protection cannot be installed and DNS rebinding remains possible. "+
				"pre-dial ssrf.ValidateURLContext still blocks the default attack path.\n", t)
	}
	if clone.Timeout == 0 {
		clone.Timeout = timeout
	}
	return &clone
}

// newSSRFSafeClient builds the default *http.Client used by ReplayJSExtracted.
// It clones DefaultTransport, optionally swaps DialContext for ssrf.SafeDialContext,
// installs a per-request timeout, and refuses to follow redirects so probe
// results record the actual response from the URL we asked for.
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

// maxReplayBodySize limits response body reads during probing (1 MB).
const maxReplayBodySize = 1 << 20

// maxJSBodySize limits the JS body read for API path extraction (10 MB).
// This is intentionally larger than MaxResponseBodySize (1 MB) used during crawl,
// because SPA JS bundles are often >1 MB and the API paths may be past the
// crawl truncation point.
const maxJSBodySize = 10 << 20

// jsContentTypes identifies JavaScript response content types.
var jsContentTypes = []string{
	"application/javascript",
	"text/javascript",
	"application/x-javascript",
}

// htmlContentTypes identifies HTML response content types.
var htmlContentTypes = []string{
	"text/html",
	"application/xhtml+xml",
}

// matchesContentType reports whether contentType (with optional ;charset
// parameters) matches any entry in types. Comparison is case-insensitive.
func matchesContentType(contentType string, types []string) bool {
	ct := strings.ToLower(contentType)
	if idx := strings.Index(ct, ";"); idx != -1 {
		ct = strings.TrimSpace(ct[:idx])
	}
	for _, t := range types {
		if ct == t {
			return true
		}
	}
	return false
}

// isHTMLResponse reports whether the response content type indicates HTML.
func isHTMLResponse(contentType string) bool {
	return matchesContentType(contentType, htmlContentTypes)
}

// isJSResponse reports whether the response content type indicates JavaScript.
func isJSResponse(contentType string) bool {
	return matchesContentType(contentType, jsContentTypes)
}

// scriptSrcPattern extracts src attributes from <script> tags in HTML.
// We deliberately accept any src value (not just *.js / *.mjs) so cache-
// busted URLs like /main.js?v=123 or /chunk.abc.js#sourcemap are caught;
// the resolved URL is filtered through isJSURL afterwards.
var scriptSrcPattern = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+)["']`)

// extractScriptURLs parses HTML for <script src="..."> tags and resolves
// them against the page URL to produce absolute JS file URLs. Non-JS srcs
// (e.g., importmaps, JSON modules) are dropped via the isJSURL filter.
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
// Regex extraction is inherently lossy: it cannot distinguish a real path
// literal from a comment, an error string, or a locale message that happens
// to contain "/api/...". False positives are expected and handled at probe
// time by the 404 filter (probe loop in ReplayJSExtracted) — wrong paths
// return 404 from the target and are dropped before being appended to the
// result. The MaxEndpoints cap bounds the cost of false positives.

// apiPathPattern matches API-like path strings in single/double-quoted JS strings.
// Captures paths containing /api/, /v1/, /v2/, /rest/, /rpc/, /graphql.
var apiPathPattern = regexp.MustCompile(
	`["']` +
		`(/?` +
		`(?:[a-zA-Z0-9_-]+/)*` +
		`(?:api/|v[1-9][0-9]*/|rest/|rpc/|graphql)` +
		`[a-zA-Z0-9/_\{}.:-]*)` +
		`["']`,
)

// templateLiteralPattern matches API-like paths in JS template literals (backticks).
// This is a fallback for simple cases without ${...} interpolation; richer
// reconstruction (preserving the literal segments around interpolations) is
// handled by extractTemplateLiteralPaths below.
var templateLiteralPattern = regexp.MustCompile(
	"`" +
		`(/?` +
		`(?:[a-zA-Z0-9_-]+/)*` +
		`(?:api/|v[1-9][0-9]*/|rest/|rpc/|graphql)` +
		`[a-zA-Z0-9/_\{}.:-]*)` +
		"`",
)

// fullURLPattern matches full API URLs (http/https) in JS strings.
// E.g., "https://api.example.com/v1/users"
var fullURLPattern = regexp.MustCompile(
	`["'` + "`]" +
		`(https?://[a-zA-Z0-9._-]+(?::[0-9]+)?` +
		`/(?:[a-zA-Z0-9_-]+/)*` +
		`(?:api/|v[1-9][0-9]*/|rest/|rpc/|graphql)` +
		`[a-zA-Z0-9/_\{}.:-]*)` +
		`["'` + "`]",
)

// servicePrefixPattern matches service prefix strings concatenated with API paths
// using the `+` operator between two QUOTED string literals.
// E.g., "identity/" + "api/auth/login" — captures "identity/".
//
// Note: backtick template literal concatenations are not matched (use
// extractTemplateLiteralPaths for those). String.prototype.concat() —
// e.g. "/api/posts/".concat(id, "/comment") — is intentionally out of
// scope (see LAB-1368 for follow-up).
var servicePrefixPattern = regexp.MustCompile(
	`["']([a-zA-Z][a-zA-Z0-9_-]{1,30}/)["']\s*\+\s*["'](?:api/|v[1-9])`,
)

// apiIndicators are the path segments that signal an API endpoint.
//
// MAINTENANCE: this list is duplicated by hand inside apiPathPattern,
// templateLiteralPattern, and fullURLPattern above (the regex alternation
// `api/|v[1-9][0-9]*/|rest/|rpc/|graphql`). When adding a new indicator,
// update both this slice AND the three regex literals — they are required
// to stay in sync.
var apiIndicators = []string{"api/", "v1/", "v2/", "v3/", "v4/", "rest/", "rpc/", "graphql"}

// staticFileExts are file extensions to skip when extracting API paths.
var staticFileExts = []string{".js", ".css", ".map", ".html", ".htm", ".png", ".jpg", ".svg"}

// --- Helper functions ---

// isJSURL reports whether the URL path ends with a JavaScript file extension.
func isJSURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	lower := strings.ToLower(u.Path)
	return strings.HasSuffix(lower, ".js") || strings.HasSuffix(lower, ".mjs")
}

// isStaticFile reports whether a path looks like a static file reference.
func isStaticFile(path string) bool {
	lower := strings.ToLower(path)
	for _, ext := range staticFileExts {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

// hasAPIIndicator reports whether the path contains a known API indicator.
func hasAPIIndicator(path string) bool {
	lower := strings.ToLower(path)
	for _, indicator := range apiIndicators {
		if strings.Contains(lower, indicator) {
			return true
		}
	}
	return false
}

// hasInlinePrefix reports whether the path has a non-API segment before the
// first API indicator, meaning it already contains a service prefix
// (e.g., "identity/api/..." or "community/v2/...").
// Paths like "api/v2/users" do NOT have an inline prefix — "api/" before "v2/"
// is itself an API indicator, not a service prefix.
func hasInlinePrefix(trimmedPath string) bool {
	// Find the earliest API indicator in the path.
	earliest := -1
	for _, indicator := range apiIndicators {
		idx := strings.Index(trimmedPath, indicator)
		if idx >= 0 && (earliest < 0 || idx < earliest) {
			earliest = idx
		}
	}
	// If the first API indicator is not at the start, there's a prefix before it.
	return earliest > 0
}

// resolveBaseURL extracts the scheme and host from a target URL.
func resolveBaseURL(targetURL string) string {
	u, err := url.Parse(targetURL)
	if err != nil {
		return targetURL
	}
	return u.Scheme + "://" + u.Host
}

// originOf returns the scheme://host[:port] origin of rawURL, or "" if it
// cannot be parsed or has no host.
func originOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// isSameOrigin reports whether rawURL has the same origin as targetOrigin.
// targetOrigin should already be in scheme://host[:port] form.
func isSameOrigin(rawURL, targetOrigin string) bool {
	if targetOrigin == "" {
		return false
	}
	return originOf(rawURL) == targetOrigin
}

// sanitizeForLog escapes terminal control characters and other non-printable
// bytes so an attacker-controlled string from a JS bundle cannot inject ANSI
// sequences or NUL bytes when emitted to the operator's terminal.
func sanitizeForLog(s string) string {
	if s == "" {
		return s
	}
	// strconv.Quote escapes control chars, non-printable bytes, and quotes;
	// it returns a Go-quoted string, which is safe to render verbatim.
	return strconv.Quote(s)
}

// copyHeaders returns a defensive copy of h to avoid sharing the caller's
// map across recorded ObservedRequest values.
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

// validateFullURL is a parse-time canonicalization that rejects URLs with
// embedded credentials, non-http(s) schemes, or empty hosts. It returns the
// canonicalized URL on success. SSRF screening (blocklist + DNS) is layered
// separately at probe time via ssrf.ValidateURL — callers MUST run that
// before issuing any request, since validateFullURL alone does not reject
// URLs whose Host is a private IP literal.
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
	if u.User != nil {
		// Reject embedded credentials (http://user:pass@host/...) — the
		// JS bundle can otherwise force Vespasian to send arbitrary basic
		// auth on the operator's behalf.
		return "", false
	}
	return u.String(), true
}

// --- Extraction logic ---

// extractServicePrefixes discovers service prefix strings using two strategies:
//
//  1. JS concatenation pattern: "identity/" + "api/auth/login"
//  2. Crawl results: Katana extracts prefix strings from JS and resolves them
//     relative to the JS file URL, producing URLs like /static/js/identity/.
//     These are identified by matching crawl results whose source is a JS file
//     and whose URL is a single segment appended to the JS file's directory.
func extractServicePrefixes(jsBody []byte, requests []ObservedRequest) []string { //nolint:gocyclo // multi-strategy prefix discovery
	seen := make(map[string]bool)
	var prefixes []string

	add := func(prefix string) {
		if !seen[prefix] {
			seen[prefix] = true
			prefixes = append(prefixes, prefix)
		}
	}

	// Strategy 1: JS concatenation pattern ("prefix/" + "api/...").
	for _, match := range servicePrefixPattern.FindAllSubmatch(jsBody, -1) {
		if len(match) >= 2 {
			add(string(match[1]))
		}
	}

	// Strategy 2: Crawl results — find URLs extracted from JS files that are
	// a single path segment appended to the JS directory (e.g., /static/js/identity/).
	jsURLs := make(map[string]bool)
	for _, req := range requests {
		if isJSURL(req.URL) {
			jsURLs[req.URL] = true
		}
	}

	for _, req := range requests {
		// Only consider results sourced from a JS file.
		if !isJSURL(req.Source) {
			continue
		}
		if !jsURLs[req.Source] {
			continue
		}

		// Parse both URLs to compare paths.
		srcURL, err1 := url.Parse(req.Source)
		reqURL, err2 := url.Parse(req.URL)
		if err1 != nil || err2 != nil {
			continue
		}

		// Get the JS file's directory and the request path.
		jsDir := srcURL.Path[:strings.LastIndex(srcURL.Path, "/")+1]
		reqPath := reqURL.Path

		// Check if reqPath is jsDir + "word/" (single segment under JS directory).
		if !strings.HasPrefix(reqPath, jsDir) {
			continue
		}
		suffix := strings.TrimPrefix(reqPath, jsDir)
		suffix = strings.TrimSuffix(suffix, "/")

		// Must be a single non-empty segment (no slashes, no dots).
		if suffix == "" || strings.Contains(suffix, "/") || strings.Contains(suffix, ".") {
			continue
		}

		// Must be a reasonable service name (lowercase alpha, short).
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

	return prefixes
}

// extractTemplateLiteralPaths walks each backtick-delimited template literal
// and reconstructs the literal segments around ${...} interpolations into
// path templates with {param}-style placeholders.
//
// The walker is interpolation-aware: backticks that appear inside a `${...}`
// expression are treated as nested template literals (their own opening/closing
// backticks) rather than as a closing delimiter for the outer literal. Without
// this, `outer ${`inner`}` would be mispaired and produce garbled output.
//
// E.g., `/api/users/${id}/profile` -> /api/users/{param}/profile
func extractTemplateLiteralPaths(jsBody []byte) []string {
	var paths []string
	for i := 0; i < len(jsBody); i++ {
		if jsBody[i] != '`' {
			continue
		}
		// Found an opening backtick. Find the matching closing backtick at
		// the same nesting level.
		end := findTemplateLiteralEnd(jsBody, i+1)
		if end < 0 {
			break // unterminated literal — bail out of the whole scan
		}
		segment := jsBody[i+1 : end]
		if path, ok := reconstructTemplateLiteral(segment); ok {
			paths = append(paths, path)
		}
		i = end // resume scanning after the closing backtick
	}
	return paths
}

// findTemplateLiteralEnd returns the index of the closing backtick that
// matches the opening backtick before `start`, walking past `${...}`
// interpolations and any nested template literals inside them. Returns -1
// if no matching backtick is found.
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
		// We're inside a ${...} expression. Skip nested template literals
		// recursively so their backticks don't close the outer one.
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

// reconstructTemplateLiteral converts a single template literal body (the
// text between two backticks) into a path string by replacing ${...}
// interpolations with {param} placeholders. It returns the path and true if
// it contains an API indicator and looks path-like, otherwise empty/false.
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
		// Inside ${...}: consume until matching closing brace.
		switch c {
		case '{':
			depth++
		case '}':
			depth--
		}
	}
	candidate := b.String()
	// Trim non-path noise from each end. Template literals embed paths in
	// expressions like ` + path + `; we want only the path-like core.
	candidate = strings.TrimSpace(candidate)
	if !strings.HasPrefix(candidate, "/") && !strings.HasPrefix(candidate, "http://") && !strings.HasPrefix(candidate, "https://") {
		// Look for the first slash and trim before it.
		if idx := strings.Index(candidate, "/"); idx > 0 {
			candidate = candidate[idx:]
		}
	}
	if candidate == "" || !hasAPIIndicator(candidate) {
		return "", false
	}
	// Reject candidates with embedded whitespace (likely not a single path).
	if strings.ContainsAny(candidate, " \t\r\n") {
		return "", false
	}
	return candidate, true
}

// extractAPIPaths scans JavaScript source code for API path patterns using
// multiple extraction strategies:
//  1. Single/double-quoted strings containing API indicators
//  2. Template literals (backticks), including ${...} interpolations
//  3. Full URLs (http/https) pointing to API endpoints
//  4. Service prefix concatenation (e.g., "identity/" + "api/auth/login")
//
// Returns deduplicated path strings. Paths with discovered service prefixes
// are expanded; already-prefixed and full-URL paths are kept as-is.
func extractAPIPaths(jsBody []byte, requests []ObservedRequest) []string { //nolint:gocyclo // multi-strategy path extraction
	prefixes := extractServicePrefixes(jsBody, requests)

	seen := make(map[string]bool)
	var paths []string

	addPath := func(raw string) {
		if isStaticFile(raw) {
			return
		}

		// Full URLs are kept as-is (they include scheme+host) after a
		// defense-in-depth validation pass that rejects credentials,
		// non-http(s) schemes, and empty hosts.
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

		// Normalize: ensure leading slash, trim trailing slash.
		if !strings.HasPrefix(raw, "/") {
			raw = "/" + raw
		}
		raw = strings.TrimRight(raw, "/")
		if raw == "" {
			return
		}

		trimmed := strings.TrimPrefix(raw, "/")

		// Check if path already has a known service prefix.
		knownPrefix := false
		for _, prefix := range prefixes {
			if strings.HasPrefix(trimmed, prefix) {
				knownPrefix = true
				break
			}
		}

		// Check if path has an inline prefix (segment before API indicator).
		if knownPrefix || hasInlinePrefix(trimmed) || len(prefixes) == 0 {
			if !seen[raw] {
				seen[raw] = true
				paths = append(paths, raw)
			}
		} else {
			// No prefix — combine with each discovered service prefix.
			// Wrong combinations will return 404/HTML and get filtered by the classifier.
			for _, prefix := range prefixes {
				fullPath := "/" + prefix + trimmed
				if !seen[fullPath] {
					seen[fullPath] = true
					paths = append(paths, fullPath)
				}
			}
		}
	}

	// Strategy 1: Single/double-quoted API paths.
	for _, match := range apiPathPattern.FindAllSubmatch(jsBody, -1) {
		if len(match) >= 2 {
			addPath(string(match[1]))
		}
	}

	// Strategy 2a: Template literal API paths (with ${...} reconstruction).
	for _, p := range extractTemplateLiteralPaths(jsBody) {
		addPath(p)
	}

	// Strategy 2b: Simple template literal pattern fallback.
	for _, match := range templateLiteralPattern.FindAllSubmatch(jsBody, -1) {
		if len(match) >= 2 {
			addPath(string(match[1]))
		}
	}

	// Strategy 3: Full URL API paths.
	for _, match := range fullURLPattern.FindAllSubmatch(jsBody, -1) {
		if len(match) >= 2 {
			addPath(string(match[1]))
		}
	}

	return paths
}

// --- Main pipeline ---

// ReplayJSExtracted scans JavaScript response bodies from crawl results for
// API path patterns, then probes those paths with raw HTTP requests to obtain
// actual API responses. Discovered endpoints are appended to the returned slice.
//
// This addresses a fundamental limitation of headless browser crawling for SPAs:
// JavaScript bundles contain API path strings that the headless browser cannot
// exercise (they require user interactions, authentication state, or are string
// concatenations that jsluice cannot resolve). By regex-extracting these paths
// from the JS body and probing them directly with raw HTTP, we bypass both the
// SPA catch-all routing and jsluice's static analysis limitations.
//
// Security defenses are described in the file-level comment block.
func ReplayJSExtracted(ctx context.Context, requests []ObservedRequest, cfg JSReplayConfig) []ObservedRequest { //nolint:gocyclo // top-level JS extraction orchestration
	cfg = cfg.withDefaults()

	// logf is a no-op unless verbose mode is on; warnf always emits.
	logf := func(format string, args ...interface{}) {
		if cfg.Verbose {
			fmt.Fprintf(cfg.Stderr, format, args...) //nolint:errcheck // debug logging to stderr
		}
	}
	warnf := func(format string, args ...interface{}) {
		fmt.Fprintf(cfg.Stderr, format, args...) //nolint:errcheck // operator-facing warning
	}

	// Determine the target origin from cfg.TargetURL or the first request.
	targetOrigin := originOf(cfg.TargetURL)
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

	// Apply a wall-clock deadline to bound the whole step regardless of how
	// many slow endpoints the JS bundle contains.
	loopCtx, cancel := context.WithTimeout(ctx, cfg.MaxTotalTime)
	defer cancel()

	// Discover JS file URLs from HTML <script> tags. Katana often mangles
	// relative JS paths when resolving against SPA routes, so we parse HTML
	// responses ourselves and resolve <script src> against the page URL.
	htmlJSURLs := make(map[string]bool)
	for _, req := range requests {
		body := req.Response.Body
		if len(body) == 0 {
			continue
		}
		// Only process HTML responses.
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

	// Scan all JS response bodies for API paths.
	allPaths := make(map[string]bool)
	processedJSURLs := make(map[string]bool)

	// processJS extracts API paths from a JS body and adds them to allPaths.
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

		// Re-fetch the JS file when the body is empty (Katana often reports
		// JS URLs without populating the response body) or truncated at
		// MaxResponseBodySize (SPA bundles are often >1 MB and API path
		// strings may be past the truncation point).
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

	// Fetch and process JS files discovered from HTML <script> tags that
	// weren't already processed from the crawl results.
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

	// Sort paths for deterministic iteration. Without this, MaxEndpoints
	// truncation produces a different probed set every run, which makes
	// the tool's output non-reproducible.
	sortedPaths := make([]string, 0, len(allPaths))
	for p := range allPaths {
		sortedPaths = append(sortedPaths, p)
	}
	sort.Strings(sortedPaths)

	// Probe each discovered API path with a raw HTTP request.
	result := make([]ObservedRequest, len(requests))
	copy(result, requests)

	probed := 0
	for _, path := range sortedPaths {
		if probed >= cfg.MaxEndpoints {
			break
		}

		// Full URLs are probed as-is; relative paths are resolved against
		// the target origin.
		fullURL := path
		if !strings.HasPrefix(path, "http://") && !strings.HasPrefix(path, "https://") {
			fullURL = targetOrigin + path
		}

		// Same-origin gate: by default, drop URLs whose origin doesn't
		// match the scan target. This prevents the JS bundle from using
		// Vespasian as a request reflector and stops auth-header leaks
		// to attacker-controlled hosts. Skipped URLs do NOT consume the
		// MaxEndpoints budget — otherwise an attacker could salt the
		// bundle with cross-origin URLs to suppress legitimate API
		// discovery.
		if !cfg.AllowCrossOrigin && !isSameOrigin(fullURL, targetOrigin) {
			warnf("js-extract: skipping cross-origin URL %s (use AllowCrossOrigin to allow)\n",
				sanitizeForLog(fullURL))
			continue
		}

		// SSRF validation: refuse private/loopback/link-local destinations
		// unless the operator has explicitly opted in via AllowPrivate.
		// Use the loop context so a JS bundle full of slow/black-holed
		// hostnames cannot stall the validation phase past MaxTotalTime.
		// Skipped URLs do NOT consume the MaxEndpoints budget.
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

		// Skip 404 responses — these are typically wrong service prefix
		// combinations (e.g., /identity/api/shop/products when the correct
		// prefix is /workshop/). Keeping them would pollute the spec with
		// endpoints that don't actually exist on that service.
		if resp.StatusCode == http.StatusNotFound {
			continue
		}

		// Defensive header copy: cfg.Headers is shared across all
		// callers, so capture a snapshot per result to avoid later
		// mutations bleeding into already-recorded requests. Recorded
		// headers track what the wire actually carried — empty for
		// cross-origin probes (see header-forwarding gate above).
		var recorded map[string]string
		if isSameOrigin(fullURL, targetOrigin) {
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

// jsReplayUserAgent identifies probe requests as coming from Vespasian's
// JS-replay step so cross-origin destinations can attribute the traffic.
// No version is included so the constant doesn't drift from the binary.
const jsReplayUserAgent = "vespasian-js-extract"

// doRequest builds and executes an HTTP GET against rawURL using cfg.Client.
// Headers from cfg.Headers are attached only when rawURL is same-origin with
// targetOrigin (header forwarding is independent of AllowCrossOrigin so auth
// headers never leave the target's origin). The caller must ensure the
// response body is consumed and closed via the returned cleanup function.
func doRequest(ctx context.Context, cfg JSReplayConfig, rawURL, targetOrigin string) (*http.Response, func(), error) {
	reqCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, rawURL, nil)
	if err != nil {
		cancel()
		return nil, func() {}, err
	}

	// Identify ourselves so cross-origin destinations can correlate the
	// traffic to a Vespasian scan rather than attribute it to a generic
	// Go-http-client. Same-origin Headers (set below) can override this
	// if the operator passes their own User-Agent via --header.
	req.Header.Set("User-Agent", jsReplayUserAgent)

	// Same-origin gate for header forwarding: never send Authorization /
	// Cookie / X-API-Key to an off-target host, even when AllowCrossOrigin
	// permits the probe. Header forwarding is strictly tied to host
	// equality, not to whether the probe was allowed.
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
		// Drain a bounded prefix of the body so the connection can be
		// reused, then close it. Both errors are intentionally ignored
		// (the response is about to be discarded either way) but the
		// blank-identifier assignment + nolint annotation keeps both
		// gosec (G104) and errcheck quiet.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)) //nolint:errcheck,gosec // best-effort drain
		_ = resp.Body.Close()                                       //nolint:errcheck,gosec // best-effort close
		cancel()
	}
	return resp, cleanup, nil
}

// maxJSRedirects bounds the number of 3xx redirects fetchJSBody will follow
// when a CDN serves a JS bundle behind a redirect. Production CDNs typically
// chain at most 1-2 redirects (e.g., versioned to immutable URL); 5 is
// generous and aligns with browser behavior.
const maxJSRedirects = 5

// fetchJSBody re-fetches a JS file with a larger body limit than the crawler
// uses. Returns nil if the response is an error, HTML (SPA catch-all), or
// unreadable. Off-origin URLs are skipped unless AllowCrossOrigin is set.
//
// Because the shared *http.Client refuses redirects (CheckRedirect returns
// ErrUseLastResponse so probe results record the actual response from the
// requested URL), this function manually follows up to maxJSRedirects 3xx
// responses before applying the HTML/error-status filters. Each hop is
// re-validated against the same-origin gate and SSRF checks so a malicious
// JS URL cannot redirect into a private destination or off-target host.
func fetchJSBody(ctx context.Context, cfg JSReplayConfig, rawURL, targetOrigin string) []byte {
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

// canFetchURL applies the same-origin gate and SSRF check before any HTTP
// request is issued. Returns false if the URL must not be fetched.
func canFetchURL(ctx context.Context, cfg JSReplayConfig, rawURL, targetOrigin string) bool {
	if !cfg.AllowCrossOrigin && !isSameOrigin(rawURL, targetOrigin) {
		// Don't re-fetch cross-origin scripts: it both leaks the user's
		// headers (when AllowCrossOrigin is false) and turns Vespasian
		// into a third-party-CDN reflector for the JS bundle author.
		return false
	}
	if !cfg.AllowPrivate {
		if err := ssrf.ValidateURLContext(ctx, rawURL); err != nil {
			return false
		}
	}
	return true
}

// fetchJSBodyHop performs a single HTTP GET and classifies the response.
// Returns (body, "", true) when the response is terminal (a final body or
// an error to surface as nil), or (nil, redirectURL, false) when the caller
// should follow a 3xx to redirectURL.
func fetchJSBodyHop(ctx context.Context, cfg JSReplayConfig, rawURL, targetOrigin string) (body []byte, redirectTo string, terminal bool) {
	resp, cleanup, err := doRequest(ctx, cfg, rawURL, targetOrigin)
	if err != nil {
		return nil, "", true
	}
	defer cleanup()

	// 3xx: caller follows.
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

	// Reject HTML responses — the URL likely hit an SPA catch-all route
	// that serves index.html for any unknown path.
	if isHTMLResponse(resp.Header.Get("Content-Type")) {
		return nil, "", true
	}

	read, err := io.ReadAll(io.LimitReader(resp.Body, maxJSBodySize))
	if err != nil {
		return nil, "", true
	}

	// Guard against servers that don't set Content-Type: if the body
	// starts with <!DOCTYPE or <html, it's HTML, not JavaScript.
	if len(read) > 0 && looksLikeHTML(read) {
		return nil, "", true
	}

	return read, "", true
}

// resolveRedirect resolves the Location header value against the current URL,
// returning the absolute URL of the next hop. Empty input or unparsable
// values produce an error so callers can abort the chain.
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

// looksLikeHTML checks if a response body appears to be HTML content
// by looking for common HTML document markers at the start of the body.
func looksLikeHTML(body []byte) bool {
	// Skip leading whitespace/BOM.
	trimmed := bytes.TrimLeft(body, " \t\r\n\xef\xbb\xbf")
	if len(trimmed) == 0 {
		return false
	}
	lower := bytes.ToLower(trimmed[:min(len(trimmed), 50)])
	return bytes.HasPrefix(lower, []byte("<!doctype")) ||
		bytes.HasPrefix(lower, []byte("<html"))
}

// probeURL makes a direct HTTP GET request to the URL and returns the response.
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

// flattenHeaders converts http.Header (multi-value) to a single-value map.
func flattenHeaders(h http.Header) map[string]string {
	result := make(map[string]string, len(h))
	for k, vals := range h {
		if len(vals) > 0 {
			result[k] = vals[0]
		}
	}
	return result
}
