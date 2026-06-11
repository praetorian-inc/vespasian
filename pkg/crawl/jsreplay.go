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

	"github.com/praetorian-inc/vespasian/pkg/mediatype"
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
		// We cannot install a SafeDialContext on an opaque RoundTripper, so
		// fall back to request-time validation: wrap the caller's transport
		// so every request URL is re-checked against the SSRF blocklist
		// immediately before it is sent. This is weaker than dial-time
		// pinning (the wrapped transport still does its own DNS resolution,
		// leaving a narrow TOCTOU window) but strictly stronger than letting
		// the request through with only a warning.
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

// ssrfValidatingRoundTripper wraps an opaque http.RoundTripper (one we cannot
// install a dial-time SafeDialContext on) and re-validates every request URL
// against the SSRF blocklist immediately before delegating. It is the fallback
// used by wrapClientWithSSRF when a caller supplies a custom transport, so a
// custom-transport client (e.g. one routed through a proxy) still cannot be
// steered at a private/internal destination.
type ssrfValidatingRoundTripper struct {
	base http.RoundTripper
}

// RoundTrip validates req.URL against the SSRF blocklist before delegating to
// the wrapped transport, returning an error (without sending the request) when
// the destination resolves to a private/internal address.
func (rt ssrfValidatingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := ssrf.ValidateURLContext(req.Context(), req.URL.String()); err != nil {
		return nil, fmt.Errorf("js-extract: SSRF validation rejected %s: %w", req.URL.Redacted(), err)
	}
	return rt.base.RoundTrip(req)
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
// Canonicalization (parameter strip + lowercase) is delegated to
// mediatype.Base so the crawl, classify, and generate stages share one
// implementation.
func matchesContentType(contentType string, types []string) bool {
	ct := mediatype.Base(contentType)
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
		apiIndicatorAlternation +
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
		apiIndicatorAlternation +
		`[a-zA-Z0-9/_\{}.:-]*)` +
		"`",
)

// fullURLPattern matches full API URLs (http/https) in JS strings.
// E.g., "https://api.example.com/v1/users"
var fullURLPattern = regexp.MustCompile(
	`["'` + "`]" +
		`(https?://[a-zA-Z0-9._-]+(?::[0-9]+)?` +
		`/(?:[a-zA-Z0-9_-]+/)*` +
		apiIndicatorAlternation +
		`[a-zA-Z0-9/_\{}.:-]*)` +
		`["'` + "`]",
)

// apiIndicatorAlternation is the single source of truth for which path
// segments signal an API endpoint. It is concatenated into every extraction
// regex (apiPathPattern, templateLiteralPattern, fullURLPattern,
// servicePrefixPattern) and into apiIndicatorPattern, so the set cannot
// drift between extraction and classification.
const apiIndicatorAlternation = `(?:api/|v[1-9][0-9]*/|rest/|rpc/|graphql)`

// servicePrefixPattern matches service prefix strings concatenated with API paths
// using the `+` operator between two QUOTED string literals.
// E.g., "identity/" + "api/auth/login" — captures "identity/".
//
// Note: backtick template literal concatenations are not matched (use
// extractTemplateLiteralPaths for those). Concatenation with non-literal
// operands — e.g. "/api/posts/".concat(id, "/comment") or "/api/users/" + id
// + "/posts" — is handled separately by extractConcatPaths (see LAB-1368).
var servicePrefixPattern = regexp.MustCompile(
	`["']([a-zA-Z][a-zA-Z0-9_-]{1,30}/)["']\s*\+\s*["']` + apiIndicatorAlternation,
)

// concatMethodPattern matches a quoted string literal receiver followed by
// `.concat(` — i.e. the head of a `.concat()` call. The path receiver is
// captured as group 1 (without surrounding quotes). The argument list is
// NOT matched by the regex because regular expressions cannot balance
// nested parentheses (e.g. `.concat(foo(a, b), "/x")`); the matching
// closing `)` is found by a paren-aware scan at the match site.
//
// Targets the LAB-1368 case: "/api/posts/".concat(id, "/comment").
// The receiver must be a string literal — chained-method or computed
// receivers (e.g. `obj.url.concat(...)`) would require an AST and are
// intentionally out of scope.
//
// The receiver character class includes `?=&%~` in addition to the
// path-only chars used by concatPlusHeadPattern. The asymmetry is
// intentional: a `.concat()` receiver in real SPAs is sometimes a
// URL fragment with embedded query syntax (e.g. `"/api/users?id=".concat(uid)`),
// whereas a `+`-chain head is almost always a clean path because the
// chain itself is being used to add the query/path tail. The post-hoc
// `hasAPIIndicator` filter in emit() drops any reconstructed path that
// doesn't contain an API marker, so the wider receiver class doesn't
// produce false positives — only widens the input pool the post-filter
// sees.
var concatMethodPattern = regexp.MustCompile(
	`["']` +
		`(/?[a-zA-Z0-9/_{}.:?=&%~-]+)` +
		`["']\.concat\(`,
)

// concatPlusHeadPattern matches the head of a `+`-concat chain whose first
// operand is a quoted string literal containing an API indicator and is
// followed by a `+` operator. Subsequent operands are walked by
// parsePlusChain rather than captured here because regex cannot bound an
// arbitrary chain without runaway backtracking.
//
// Targets the LAB-1368 case: "/api/users/" + id + "/posts".
// The leading API-indicator anchor keeps random `"a" + b + "c"` literals
// from triggering the chain walker.
//
// Returns: group 1 = head literal (without surrounding quotes); match end
// is positioned immediately after the trailing `+`, which is where
// parsePlusChain begins its walk.
var concatPlusHeadPattern = regexp.MustCompile(
	`["']` +
		`(/?` +
		`(?:[a-zA-Z0-9_-]+/)*` +
		apiIndicatorAlternation +
		`[a-zA-Z0-9/_{}.:-]*)` +
		`["']\s*\+`,
)

// concatPathSentinel is what we substitute for any non-literal concat
// argument or +-chain operand. A pure numeric segment so the REST
// generator's NormalizePathWithNames turns it into a named {param} (see
// pkg/generate/rest/normalize.go). Using "0" rather than "{}" keeps the
// reconstructed path a syntactically valid HTTP path that the prober can
// actually issue a request against.
const concatPathSentinel = "0"

// maxConcatChainOperands bounds the length of a `+`-concat chain
// parsePlusChain will walk before bailing out. Real URL chains rarely
// exceed a handful of segments; past this we are almost certainly chasing
// noise in unrelated expressions and stopping limits worst-case work.
const maxConcatChainOperands = 16

// maxConcatChainSpan bounds the total byte span parsePlusChain will walk
// from the start of the chain. parsePlusChain enforces it by clamping its
// working slice to jsBody[:start+maxConcatChainSpan], so every per-operand
// scan (scanStringLiteral, scanIdentifierOperand) is physically bounded
// regardless of bracket depth or operand shape. Without this cap a hostile
// JS bundle could place a few-byte `"/api/" + ` anchor in front of a
// megabytes-long bracketed sub-expression whose operand-terminators
// (`+`, `;`, `,`, newline, `)`) only appear near end-of-bundle, forcing
// scanIdentifierOperand to walk the whole span per match.
//
// 1024 bytes is comfortably larger than any realistic URL-construction
// chain and small enough to bound aggregate worst-case parser work at
// O(M * maxConcatChainSpan) = O(M * 1024) bytes across all M chain
// matches in a 10MiB body. The maxConcatChainOperands cap does NOT
// multiply the span — all operand walks in a single parsePlusChain
// invocation share the same clamped slice and `pos` advances
// monotonically within it, so per-invocation work is bounded by the
// slice length, not by operand count.
const maxConcatChainSpan = 1024

// maxConcatArgList is the maximum size of the raw argument list
// findConcatArgListEnd will scan inside a `.concat(...)` call. Bounds the
// per-call work of the paren-aware scan against pathological bundles that
// pack many nested brackets or long quoted strings into one argument list.
// 500 bytes is comfortably wider than any real argument list (the LAB-1368
// extractor only cares about literal segments and identifier-shaped
// operands, which together fit well under that cap).
const maxConcatArgList = 500

// maxConcatPathsPerBundle caps the number of reconstructed concat paths
// emitted from a single JS bundle. Complements the cross-bundle
// MaxEndpoints backstop (default 500) by bounding pre-probe fan-out on a
// hostile bundle densely packed with API-indicator concat anchors.
const maxConcatPathsPerBundle = 256

// apiIndicatorPattern matches the path segments that signal an API endpoint.
// Sourced from apiIndicatorAlternation so it is impossible for it to drift
// from the extraction regexes.
var apiIndicatorPattern = regexp.MustCompile(`(?i)` + apiIndicatorAlternation)

// standalonePrefixPattern matches bare service-prefix string literals like
// "identity/", "workshop/", "community/" — short lowercase-alpha-with-dashes
// segments ending in a slash. Catches bundles that build URLs by
// concatenating a config constant with a path:
//
//	const SVC_IDENTITY = "identity/"
//	fetch(SVC_IDENTITY + "api/auth/login")
//
// rather than the strict literal+literal form servicePrefixPattern requires.
//
// Hardened against false positives (asset folders like "images/", "static/",
// "vendor/") via three filters in extractServicePrefixes:
//
//  1. Exclude API indicators (api/, v1/, ...) — those would otherwise be
//     mistaken for service prefixes.
//  2. Frequency threshold — a real service prefix is referenced repeatedly
//     in the bundle (every fetch call); one-off literals are usually folder
//     names. Requires ≥ standalonePrefixMinFrequency occurrences.
//  3. Per-bundle cap — bound the fan-out at maxBundlePrefixCap
//     so a noisy bundle cannot exhaust MaxEndpoints with N×M expansions.
var standalonePrefixPattern = regexp.MustCompile(
	`["']([a-z][a-z0-9_-]{1,30}/)["']`,
)

// standalonePrefixMinFrequency is how many times a candidate must appear in
// a bundle to be considered a real service prefix.
//
// Set to 1 because production SPAs (e.g., OWASP crAPI) typically declare each
// service prefix exactly once as a runtime constant (`const SVC_X = "x/"`)
// and reference it via the variable thereafter — a literal-match count >= 2
// would reject these legitimate prefixes. Noise control is delegated to
// (a) the API-indicator filter, (b) the per-bundle cap of 8, (c) the
// downstream 404 filter that drops wrong-prefix probe combinations, and
// (d) the global cfg.MaxEndpoints probe budget that hard-caps the total
// number of prefix×path combinations ever probed. Together these bound the
// amplification cost of false-positive prefixes without trading away recall
// on real-world bundles.
const standalonePrefixMinFrequency = 1

// maxBundlePrefixCap caps the TOTAL number of service prefixes
// extractServicePrefixes will emit for a single JS bundle. Strategy 3
// respects this cap as a budget — if Strategies 1 and 2 have already
// emitted N prefixes, Strategy 3 will add at most max(0, cap-N) more.
//
// Bounds the worst-case N (paths) × M (prefixes) probe-budget consumption
// when a bundle contains many short standalone string literals.
const maxBundlePrefixCap = 8

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
	return apiIndicatorPattern.MatchString(path)
}

// hasInlinePrefix reports whether the path has a non-API segment before the
// first API indicator, meaning it already contains a service prefix
// (e.g., "identity/api/..." or "community/v2/...").
// Paths like "api/v2/users" do NOT have an inline prefix — "api/" before "v2/"
// is itself an API indicator, not a service prefix.
func hasInlinePrefix(trimmedPath string) bool {
	loc := apiIndicatorPattern.FindStringIndex(trimmedPath)
	return loc != nil && loc[0] > 0
}

// defaultPortForScheme returns the canonical default port for a URL scheme,
// or "" if the scheme has no default we recognize. Used by originOf to
// canonicalize implicit-vs-explicit-port forms (https://example.com and
// https://example.com:443 must compare equal).
func defaultPortForScheme(scheme string) string {
	switch strings.ToLower(scheme) {
	case "http":
		return "80"
	case "https":
		return "443"
	}
	return ""
}

// originOf returns the canonicalized scheme://host:port origin of rawURL, or
// "" if it cannot be parsed or has no host. Default ports are made explicit
// and the scheme + host are lower-cased so that
//
//	https://example.com   ->  https://example.com:443
//	HTTPS://Example.com   ->  https://example.com:443
//	https://example.com:443 -> https://example.com:443
//
// all collapse to the same string. Without this normalization, isSameOrigin
// would treat the implicit-port and explicit-port forms as different origins
// and incorrectly skip valid same-origin probes.
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

// isSameOrigin reports whether rawURL has the same origin as targetOrigin.
// Both sides are normalized via originOf so default-port-vs-explicit-port
// pairs (e.g., https://example.com and https://example.com:443) compare equal.
func isSameOrigin(rawURL, targetOrigin string) bool {
	if targetOrigin == "" {
		return false
	}
	return originOf(rawURL) == originOf(targetOrigin)
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

	// Strategy 3: standalone short-segment string literals.
	//
	// Many SPAs (e.g., crAPI) declare service prefixes as runtime constants
	// (`const SVC = "identity/"`) and concatenate at call time, so the
	// strict literal+literal `servicePrefixPattern` never fires.
	//
	// The bare-pattern matches a wide universe of strings — folder names,
	// CSS classes, asset prefixes — so we apply three filters:
	//   - exclude API indicators (would self-classify as prefix)
	//   - require ≥ standalonePrefixMinFrequency occurrences in the bundle
	//   - cap at maxBundlePrefixCap, sorted by descending
	//     frequency then ascending lexicographic order for determinism
	addStandaloneCandidates(jsBody, add, seen)

	return prefixes
}

// addStandaloneCandidates is Strategy 3 of extractServicePrefixes. Pulled
// out so the prefix-discovery pipeline reads top-down and the rubric (filter
// → frequency-count → cap → sort → emit) is testable in isolation.
//
// Respects maxBundlePrefixCap as a TOTAL budget across the whole bundle: if
// Strategies 1 and 2 have already emitted N prefixes (N == len(seen) at
// entry to this function), Strategy 3 will add at most max(0, cap - N) more.
// This guarantees the bundle never exceeds the cap regardless of how the
// earlier strategies fared.
func addStandaloneCandidates(jsBody []byte, add func(string), seen map[string]bool) {
	// Snapshot the existing prefix count BEFORE we start adding.
	existing := len(seen)
	if existing >= maxBundlePrefixCap {
		// Strategies 1 + 2 already saturated the bundle's budget; nothing
		// to add here.
		return
	}
	budget := maxBundlePrefixCap - existing

	freq := make(map[string]int)
	for _, match := range standalonePrefixPattern.FindAllSubmatch(jsBody, -1) {
		if len(match) < 2 {
			continue
		}
		candidate := string(match[1])
		// Filter 1: API indicators are not service prefixes.
		if apiIndicatorPattern.MatchString(candidate) {
			continue
		}
		// Skip prefixes already emitted by Strategy 1 / 2. We continue
		// before incrementing freq, so these are entirely excluded from
		// Strategy 3's frequency-count accounting (they are already
		// counted toward the cap via `existing` above).
		if seen[candidate] {
			continue
		}
		freq[candidate]++
	}

	// Filter 2: frequency threshold.
	type cand struct {
		name  string
		count int
	}
	candidates := make([]cand, 0, len(freq))
	for name, n := range freq {
		if n < standalonePrefixMinFrequency {
			continue
		}
		candidates = append(candidates, cand{name, n})
	}

	// Cap-aware sort: descending count, ascending name for tie-breaking.
	// This gives deterministic IDs across runs and prefers prefixes used
	// many times (likelier to be real service prefixes).
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].count != candidates[j].count {
			return candidates[i].count > candidates[j].count
		}
		return candidates[i].name < candidates[j].name
	})

	// Filter 3: per-bundle TOTAL cap (Strategies 1 + 2 + 3 combined).
	limit := budget
	if len(candidates) < limit {
		limit = len(candidates)
	}
	for i := 0; i < limit; i++ {
		add(candidates[i].name)
	}
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

// extractConcatPaths scans for API paths built by JS string concatenation —
// either a String.prototype.concat call or a `+`-operator chain — including
// chains where every operand is a string literal. Two forms are recognized:
//
//  1. String.prototype.concat method form:
//     "/api/posts/".concat(id, "/comment") -> /api/posts/0/comment
//  2. `+`-operator chain form:
//     "/api/users/" + id + "/posts" -> /api/users/0/posts
//
// Non-literal operands are replaced with concatPathSentinel ("0") so the
// reconstructed path is a valid HTTP path that the prober can issue. The
// downstream REST normalizer turns the sentinel into a named {param}.
//
// Pure literal+literal concatenations are accepted by BOTH forms — neither
// regex requires a non-literal operand to match. When the chain happens to
// be all literals (e.g. `"/api/" + "users"`), the path reconstructs the
// same way and is emitted; servicePrefixPattern + apiPathPattern may also
// match the same source, but the seen-map in emit() deduplicates collisions
// so no double-emission occurs.
func extractConcatPaths(jsBody []byte) []string { //nolint:gocyclo // emit() state machine (slash-collapse + indicator filter + dedup + per-bundle cap); splitting hurts readability and matches the sibling parser convention in this file
	seen := make(map[string]bool)
	var paths []string

	emit := func(p string) {
		if len(paths) >= maxConcatPathsPerBundle {
			return
		}
		// Collapse `//` runs introduced by literal+literal concatenations
		// where the head literal ends in `/` and the next literal begins
		// with `/` (e.g. `"/api/posts/" + "/comment"` → `"/api/posts//comment"`).
		// addPath downstream only trims leading/trailing slashes, not
		// internal runs, and the REST normalizer treats `//{id}` as a
		// distinct (malformed) path segment.
		//
		// Preserve the `://` scheme separator in full URLs: collapse only
		// the path-side of the URL (or the whole string if no scheme is
		// present). Looping until stable handles rare ≥3-slash runs.
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

	// Form 1: .concat() method form.
	for _, match := range concatMethodPattern.FindAllSubmatchIndex(jsBody, -1) {
		// match indices: [0,1]=full match (incl. `.concat(`), [2,3]=receiver.
		if len(match) < 4 || match[2] < 0 {
			continue
		}
		receiver := string(jsBody[match[2]:match[3]])
		argEnd := findConcatArgListEnd(jsBody, match[1])
		if argEnd < 0 {
			continue
		}
		// findConcatArgListEnd caps its scan at match[1]+maxConcatArgList,
		// so argEnd-match[1] is already <= maxConcatArgList — no second
		// post-check needed.
		argList := string(jsBody[match[1]:argEnd])
		emit(receiver + parseConcatArgs(argList))
	}

	// Form 2: `+`-chain form.
	for _, match := range concatPlusHeadPattern.FindAllSubmatchIndex(jsBody, -1) {
		// match indices: [0,1]=full match (incl. trailing `+`),
		// [2,3]=head literal.
		if len(match) < 4 || match[2] < 0 {
			continue
		}
		head := string(jsBody[match[2]:match[3]])
		suffix := parsePlusChain(jsBody, match[1])
		emit(head + suffix)
	}

	return paths
}

// parseConcatArgs splits a JS .concat() argument list and returns the
// reconstructed suffix string. Each comma-separated argument is either a
// quoted string literal (kept verbatim, quotes stripped), a backtick
// template literal with no ${} interpolation (kept verbatim), or any other
// expression token (replaced with concatPathSentinel).
//
// argList is the raw source between the `(` and `)` of the .concat call.
// Commas inside matched quotes are NOT treated as separators.
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

// findConcatArgListEnd returns the index of the `)` that closes the
// .concat( opened immediately before start, accounting for nested
// parens/brackets/braces and string literals so a `)` inside a quoted
// argument or a nested call (e.g. `.concat(foo(a, b), "/x")`) doesn't
// terminate the scan prematurely. Returns -1 if the call is malformed or
// the matching `)` is not found within maxConcatArgList bytes.
func findConcatArgListEnd(jsBody []byte, start int) int { //nolint:gocyclo // small state machine
	depthRound, depthSquare, depthCurly := 0, 0, 0
	limit := start + maxConcatArgList
	if limit > len(jsBody) {
		limit = len(jsBody)
	}
	// Clamp the slice handed to per-byte helpers so any string-literal scan
	// (including backtick template literals routed through
	// findTemplateLiteralEnd, which has no newline termination) is
	// physically bounded at `limit`. Mirrors the slice-clamp pattern used
	// by parsePlusChain — without this, a backtick opening near `limit`
	// could force scanStringLiteral to walk megabytes looking for the
	// matching backtick.
	//
	// Defensive-only / no behavioral signature: this clamp never changes
	// findConcatArgListEnd's return value, because the outer loop below is
	// already capped at `i < limit` regardless of the clamp — once a
	// string scan jumps `i` past `limit`, the loop exits and returns -1
	// either way. The clamp's sole effect is bounding a single
	// pathological per-call scan; because string/backtick delimiters pair
	// up, the aggregate scan cost over a bundle is already O(N), so the
	// clamp does not change measured runtime (verified: a 3.1MB / 5000-
	// match worst case runs in ~76ms with OR without it). It is retained
	// as cheap insurance against a single megabyte-scale unterminated
	// literal in minified single-line JS. Consequently there is no
	// regression test that can fail when this clamp is removed — it is the
	// parsePlusChain clamp (which DOES have a behavioral signature) that
	// the DoS-bound tests pin.
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

// splitConcatArgs splits argList on top-level commas, ignoring commas
// inside matched quotes, backticks, brackets, braces, or parentheses.
// Returns the raw argument strings (whitespace not trimmed).
//
// String/backtick scanning is delegated to scanStringLiteral so that
// backtick template literals (including those with nested ${} blocks) are
// handled consistently with the rest of the file.
func splitConcatArgs(argList string) []string { //nolint:gocyclo // small string-state machine; splitting hurts readability
	data := []byte(argList)
	var args []string
	var b strings.Builder
	depthRound, depthSquare, depthCurly := 0, 0, 0
	for i := 0; i < len(data); i++ {
		c := data[i]
		switch c {
		case '"', '\'', '`':
			end := scanStringLiteral(data, i)
			if end < 0 {
				// Unterminated/malformed literal: append the remainder
				// verbatim and stop so stray commas in the tail don't
				// produce spurious extra arguments.
				b.Write(data[i:])
				goto done
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
done:
	if b.Len() > 0 {
		args = append(args, b.String())
	}
	return args
}

// stringLiteralValue reports whether s is a JS string or template literal
// with no ${} interpolation and returns its unquoted text. Escape
// sequences inside the literal are NOT decoded — for our use (path
// reconstruction) the raw text is what we want, since JS escapes rarely
// appear in URL paths and decoding them risks introducing characters that
// don't round-trip through the prober.
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

// parsePlusChain walks a `+`-concat chain starting at start (the byte
// immediately after a `+` that follows the head literal). It alternates
// operand and `+` tokens, collecting string-literal operands verbatim and
// substituting concatPathSentinel for any other operand. Returns the
// reconstructed suffix.
//
// Walks at most maxConcatChainOperands operands AND at most
// maxConcatChainSpan bytes from start; bails immediately on a malformed
// operand, a missing connecting `+`, or any unexpected character. The
// byte-span cap is enforced by clamping the working slice to
// jsBody[:start+maxConcatChainSpan] BEFORE any per-operand scan, so it
// applies uniformly to iteration 0 (the first-operand walk) as well as
// to later iterations. Without the slice clamp, a hostile bundle could
// place a `"/api/"+` anchor in front of an arbitrarily long bracketed
// sub-expression and force scanIdentifierOperand to walk to end-of-body
// looking for a depth-0 operand terminator. Trailing whitespace and the
// final operand are tolerated.
func parsePlusChain(jsBody []byte, start int) string {
	// Clamp working slice: any helper (scanStringLiteral,
	// scanIdentifierOperand) that loops on `i < len(body)` is now
	// physically bounded at start+maxConcatChainSpan, regardless of
	// bracket depth or operand shape. This is strictly cheaper than
	// a per-iteration counter because it cannot be bypassed by adding
	// new operand types in the future.
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

// readChainOperand reads a single operand from a `+`-concat chain at pos.
// A string literal returns its unquoted text; any other operand returns
// concatPathSentinel. Operand boundary is the next top-level `+`, `;`,
// `,`, newline, or matched closing bracket of the surrounding expression.
// Returns (text, end-index past the operand, ok).
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

// scanStringLiteral returns the index of the matching closing quote of
// the string starting at start, or -1 if not found within a bounded scan.
// Handles backslash escapes; for template literals (`...`) the scan also
// walks past ${} interpolations so nested `+` characters inside them are
// not mistaken for chain separators.
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

// scanIdentifierOperand returns the end index (exclusive) of a single
// non-literal operand starting at pos. The operand is consumed up to the
// next top-level operator or terminator. Bracketed sub-expressions are
// skipped so commas/+ inside them do not split the operand.
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

// skipPlusChainWhitespace advances past spaces, tabs, and newlines.
// Newlines are skipped here because parsePlusChain only calls this while
// positioned BETWEEN operands (always after a `+`), where typical JS
// formatting may break the line. Chain termination by an unaccompanied
// newline is enforced by scanIdentifierOperand, which stops at `\n` so an
// identifier operand cannot gobble up the following statement.
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

// extractAPIPaths scans JavaScript source code for API path patterns using
// multiple extraction strategies:
//  1. Single/double-quoted strings containing API indicators
//  2. Template literals (backticks), including ${...} interpolations
//  3. Full URLs (http/https) pointing to API endpoints
//  4. Service prefix concatenation (e.g., "identity/" + "api/auth/login")
//  5. String.prototype.concat() and +-chain with identifiers (LAB-1368)
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

	// Strategy 5: String.prototype.concat() and +-chain with identifiers
	// (LAB-1368). Reconstructed paths use a numeric sentinel for non-literal
	// operands so the REST normalizer can parameterize them. Run last so the
	// more-precise strategies above win the dedup race when both match.
	// (Strategy 4 — literal+literal service-prefix concatenation — runs
	// implicitly above via extractServicePrefixes + addPath fan-out.)
	for _, p := range extractConcatPaths(jsBody) {
		addPath(p)
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

		// Compute the same-origin verdict once per iteration; it is reused
		// both by the cross-origin gate below and the header-recording check
		// further down (the URL and target origin do not change in between).
		sameOrigin := isSameOrigin(fullURL, targetOrigin)

		// Same-origin gate: by default, drop URLs whose origin doesn't
		// match the scan target. This prevents the JS bundle from using
		// Vespasian as a request reflector and stops auth-header leaks
		// to attacker-controlled hosts. Skipped URLs do NOT consume the
		// MaxEndpoints budget — otherwise an attacker could salt the
		// bundle with cross-origin URLs to suppress legitimate API
		// discovery.
		if !cfg.AllowCrossOrigin && !sameOrigin {
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

// jsExtractUserAgent identifies probe requests as coming from Vespasian's
// JS-replay step so cross-origin destinations can attribute the traffic.
// No version is included so the constant doesn't drift from the binary.
const jsExtractUserAgent = "vespasian-js-extract"

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
	req.Header.Set("User-Agent", jsExtractUserAgent)

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
// returning the absolute URL of the next hop. An unparsable currentURL or
// Location returns an error so callers can abort the chain. An empty
// Location returns currentURL unchanged (Go's url.ResolveReference contract);
// fetchJSBody guards against empty Locations BEFORE calling this function so
// the empty-Location case is documentary rather than reachable at runtime.
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
