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
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/praetorian-inc/vespasian/pkg/httpx"
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

	// Proxy routes replay traffic through an intercepting proxy when set, and is
	// honored ONLY when Client is nil (the production path — buildJSReplayConfig
	// never sets Client): an injected Client owns its transport, and
	// wrapClientWithSSRF would clobber a proxied dialer, so withDefaults warns on
	// Stderr that replay traffic will BYPASS the proxy in that case. The proxied
	// client installs no dial-time SSRF pin, since it dials the proxy rather than the
	// target; URL-level scope (ValidateProbeURL, canFetchURL) is unchanged.
	Proxy httpx.ProxyConfig

	Verbose bool

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
		if cfg.Proxy.Enabled() {
			// Route through the proxy: no dial-time SSRF pin (we dial the proxy,
			// not the target). This is the production path; an injected Client
			// deliberately opts out of Proxy (wrapClientWithSSRF would clobber a
			// proxied dialer).
			cfg.Client = httpx.BuildHTTPClient(cfg.Proxy, cfg.Timeout, httpx.NoFollowRedirects)
		} else {
			cfg.Client = newSSRFSafeClient(cfg.Timeout, cfg.AllowPrivate)
		}
	} else {
		if cfg.Proxy.Enabled() {
			// SEC-BE-004: an injected Client owns its transport, so a configured Proxy
			// is ignored here. Warn rather than bypass the proxy without a trace.
			fmt.Fprintf(cfg.Stderr, "js-extract: warning: Proxy configured but ignored — an injected Client owns its transport; replay traffic will BYPASS the proxy\n") //nolint:errcheck // best-effort warning
		}
		// Caller supplied a client. SSRF-wrap when AllowPrivate is false, and always
		// enforce our redirect policy: probeURL records the status we asked for (no
		// auto-follow), and fetchJSBody follows 3xx manually with bounded depth plus
		// per-hop SSRF and same-origin re-validation.
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
		cfg.Client.CheckRedirect = httpx.NoFollowRedirects
	}
	return cfg
}

// wrapClientWithSSRF copies caller and installs ssrf.SafeDialContext on a cloned
// transport. Never mutates the caller's Client or Transport — other holders of
// those pointers (a logging middleware, a connection pool, a test harness) would
// silently get new dial behavior.
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
		CheckRedirect: httpx.NoFollowRedirects,
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
		APIIndicatorAlternation +
		`[a-zA-Z0-9/_\{}.:-]*)` +
		`["']`,
)

// templateLiteralPattern is the no-interpolation fallback;
// extractTemplateLiteralPaths handles ${...}.
var templateLiteralPattern = regexp.MustCompile(
	"`" +
		`(/?` +
		`(?:[a-zA-Z0-9_-]+/)*` +
		APIIndicatorAlternation +
		`[a-zA-Z0-9/_\{}.:-]*)` +
		"`",
)

// fullURLPattern matches absolute API URLs, e.g. "https://api.example.com/v1/users".
var fullURLPattern = regexp.MustCompile(
	`["'` + "`]" +
		`(https?://[a-zA-Z0-9._-]+(?::[0-9]+)?` +
		`/(?:[a-zA-Z0-9_-]+/)*` +
		APIIndicatorAlternation +
		`[a-zA-Z0-9/_\{}.:-]*)` +
		`["'` + "`]",
)

// APIIndicatorAlternation is the single source for API-signaling path segments.
// Every extraction regex (apiPathPattern, templateLiteralPattern, fullURLPattern,
// servicePrefixPattern) and apiIndicatorPattern embed it, so extraction and
// classification cannot drift.
//
// Exported for pkg/classify (LAB-4992): the classifier's Rule 3 gate
// (apiPathSegments + apiVersionPathPattern) must recognize every indicator this
// extractor can produce, or an offline concat/service-prefix candidate on an
// unrecognized indicator fails Rule 3, Rule 7's static-JS floor never fires, and it
// is silently dropped at the default confidence. classify's
// TestAPIIndicatorParityWithCrawlExtraction pins this exact string, so widening the
// set here fails that test until the classifier's gate is widened to match.
const APIIndicatorAlternation = `(?:api/|v[1-9][0-9]*/|rest/|rpc/|graphql)`

// servicePrefixPattern matches literal+literal `+`, e.g. "identity/" +
// "api/auth/login" captures "identity/". Backticks and non-literal operands go
// to extractTemplateLiteralPaths and extractConcatPaths (LAB-1368).
var servicePrefixPattern = regexp.MustCompile(
	`["']([a-zA-Z][a-zA-Z0-9_-]{1,30}/)["']\s*\+\s*["']` + APIIndicatorAlternation,
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
		APIIndicatorAlternation +
		`[a-zA-Z0-9/_{}.:-]*)` +
		`["']\s*\+`,
)

// ConcatPathSentinel is the exported form of concatPathSentinel, so
// pkg/analyze/jsstatic's concatDedupKey canonicalizes on the same value this
// package substitutes.
const ConcatPathSentinel = "0"

// concatPathSentinel replaces non-literal concat operands and +-chain operands.
// Numeric so rest.NormalizePathWithNames turns it into a named {param} (see
// pkg/generate/rest/normalize.go), and "0" rather than "{}" keeps the path valid
// enough to actually probe.
const concatPathSentinel = ConcatPathSentinel

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

// apiIndicatorPattern is sourced from APIIndicatorAlternation so it cannot drift
// from the extraction regexes.
var apiIndicatorPattern = regexp.MustCompile(`(?i)` + APIIndicatorAlternation)

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

// SameOrigin reports whether a and b share an origin (scheme, host, port),
// canonicalizing default ports so `https://h/x` and `https://h:443/y` compare equal.
// An unparseable or hostless URL fails closed to false.
//
// Exported for pkg/analyze/jsstatic (LAB-4992): the offline concat extractor must
// share this comparison rather than testing host and scheme separately, which does
// not canonicalize default ports — a reconstruction of `https://h:443/api/x` from a
// bundle served at `https://h/` would then fail the same-origin gate and be dropped,
// even though originOf here treats the two as identical.
func SameOrigin(a, b string) bool {
	oa := originOf(a)
	if oa == "" {
		return false
	}
	return oa == originOf(b)
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
//
// SEC-BE-001: u.Hostname() strips the brackets from an IPv6 literal ("[::1]" ->
// "::1"), so an IPv6 host is re-bracketed before being joined with ":" + port.
// Without that, two distinct URLs rebuild to the IDENTICAL bracket-less string
// "https://2001:db8::1:8443" — one with a real port outside the brackets
// ("https://[2001:db8::1]:8443/x") and one where that digit sequence is part of the
// literal itself with no port at all ("https://[2001:db8::1:8443]/x", which takes the
// https default 443) — making originOf non-injective for IPv6 targets. That
// collision merged a real observation and an attacker-authored candidate on a
// different IPv6 literal into one endpointKey.origin in pkg/generate/rest, and made
// the emitted `servers` URL and `info.title` syntactically invalid.
//
// SEC-BE: the re-bracketing is keyed on whether url.Parse itself bracketed u.Host,
// NOT on whether Hostname() contains a ":", because the two differ for a host that is
// not an IP literal at all:
//   - "https://foo:bar:80/api/x" is a malformed authority. url.Parse never bracketed
//     it, but Hostname() still returns "foo:bar" — Go splits on the LAST colon — so a
//     contains-":" check re-brackets it to "[foo:bar]:80", which does not re-parse as
//     the same origin and costs CanonicalOrigin its idempotency.
//   - "https://[fe80::1%25eth0]/x" IS bracketed, but carries an IPv6 zone ID.
//     Hostname() returns "fe80::1%eth0", and "%" outside percent-encoding is not
//     valid in a URL, so re-bracketing it verbatim also produces a string that does
//     not re-parse.
//
// Both shapes fail closed to "" rather than emitting a value that cannot re-parse.
// "" is originOf's documented "no usable origin", which every caller here and in
// pkg/generate/rest treats as "skip this candidate" and never as "same-origin"; a
// link-local zone-id address is not a legitimate scan target either. For a genuine
// bracketed IPv6 literal with no zone ID the check is a no-op, and url.Parse never
// brackets an IPv4 or DNS hostname in the first place.
func originOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	bracketed := strings.HasPrefix(u.Host, "[")
	host := strings.ToLower(u.Hostname())
	// Two shapes cannot yield a valid origin, so both fail closed rather than
	// fabricate a string that will not re-parse (see doc comment above):
	// a bracketed literal carrying a zone ID, whose "%" is invalid in a URL,
	// and a host containing ":" that url.Parse did NOT bracket, which is a
	// malformed authority rather than an IP literal.
	if (bracketed && strings.Contains(host, "%")) || (!bracketed && strings.Contains(host, ":")) {
		return ""
	}
	if bracketed {
		// Genuine bracketed IPv6 literal: put back the brackets Hostname()
		// stripped, so the origin stays syntactically valid and distinguishable
		// from a differently-bracketed spelling of a similar-looking literal.
		host = "[" + host + "]"
	}
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

// CanonicalOrigin returns the canonical "scheme://host[:port]" origin of rawURL for
// both comparison and display, or "" when rawURL does not parse to a usable http(s)
// origin with a host present. A host-less "absolute" URL such as "https:/api/x" — one
// slash after the scheme is not an authority marker — is rejected here rather than
// producing a degenerate "https://" origin, as are the two non-IP-literal host shapes
// originOf fails closed on (see originOf).
//
// It shares originOf's lower-casing and default-port equivalence, but strips a
// default port from the result rather than making it explicit, so the canonical form
// matches the conventional display shape ("https://example.com", not
// "https://example.com:443").
//
// Exported so pkg/generate/rest and any other origin-comparing consumer share
// exactly one definition of "origin" with this package, as [SameOrigin],
// [ResolveTargetOrigin] and [IsPrintableASCIIURL] are (LAB-4992). A second
// normalization disagreeing on host case-folding or default ports meant a trusted
// host spelled with an explicit ":443" or mixed case never string-equalled the same
// host derived from an endpoint URL, letting a colliding attacker-controlled origin
// win a tie-break the trusted host should have won.
func CanonicalOrigin(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return ""
	}
	origin := originOf(rawURL)
	if dp := defaultPortForScheme(strings.ToLower(u.Scheme)); dp != "" {
		origin = strings.TrimSuffix(origin, ":"+dp)
	}
	return origin
}

// firstHTMLOrigin binds replay to the real app page rather than the first capture
// entry, which in an imported mixed-origin capture may be a third-party asset. It
// reuses the <script>-discovery loop's HTML detection so the two stay consistent, and
// returns "" when no response is HTML.
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

// ResolveTargetOrigin derives "the target origin" for a scan from an explicit target
// URL and an observed request set, in priority order:
//  1. explicit targetURL, if it parses to a usable origin;
//  2. the origin of the first request whose RESPONSE is HTML (the real app page) —
//     see firstHTMLOrigin;
//  3. the origin of the first request with a non-empty URL.
//
// Returns "" if none yields a usable origin.
//
// A non-empty targetURL that fails to canonicalize does NOT fall through to the
// capture-derived steps (SEC-BE-001, LAB-4992). The request set may contain synthetic
// static:js entries whose URLs are reconstructed from bundle text, because
// pipeline.Augment runs before the JS-replay hook, so falling through would let a
// hostile bundle supply the origin that receives --header credentials — silently
// rebinding a pinned target to one the capture's own content chose. An explicitly
// pinned target that cannot be honored fails closed. The capture-derived fallback is
// correct and intended only for targetURL == "" (`generate` with no --target-url),
// where there is no pinned target to betray.
//
// Preferring the HTML page over the first request matters for mixed-origin or
// imported captures (HAR, Burp) whose first entry may be a third-party asset, a CDN
// font or an analytics beacon: binding to that asset's origin leaves the app's own
// same-origin bundles looking cross-origin (LAB-3892). Single-origin crawl captures
// are unaffected — their first entry is the HTML page anyway.
//
// Exported and shared (SEC-BE-001) so ReplayJSExtracted and the probe-stage
// cross-origin gate in internal/pipeline agree on what "the target origin" means for
// a given scan; two independent derivations could diverge and reopen the cross-origin
// gap one of them closes.
func ResolveTargetOrigin(targetURL string, requests []ObservedRequest) string {
	if targetURL != "" {
		// Fail closed here rather than falling through — see doc comment.
		return originOf(targetURL)
	}
	if origin := firstHTMLOrigin(requests); origin != "" {
		return origin
	}
	for _, req := range requests {
		if req.URL == "" {
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
	// Delegates to the exported SameOrigin so this package has exactly one
	// origin-comparison implementation (QUAL-002). The guards are equivalent:
	// a "" targetOrigin yields originOf("") == "", which SameOrigin never
	// reports equal because it first requires a non-empty left origin.
	return SameOrigin(rawURL, targetOrigin)
}

// IsAbsoluteHTTPURL reports whether raw carries an http or https scheme,
// case-insensitively. url.Parse lower-cases the scheme, so a bundle literal
// spelled "HTTPS://host/x" is absolute to every downstream consumer; a
// case-sensitive strings.HasPrefix check would classify it as relative and send
// it down a path-resolution branch instead (QUAL-003). Shared with
// pkg/analyze/jsstatic so the offline and active paths classify identically.
//
// This answers only "does it have an http(s) scheme". It is NOT a validity
// check — callers that act on the URL must still run ValidateFullURL (embedded
// credentials, empty host) and, before any request, ssrf.ValidateURL.
func IsAbsoluteHTTPURL(raw string) bool {
	lower := strings.ToLower(raw)
	return strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")
}

// sanitizeForLog stops an attacker-controlled bundle string injecting ANSI
// sequences or NULs into the operator's terminal.
func sanitizeForLog(s string) string {
	if s == "" {
		return s
	}
	return strconv.Quote(s)
}

// SanitizeForLog is the exported form of sanitizeForLog (SEC-BE-002, LAB-4992).
// internal/pipeline's probe-stage cross-origin gate prints attacker-influenced URLs
// and origins to the same always-on operator sink this package's own warnings use, so
// it must apply the identical sanitizer rather than growing a second one that can
// diverge. sanitizeForLog remains the single implementation.
func SanitizeForLog(s string) string {
	return sanitizeForLog(s)
}

// warnDerivedOrigin names the origin replay will hit, and the credentials going
// with it, when --target-url is unset. Never gated on Verbose: the operator did
// not choose this origin, the capture did. targetOrigin goes through sanitizeForLog
// for parity with this file's other URL logging. Interim; redesign is LAB-4998.
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

// ValidateFullURL is the parse-time gate: it rejects embedded credentials,
// non-http(s) schemes and empty hosts, returning the canonicalized URL on success. It
// does NOT reject private IP literals — callers MUST also run ssrf.ValidateURL before
// issuing a request.
//
// Exported for pkg/analyze/jsstatic (SEC-BE-001, LAB-4992): the fully-offline concat
// extractor emits absolute reconstructions too and must apply this same gate. A
// host-only comparison does not suffice, because net/url puts userinfo in u.User, not
// u.Host, so `"https://".concat("u:p@<bundlehost>/api/x")` has a host equal to the
// bundle's own and would pass. Since probe.Config.AuthHeaders is populated by no
// non-test caller, net/http would then derive `Authorization: Basic
// <base64(userinfo)>` from req.URL.User and send attacker-chosen credentials to the
// target on the operator's behalf.
func ValidateFullURL(raw string) (string, bool) {
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
	if !strings.HasPrefix(candidate, "/") && !IsAbsoluteHTTPURL(candidate) {
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
		p = cleanConcatPath(p)
		if p == "" || seen[p] {
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

		if IsAbsoluteHTTPURL(raw) {
			cleaned, ok := ValidateFullURL(raw)
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

	// Strategy 5: .concat() and `+` chains (LAB-1368). Reconstructed paths use a
	// numeric sentinel for non-literal operands so the REST normalizer can
	// parameterize them. Last, so the more precise strategies win the dedup race.
	// Strategy 4, literal+literal prefix concat, has no block of its own —
	// extractServicePrefixes plus the addPath fan-out above does it.
	for _, p := range extractConcatPaths(jsBody) {
		addPath(p)
	}

	// Strategy 5b: literal service-prefix +-concat (LAB-4992). Shares
	// servicePrefixPlusPaths with the fully-offline static path (via
	// ExtractStaticConcatPaths) so both reconstruct the
	// `"identity/" + "api/auth/login"` form identically; replay additionally
	// probes and 404-filters the reconstructions. Without this the "share one
	// extractor / reconstruct identically" contract held only for the offline
	// path — extractConcatPaths above misses the literal+literal service-prefix
	// head that servicePrefixPlusPaths recovers.
	for _, p := range servicePrefixPlusPaths(jsBody) {
		addPath(p)
	}

	return paths
}

// cleanConcatPath collapses `//` runs in a reconstructed concat path (preserving
// a `://` scheme separator) and rejects the path — returning "" — when it is
// empty, carries no API indicator, or contains whitespace. Shared by
// extractConcatPaths' emit() and servicePrefixPlusPaths so both concat
// reconstruction forms filter and canonicalize identically.
//
// `//` runs arise from literal+literal concatenations where the head literal
// ends in `/` and the next literal begins with `/` (e.g. `"/api/posts/" +
// "/comment"`). The REST normalizer treats `//{id}` as a distinct (malformed)
// segment, so collapsing here keeps reconstructed paths well-formed. Looping
// until stable handles rare >=3-slash runs.
//
// The `//`-collapse and `://` scheme detection operate only on the path portion:
// a query string / fragment is split off first so a relative path whose query
// carries an absolute URL (e.g. `"/api//proxy?url=https://x"`) is not mistaken
// for a scheme-bearing URL, and `//` inside a query value is preserved.
func cleanConcatPath(p string) string {
	path, suffix := p, ""
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		path, suffix = p[:i], p[i:]
	}

	if scheme, rest, hasScheme := strings.Cut(path, "://"); hasScheme {
		for strings.Contains(rest, "//") {
			rest = strings.ReplaceAll(rest, "//", "/")
		}
		path = scheme + "://" + rest
	} else {
		for strings.Contains(path, "//") {
			path = strings.ReplaceAll(path, "//", "/")
		}
	}

	// Trim trailing slashes so this extractor canonicalizes paths IDENTICALLY to
	// addPath ("ensure leading slash, trim trailing slash"), which is the shared
	// contract for every other extractor in this file (QUAL-002, LAB-4992).
	// Previously only the leading slash was normalized downstream and no side
	// trimmed here, so a reconstruction like `"/api/orders/" + id + "/"` emitted
	// /api/orders/0/ while the active path's equivalent emitted /api/orders/0.
	// Two consequences, both spec-visible:
	//
	//  1. NormalizePathWithNames splits and rejoins on '/', so the trailing empty
	//     segment survives: the offline mirror produced the OpenAPI path
	//     `/api/orders/{orderId}/` while the live js-extract entry for the same
	//     reconstruction produced `/api/orders/{orderId}` — two distinct
	//     groupEndpoints keys for one endpoint, and neither merged with a real
	//     dynamic observation of GET /api/orders/5 (which normalizes unslashed).
	//  2. reachedPathKey trims the trailing slash on BOTH sides, so a live probe
	//     of the unslashed form superseded the correctly-slashed mirror. On a
	//     trailing-slash-required API (Django/DRF, Flask strict_slashes) that
	//     probe 404s, so the mirror was dropped and the endpoint lost outright.
	//
	// Canonicalizing here rather than at each emitter keeps the active and
	// offline paths from drifting again, which is this change's design goal. The
	// trim applies to the path portion only, so a trailing slash inside a query
	// value is preserved (addPath trims the whole string; the difference only
	// matters for query-bearing reconstructions, where trimming the path is the
	// correct reading). A path that trims away entirely (e.g. "/") fails the
	// hasAPIIndicator check below, as it did before.
	path = strings.TrimRight(path, "/")
	p = path + suffix

	if p == "" || !hasAPIIndicator(p) {
		return ""
	}
	// Enforce a strict ASCII ALLOW-list over the reconstruction (SEC-BE-002,
	// third pass). This is the only extractor in this file that admits arbitrary
	// bytes: parseConcatArgs / readChainOperand -> stringLiteralValue copy
	// string-literal operand bytes VERBATIM with no character class, so whatever
	// a hostile bundle puts inside a `.concat()` argument or `+`-chain operand
	// lands here, and the ASCII `api/` elsewhere in the path still satisfies
	// hasAPIIndicator. The sibling extractors (apiPathPattern,
	// templateLiteralPattern, fullURLPattern, servicePrefixPattern) all already
	// constrain their captures to an ASCII class, so an allow-list here brings
	// this path in line with them rather than inventing a new policy.
	//
	// An allow-list replaced an enumerate-the-bad-categories block-list, which
	// kept losing this race. The block-list's first form (`r == ' ' ||
	// unicode.IsControl(r)`) let every rune above U+00FF through, because
	// unicode.IsControl consults only the Latin-1 table — U+202A-U+202E bidi
	// override, U+200B ZWSP, U+FEFF BOM, U+00A0 NBSP, U+3000. Widening it to
	// Zs/Cc/Cf/Zl/Zp closed those but still admitted homoglyphs (Cyrillic а),
	// fullwidth slash lookalikes (U+FF0F), combining marks (U+0301) and variation
	// selectors (U+FE0F, category Mn — not Cf). Inverting the predicate closes the
	// entire non-ASCII class at once and needs no width-1 utf8.RuneError special
	// case, since every byte >= 0x80 simply is not in the set.
	//
	// The HTTP request path was never the exposure — net/url percent-encodes
	// non-ASCII in EscapedPath(), so there is no request-splitting or
	// header-injection vector. The sink is the operator-facing artifact: yaml.v3
	// emits these bytes RAW into the generated OpenAPI path key, so a scanned site
	// could make a spec path RENDER differently from the bytes it contains (RTL
	// override, homoglyph) or hide segments behind zero-width runes —
	// report/deliverable spoofing during an assessment.
	//
	// `?`, `=`, `&` and `#` are legal only in the query/fragment suffix, which is
	// why the two portions are checked against different sets: a bare `?` inside
	// what cleanConcatPath treats as the path would mean the split above did not
	// happen, i.e. a malformed reconstruction.
	if !allowedConcatBytes(path, false) || !allowedConcatBytes(suffix, true) {
		return ""
	}
	return p
}

// allowedConcatBytes reports whether every byte of s is admissible, treating a
// `%` as the start of a percent-escape that must be well-formed AND must decode
// to a printable ASCII byte.
//
// The decode check is what closes the percent-encoding route around the
// allow-list (SEC-BE-002, third pass). Permitting a bare `%` was not enough:
// `/api/x%E2%80%AEy` passes a byte-wise allow-list unchanged, and the sink
// DECODES — url.Parse populates u.Path with the raw bytes E2 80 AE, groupEndpoints
// keys the OpenAPI path on u.Path, and yaml.v3's is_printable admits a 0xE2 lead
// byte — so a U+202E right-to-left override reached the generated spec path key
// raw, which is the exact deliverable-spoofing the allow-list was written to
// prevent. Requiring the decoded byte to be printable ASCII (0x20-0x7E) rejects
// every non-ASCII escape and every encoded control byte (%00, %0A, %7F) while
// still admitting the encodings real APIs use (%20, %2F, %3D, %5B).
func allowedConcatBytes(s string, inSuffix bool) bool {
	return scanEscapedBytes(s, func(c byte) bool {
		return isAllowedConcatByte(c, inSuffix)
	})
}

// scanEscapedBytes walks s and reports whether every byte is admissible: a
// literal byte must satisfy isLiteralByte, and a `%` must start a
// well-formed percent-escape that decodes to printable ASCII (see
// validPercentEscape) — the escape-handling half of the policy is identical
// for every caller, so it lives here once rather than in each caller's own
// loop (QUAL-002).
//
// isLiteralByte is where callers differ: allowedConcatBytes gates non-`%`
// bytes through isAllowedConcatByte (parameterized on inSuffix via closure,
// so that concat-specific concept never leaks into this shared loop), while
// IsPrintableASCIIURL gates them with a direct 0x21-0x7E range check.
func scanEscapedBytes(s string, isLiteralByte func(byte) bool) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			if !isLiteralByte(s[i]) {
				return false
			}
			continue
		}
		if !validPercentEscape(s, i) {
			return false
		}
		// Skip the two hex digits; the loop's own i++ accounts for the '%'.
		i += 2
	}
	return true
}

// validPercentEscape reports whether the escape starting at s[i] (which must
// be '%') is well-formed and decodes to printable ASCII (0x20-0x7E). It
// reports false when the escape is truncated ("/api/x%", "/api/x%E"),
// contains a non-hex digit, or decodes to anything other than printable
// ASCII.
//
// The printable-ASCII requirement is the load-bearing part (SEC-BE-002): a
// byte-wise allow-list that merely permits `%` is trivially routed around,
// because the sink DECODES. url.Parse populates u.Path with the decoded bytes,
// groupEndpoints keys the OpenAPI path on u.Path, and yaml.v3 emits a 0xE2 lead
// byte raw — so `/api/x%E2%80%AEy` delivered a U+202E right-to-left override into
// the generated spec path key. Rejecting non-printable decodes also covers
// encoded controls (%00, %0A, %7F) in one predicate.
//
// Uses encoding/hex rather than a hand-rolled digit decoder so the accepted digit
// set (both cases, exactly [0-9A-Fa-f]) is the standard library's rather than
// something this file has to get right and keep right.
func validPercentEscape(s string, i int) bool {
	if i+2 >= len(s) {
		return false
	}
	buf, err := hex.DecodeString(s[i+1 : i+3])
	if err != nil {
		return false
	}
	if buf[0] < 0x20 || buf[0] > 0x7E {
		return false
	}
	return true
}

// IsPrintableASCIIURL reports whether raw is safe to place in an operator-facing
// artifact: every literal byte is printable, non-space ASCII, and every
// percent-escape decodes to printable ASCII.
//
// Exported so pkg/analyze/jsstatic can apply ONE byte policy to every producer at
// its synthesis choke point (SEC-BE-002). Previously the policy lived only in
// cleanConcatPath, which guards the concat/service-prefix reconstruction — so the
// jsluice AST-literal producer, whose only filter (filterURL) checks schemes and
// asset extensions, had no charset check at all. That mattered because classify
// Rule 7 floors EVERY IsJSStaticSource candidate to the default --confidence, so
// AST literals that previously died at 0.15 now survive: `fetch("/api/v1/<U+202E>nimda")`
// reached the generated OpenAPI path key with the override intact, and the
// absolute variant put a raw-bidi host in the spec's servers list and info.title.
// pkg/generate/rest applies no printable-ASCII filter of its own.
//
// Space is excluded deliberately (0x21 lower bound): a literal space cannot occur
// in a URL that survived extraction, so admitting one would only widen the set
// for no gain. A percent-ENCODED space (%20) is still accepted, since that is how
// real APIs spell it.
//
// Tradeoff, accepted and documented: a genuinely internationalized host or path
// spelled in raw UTF-8 (an IDN like https://münchen.example/api) is rejected
// rather than percent-encoded. That matches what cleanConcatPath has always done
// to the concat path, keeps one policy across producers, and costs recall only for
// non-ASCII APIs, which this extractor was never able to reconstruct reliably
// anyway.
func IsPrintableASCIIURL(raw string) bool {
	return scanEscapedBytes(raw, func(c byte) bool {
		return c >= 0x21 && c <= 0x7E
	})
}

// isAllowedConcatByte reports whether c may appear literally in a reconstructed
// candidate path. ASCII-only by construction: every byte >= 0x80 falls through to
// false, so no raw non-ASCII rune can reach a generated spec path key
// (SEC-BE-002). inSuffix admits the query/fragment delimiters, which would mean a
// malformed reconstruction if they appeared in the path portion.
//
// `%` is deliberately NOT handled here — allowedConcatBytes intercepts it first so
// the escape can be validated as a unit.
func isAllowedConcatByte(c byte, inSuffix bool) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	switch c {
	// Structural and RFC 3986 sub-delims / unreserved punctuation that
	// legitimately appear in API paths, plus `{}` for the {param} placeholders the
	// REST normalizer emits.
	case '/', '_', '-', '.', ':', '{', '}', '~', '@', '!', '$', '\'', '(', ')', '*', '+', ',', ';':
		return true
	// QUAL-004: brackets and the pipe are gen-delims/unreserved-in-practice that
	// real APIs use heavily in query syntax — `?filter[status]=open` (JSON:API and
	// PHP-style array params) and `?q=a|b`. The first allow-list omitted them, so
	// those endpoints were silently dropped, which is a recall regression rather
	// than a security gain: both are plain ASCII and cannot spoof a rendered path.
	// Admitted in the path portion too, since the pre-allow-list block-list
	// accepted them there and nothing about a path makes them dangerous.
	case '[', ']', '|':
		return true
	case '?', '=', '&', '#':
		return inSuffix
	}
	return false
}

// servicePrefixPlusHeadPattern matches the head of a `+`-concat chain whose
// first operand is a quoted service-prefix literal — a short slash-terminated
// segment that does NOT itself have to contain an API indicator (e.g.
// "identity/", "svc/"). It is the service-prefix analog of
// concatPlusHeadPattern, which requires the head to contain an API indicator
// and therefore misses the literal+literal service-prefix form
// `"identity/" + "api/auth/login"`.
//
// The head must start with a letter (no leading slash) so this pattern does not
// re-match the leading-slash heads already handled by concatPlusHeadPattern.
// cleanConcatPath's hasAPIIndicator post-filter drops any assembled chain that
// never reaches an API path, so a bare `"assets/" + x` produces nothing.
var servicePrefixPlusHeadPattern = regexp.MustCompile(
	`["']([a-zA-Z][a-zA-Z0-9_-]{0,30}/)["']\s*\+`,
)

// servicePrefixPlusPaths reconstructs concrete `+`-concat chains whose head is a
// service-prefix literal (`"identity/" + "api/auth/login"` -> identity/api/auth/login,
// `"identity/" + id + "/api/x"` -> identity/0/api/x). It reuses parsePlusChain
// for the tail walk (same numeric sentinel for non-literal operands) and
// cleanConcatPath for the API-indicator filter, so it reconstructs identically
// to the other concat forms. Bounded by maxConcatPathsPerBundle.
func servicePrefixPlusPaths(jsBody []byte) []string {
	var paths []string
	seen := make(map[string]bool)
	for _, match := range servicePrefixPlusHeadPattern.FindAllSubmatchIndex(jsBody, -1) {
		if len(paths) >= maxConcatPathsPerBundle {
			break
		}
		if len(match) < 4 || match[2] < 0 {
			continue
		}
		head := string(jsBody[match[2]:match[3]])
		suffix := parsePlusChain(jsBody, match[1])
		p := cleanConcatPath(head + suffix)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		paths = append(paths, p)
	}
	return paths
}

// ExtractStaticConcatPaths reconstructs API paths built by JS string
// concatenation from a single JS bundle body, using only network-free logic:
// String.prototype.concat, `+`-operator chains, and literal service-prefix
// `+`-concatenation. Non-literal operands are replaced with the numeric sentinel
// ("0") so the reconstructed path stays parameterizable by the REST normalizer.
//
// It is the offline-safe entry point shared with pkg/analyze/jsstatic (LAB-4992)
// so the fully-offline static analyzer reconstructs concat / service-prefix SPA
// endpoints identically to the active ReplayJSExtracted path — which additionally
// re-fetches the bundles and probes the reconstructed paths. Unlike the active
// extractAPIPaths, it deliberately does NOT perform speculative service-prefix
// fan-out (combining a discovered prefix with every bare path): those
// combinations are only safe when probed and 404-filtered, which the offline
// path cannot do. Returns raw reconstructions (deduped); the caller adds the
// leading slash and resolves relative paths.
func ExtractStaticConcatPaths(jsBody []byte) []string {
	seen := make(map[string]bool)
	var out []string
	add := func(p string) {
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	for _, p := range extractConcatPaths(jsBody) {
		add(p)
	}
	for _, p := range servicePrefixPlusPaths(jsBody) {
		add(p)
	}
	return out
}

// --- Main pipeline ---

// ReplayJSExtracted extracts API paths from captured JS bodies, probes them over
// raw HTTP, and appends what answers to the returned slice.
//
// It exists because a headless crawl cannot exercise paths that need user
// interaction or auth state, or that jsluice cannot resolve. Raw HTTP does not
// escape a server-side catch-all: a wrong path still returns the SPA shell, which
// is why fetchJSBodyHop filters HTML. Defenses are in the file header.
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

	// Origin priority and rationale live on ResolveTargetOrigin: explicit
	// cfg.TargetURL, then the HTML page's origin, then the first non-empty request URL.
	targetOrigin := ResolveTargetOrigin(cfg.TargetURL, requests)
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

	// refuted records the reachedPathKey of every full URL the target answered
	// 404 for. Those paths — and ONLY those — have a dispositive negative
	// verdict, so supersedeConcatMirrors drops their passive offline concat
	// mirror after the loop; see its doc comment for what survives a non-404 and
	// why, and reachedPathKey's for why the key is path-only, not origin+path.
	//
	// QUAL-004: this set was previously populated for ANY answered status, which
	// made live replay SUBTRACTIVE — supplying a reachable --target-url produced
	// STRICTLY LESS output than running fully offline, inverting the feature on
	// exactly the deployment shape JS-replay exists for. probeURL returns a
	// non-nil *ObservedResponse for every completed exchange regardless of status
	// or content type, so a 200 text/html SPA catch-all (nginx try_files), a 204,
	// an HTML-bodied 401/403, or a 302 -> /login all deleted the mirror; and the
	// replacement appended below carries Source "js-extract", which
	// crawl.IsJSStaticSource does NOT match, so classify Rule 7's
	// StaticJSConfidence floor never applies to it — it scores only Rule 3's 0.15
	// and is dropped at the 0.5 default threshold. Measured end-to-end, the spec
	// went from one path to zero. Restricting the set to 404 keeps the decoy
	// filter this exists for while making replay purely additive.
	//
	// SEC-BE-004: a 404 is the best available signal, but it is NOT proof of
	// absence. Returning 404 rather than 401/403 for an unauthorized-but-real
	// resource is a widespread anti-enumeration convention, and doRequest's
	// fixed User-Agent lets a hostile target fingerprint this scanner and 404
	// everything to hide its API surface. So an unauthenticated run can drop a
	// real endpoint here.
	//
	// That ambiguity is NOT resolvable by probing. A control probe of a random
	// nonexistent path was implemented and reverted: a correctly-behaving
	// server 404s such a path precisely BECAUSE it does not exist, so the
	// control response is identical for an honest server and for an
	// anti-enumeration one — it misclassified every normal target (caught by
	// the concat-spa live test, whose mux 404s unknown paths) while giving no
	// signal at all for the case it was written to detect. Distinguishing
	// "absent" from "unauthorized" requires credentials, not another request.
	//
	// What is done instead: the drop is ANNOUNCED. Each dropped path is named
	// on Warnings with the two remedies (--header, --probe=false), so the loss
	// is visible and recoverable rather than silent. Do not reintroduce a
	// probe-based gate here without a signal that actually separates the two
	// cases.
	refuted := make(map[string]bool)

	probed := 0
	for _, path := range sortedPaths {
		if probed >= cfg.MaxEndpoints {
			break
		}

		fullURL := path
		// Defense-in-depth only: IsAbsoluteHTTPURL is case-insensitive, but nothing
		// reaches here with a mixed-case scheme today because fullURLPattern (and the
		// other extraction regexes) require a lowercase `https?://`, so such a literal
		// is never extracted. Kept case-insensitive anyway so this branch stays correct
		// if extraction is ever widened — but it is NOT unit-tested for that input,
		// because a test would be vacuous (see TestIsAbsoluteHTTPURLCallSites).
		if !IsAbsoluteHTTPURL(path) {
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
		// 404 means a wrong prefix combination (/identity/api/shop/products when the
		// correct prefix is /workshop/); keeping them pollutes the spec with endpoints
		// that do not exist. It is also the only DISPOSITIVE verdict, so it is the only
		// status that refutes the offline concat mirror for this path — see refuted's
		// doc comment.
		//
		// SEC-BE-004: the drop is announced on Warnings rather than performed silently,
		// because no probe can separate "absent" from "unauthorized" (again, see
		// refuted). Naming each dropped path is what lets an operator notice the loss
		// and re-run with --header or --probe=false.
		if resp.StatusCode == http.StatusNotFound {
			refuted[reachedPathKey(fullURL)] = true
			warnf("js-extract: %s answered 404; dropping its offline js-concat mirror "+
				"(re-run with --header if this endpoint is auth-gated, or --probe=false to keep every offline candidate)\n",
				sanitizeForLog(fullURL))
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

	return supersedeConcatMirrors(result, refuted)
}

// supersedeConcatMirrors drops the passive offline concat mirror
// (SourceStaticJSConcat, emitted by pkg/analyze/jsstatic) for every path the
// live probe REFUTED with a 404, so a decoy the target 404s does not leak back
// into the spec via the mirror. Candidates for paths that were never probed, or
// that answered with any non-404 status, are left untouched — the offline
// fallback (LAB-4992 AC1) and the additive-replay guarantee (QUAL-004)
// respectively. Matching is host-agnostic (path-only, QUAL-001): the mirror is
// dropped whether or not the bundle it was reconstructed against shares a host
// with the probe target.
//
// Only SourceStaticJSConcat is superseded. Plain SourceStaticJS and
// SourceStaticJSSourcemap mirrors survive a 404 deliberately: an AST literal is
// recovered from a real call site in the bundle, so a 404 there is more likely
// auth/param-gated than a wrong-guess decoy, unlike an unvalidated combinatorial
// reconstruction. pkg/classify/rest.go's staticJSFloor documents the same
// asymmetry from the classifier side; TestReplayJSExtracted_KeepsNonConcatMirrorsForRefutedPaths
// pins it. Do not widen this predicate to crawl.IsJSStaticSource without
// revisiting that reasoning.
//
// Residual limitation: paths beyond cfg.MaxEndpoints are never probed, so they
// never enter refuted and their offline mirror is retained — a decoy past the cap
// can still surface. This matches the pre-existing MaxEndpoints truncation
// semantics and is bounded by that cap.
//
// Extracted from ReplayJSExtracted (QUAL-004) so probe I/O and result filtering
// are separable and independently testable.
func supersedeConcatMirrors(result []ObservedRequest, refuted map[string]bool) []ObservedRequest {
	if len(refuted) == 0 {
		return result
	}
	filtered := result[:0]
	for _, r := range result {
		if r.Source == SourceStaticJSConcat && refuted[reachedPathKey(r.URL)] {
			continue
		}
		filtered = append(filtered, r)
	}
	return filtered
}

// reachedPathKey normalizes rawURL to a path-only key so the live-probe
// reached-set matches the offline concat mirror regardless of which origin
// each side resolved the URL against (LAB-4992 QUAL-001). jsstatic resolves
// the mirror URL against the bundle/capture origin — which may be a CDN
// hosting the JS, or differ from an operator-pinned --target-url — while
// JS-replay always builds its probe URL from the target origin. Keying on
// origin+path (the previous approach) silently no-ops the mirror-drop
// whenever those origins differ, re-opening the 404-decoy leak; matching on
// path alone (trailing slash trimmed, consistent with the rest of this
// file's normalization) drops the mirror host-agnostically.
//
// Unparseable URLs and URLs with no path component fall back to the raw
// string so a malformed input degrades to an exact (narrower, still safe)
// match rather than silently colliding with every other empty-path URL.
func reachedPathKey(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	path := u.EscapedPath()
	if path == "" {
		return rawURL
	}
	if path != "/" {
		path = strings.TrimRight(path, "/")
	}
	return path
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
