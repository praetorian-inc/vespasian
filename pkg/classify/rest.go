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

package classify

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/praetorian-inc/vespasian/pkg/crawl"
	"github.com/praetorian-inc/vespasian/pkg/mediatype"
)

// staticExtensions lists file extensions that indicate static assets.
var staticExtensions = []string{
	".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".ico",
	".woff", ".woff2", ".ttf", ".eot", ".svg", ".map",
}

// staticPathSegments lists path segments that indicate static asset directories.
var staticPathSegments = []string{
	"/static/", "/assets/", "/dist/", "/bundle/",
}

// apiContentTypes lists content types that indicate API responses.
var apiContentTypes = []string{
	"application/json", "application/xml", "text/xml", "application/problem+json",
	"application/vnd.api+json", "application/hal+json",
}

// apiPathSegments lists literal path segments that indicate API endpoints.
// Versioned segments (/v1/, /v2/, …) are matched separately by
// apiVersionPathPattern so any version number is recognized, not a fixed few.
var apiPathSegments = []string{
	"/api/", "/rest/", "/rpc/", "/graphql",
}

// apiVersionPathPattern matches a versioned API path segment for ANY version
// number (/v1/, /v2/, …/v4/…/v12/). It mirrors the v[1-9][0-9]*/ alternation in
// crawl.apiIndicatorAlternation so the classifier's API-indicator recognition
// does not drift below the extraction side — otherwise offline concat/service-
// prefix candidates on /v4+/ paths (which crawl extracts) would fail Rule 3,
// so Rule 7's static-JS floor would never fire and they would be dropped at the
// default confidence (LAB-4992).
var apiVersionPathPattern = regexp.MustCompile(`/v[1-9][0-9]*/`)

// Confidence scores assigned by each heuristic rule.
const (
	ContentTypeConfidence = 0.8  // Rule 2: API content-type match.
	PathHeuristicBoost    = 0.15 // Rule 3: API path segment boost.
	HTTPMethodConfidence  = 0.7  // Rule 4: Non-GET HTTP method signal.
	JSONBodyConfidence    = 0.85 // Rule 5: JSON response structure.
	// RequestSignalConfidence is assigned by Rule 6 when a request shows API
	// intent (an API path together with a JSON/XML Accept or request
	// content-type) even if no response was captured. It is deliberately set at
	// or above DefaultConfidenceThreshold so a JSON API reached by GET whose
	// response arrived too late to capture still classifies — the REST-vs-not
	// verdict then depends on the request, not on response timing (LAB-4678, B2).
	RequestSignalConfidence = 0.6
	// StaticJSConfidence is the floor for an offline JS-static candidate whose
	// path carries an API indicator (Rule 7). It equals the default --confidence
	// threshold (0.5) so these unprobed candidates survive fully-offline
	// generation instead of being dropped at Rule 3's 0.15 (LAB-4992).
	StaticJSConfidence = 0.5
)

// RESTClassifier classifies REST API requests using ordered heuristic rules.
type RESTClassifier struct{}

// Name returns the classifier name.
func (c *RESTClassifier) Name() string {
	return "rest"
}

// Classify determines if the request is a REST API call.
func (c *RESTClassifier) Classify(req crawl.ObservedRequest) (bool, float64) {
	isAPI, confidence, _ := c.ClassifyDetail(req)
	return isAPI, confidence
}

// ClassifyDetail returns classification result with a detailed reason string.
//
// Heuristic rules applied in order:
//  1. Static asset exclusion → (false, 0, "")
//  2. Content-type filter → confidence 0.8
//  3. Path heuristics → boost +0.15 (cap 1.0)
//  4. HTTP method signal → confidence max(current, 0.7)
//  5. Response structure → confidence max(current, 0.85)
//  6. Request-side API signal → confidence max(current, RequestSignalConfidence) when the
//     path carries an API indicator AND the request itself shows JSON/XML intent
//     (Accept or request content-type), regardless of whether a response was captured
//  7. Offline JS-static candidate floor → confidence max(current, StaticJSConfidence) when the path carries an API indicator
func (c *RESTClassifier) ClassifyDetail(req crawl.ObservedRequest) (bool, float64, string) { //nolint:gocyclo // multi-signal heuristic classifier
	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		return false, 0, ""
	}

	lowerPath := strings.ToLower(parsedURL.Path)

	// Rule 1: Static asset exclusion.
	for _, ext := range staticExtensions {
		if strings.HasSuffix(lowerPath, ext) {
			return false, 0, ""
		}
	}
	for _, seg := range staticPathSegments {
		if strings.Contains(lowerPath, seg) {
			return false, 0, ""
		}
	}

	var confidence float64
	var reason string

	// Rule 2: Content-type filter. rule2CT records the API media type matched
	// on the response so Rule 6 can avoid re-reporting the same content type as
	// a request-side signal (QUAL-005).
	respCT := req.Response.ContentType
	if respCT == "" {
		respCT = mediatype.Header(req.Response.Headers, "content-type")
	}
	rule2CT := matchAPIContentType(respCT)
	if rule2CT != "" {
		confidence = ContentTypeConfidence
		reason = appendReason(reason, "content-type:"+rule2CT)
	}

	// pathIsAPI is computed once here and reused by Rule 3 (confidence boost),
	// Rule 6 (request-side signal gate) and Rule 7 (offline JS-static floor) so
	// the API-path scan runs once rather than repeatedly in the same call
	// (QUAL-003).
	pathIsAPI := false
	for _, seg := range apiPathSegments {
		if strings.Contains(lowerPath, seg) {
			pathIsAPI = true
			break
		}
	}
	// A bare version segment (/v1/, /v2/, ...) is an API indicator too, even
	// with no "api"-style word in the path. Offline JS-static candidates from
	// SPA bundles routinely look like /v2/users, and without this they would
	// never satisfy Rule 7's gate and would be dropped at the default
	// confidence (LAB-4992).
	if !pathIsAPI && apiVersionPathPattern.MatchString(lowerPath) {
		pathIsAPI = true
	}

	// Rule 3: Path heuristics.
	if pathIsAPI {
		confidence += PathHeuristicBoost
		if confidence > 1.0 {
			confidence = 1.0
		}
		reason = appendReason(reason, "path-heuristic")
	}

	// Rule 4: HTTP method signal.
	// Every rule that detects its signal appends to the reason (not only when
	// the reason is still empty) so the reason lists ALL contributing signals
	// and matches the final confidence. Otherwise a POST on an /api/ path would
	// report reason=path-heuristic (0.15) while confidence is 0.70 from this
	// rule — attributing the score to the wrong signal.
	upper := strings.ToUpper(req.Method)
	if upper == "POST" || upper == "PUT" || upper == "PATCH" || upper == "DELETE" {
		if confidence < HTTPMethodConfidence {
			confidence = HTTPMethodConfidence
		}
		reason = appendReason(reason, "method:"+upper)
	}

	// Rule 5: Response structure (JSON body).
	// Forward-only scan: find first non-whitespace byte without scanning
	// the entire body from both ends (avoids O(n) scan on large bodies).
	if len(req.Response.Body) > 0 {
		if b, ok := firstNonSpace(req.Response.Body); ok && (b == '{' || b == '[') {
			if confidence < JSONBodyConfidence {
				confidence = JSONBodyConfidence
			}
			reason = appendReason(reason, "response-structure:json")
		}
	}

	// Rule 6: Request-side API signal (LAB-4678, B2).
	// Rules 2 and 5 need a fully-arrived response, so a JSON API reached by GET
	// whose response was captured half-finished (empty content-type and body)
	// falls to the path boost alone (0.15) and is dropped — making the
	// REST-vs-not verdict a function of response timing rather than a property
	// of the app. When the request itself shows API intent on an API path,
	// classify it regardless of whether the response was captured, so the
	// verdict is stable for a given input. Non-GET methods are already covered
	// by Rule 4 (0.7) independent of response timing; this rule closes the
	// GET-with-JSON-intent gap. The API-path match alone is NOT sufficient (that
	// stays at the Rule 3 boost) to avoid classifying plain navigations under
	// api-like paths.
	if pathIsAPI {
		signal := ""
		if apiCT := acceptSignalsAPI(mediatype.Header(req.Headers, "accept")); apiCT != "" {
			signal = "accept:" + apiCT
		}
		if signal == "" {
			// Only surface a request content-type signal that Rule 2 did not
			// already record for the same media type; otherwise the -v reason
			// would carry both "content-type:X" and "request-signal:content-type:X",
			// which convey the same fact (QUAL-005).
			if apiCT := matchAPIContentType(mediatype.Header(req.Headers, "content-type")); apiCT != "" && apiCT != rule2CT {
				signal = "content-type:" + apiCT
			}
		}
		if signal != "" {
			if confidence < RequestSignalConfidence {
				confidence = RequestSignalConfidence
			}
			reason = appendReason(reason, "request-signal:"+signal)
		}
	}

	// Rule 7: Offline JS-static candidate floor.
	confidence, reason = staticJSFloor(req, pathIsAPI, confidence, reason)

	return confidence > 0, confidence, reason
}

// staticJSFloor implements Rule 7 (LAB-4992): the offline JS-static confidence
// floor. A path reconstructed from a JS bundle carries an API indicator but,
// when generated fully offline, has no probed response — Rules 2/4/5 never
// fire and Rule 3 alone (0.15) leaves it below the default 0.5 threshold,
// silently dropping the very concat/service-prefix endpoints jsstatic
// recovered. Floor such candidates to StaticJSConfidence so they survive
// default-confidence generation as unprobed candidates. Gated on the shared
// path heuristic (pathIsAPI) so non-API-looking static:js entries are not
// promoted.
//
// QUAL-002: this floor applies to EVERY IsJSStaticSource candidate — the
// AST-literal source (SourceStaticJS), sourcemap-recovered source, AND
// concat/service-prefix reconstructions (SourceStaticJSConcat) alike. Only
// SourceStaticJSConcat is ever superseded by the reached-filter in
// ReplayJSExtracted (which drops a concat mirror once the live probe 404s
// the same reconstructed path); a plain SourceStaticJS AST literal has no
// such supersession and stays floored even if a probe elsewhere 404s it.
// This is deliberate, not an oversight: an AST literal is recovered from a
// real call site in the bundle (fetch/axios/etc.), so a 404 there is more
// likely auth/param-gated than a wrong-guess decoy, unlike an unvalidated
// concat/service-prefix combinatorial reconstruction. Do not extend the
// concat reached-filter supersession to plain static:js literals without
// revisiting this reasoning.
func staticJSFloor(req crawl.ObservedRequest, pathIsAPI bool, confidence float64, reason string) (float64, string) {
	if pathIsAPI && confidence < StaticJSConfidence && crawl.IsJSStaticSource(req.Source) {
		confidence = StaticJSConfidence
		reason = appendReason(reason, "static-js-candidate")
	}
	return confidence, reason
}

// appendReason joins classification signal tags with "+" so the reason string
// records every signal that contributed, in rule order. An empty existing
// reason yields the tag alone.
func appendReason(existing, sig string) string {
	if existing == "" {
		return sig
	}
	return existing + "+" + sig
}

// matchAPIContentType canonicalizes ct (lowercase + charset/parameter strip via
// mediatype.Base) and returns the matching apiContentTypes entry, or "" if none
// matches. Shared by Rule 2 (response content-type) and Rule 6 (request
// content-type) so both apply one matching rule (QUAL-004).
func matchAPIContentType(ct string) string {
	base := mediatype.Base(ct)
	for _, apiCT := range apiContentTypes {
		if base == apiCT {
			return apiCT
		}
	}
	return ""
}

// acceptSignalsAPI parses an Accept header and returns the API media type the
// client is explicitly asking for, or "" if none. It splits into media ranges,
// ignores q-parameters and the "*/*" wildcard, and exact-matches against
// apiContentTypes. Crucially, a header that accepts text/html or
// application/xhtml+xml is treated as a document navigation, NOT API intent —
// browsers always send those on page loads, and the standard navigation Accept
// header also contains application/xml (which would otherwise substring-match).
// This keeps Rule 6 from classifying plain HTML pages under api-like paths
// (e.g. a Swagger UI at /api/docs or a /graphql playground) as REST APIs.
func acceptSignalsAPI(accept string) string {
	if accept == "" {
		return ""
	}
	match := ""
	for _, part := range strings.Split(accept, ",") {
		mt := part
		if i := strings.Index(mt, ";"); i != -1 {
			mt = mt[:i]
		}
		mt = strings.ToLower(strings.TrimSpace(mt))
		if mt == "text/html" || mt == "application/xhtml+xml" {
			// A document-navigation marker anywhere in the header disqualifies
			// the whole request as API intent.
			return ""
		}
		if match == "" {
			// mt is already lowercased and stripped of parameters above, so
			// matchAPIContentType's mediatype.Base is a no-op on it; sharing the
			// helper keeps Rule 2, Rule 6, and this Accept branch on one matching
			// rule (QUAL-003).
			match = matchAPIContentType(mt)
		}
	}
	return match
}

// firstNonSpace returns the first non-ASCII-whitespace byte in b.
// It scans forward only, making it O(1) for typical HTTP bodies that
// start with a non-whitespace character.
func firstNonSpace(b []byte) (byte, bool) {
	for _, c := range b {
		switch c {
		case ' ', '\t', '\n', '\r':
			continue
		default:
			return c, true
		}
	}
	return 0, false
}
