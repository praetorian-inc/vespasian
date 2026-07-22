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
// so Rule 6's static-JS floor would never fire and they would be dropped at the
// default confidence (LAB-4992).
var apiVersionPathPattern = regexp.MustCompile(`/v[1-9][0-9]*/`)

// Confidence scores assigned by each heuristic rule.
const (
	ContentTypeConfidence = 0.8  // Rule 2: API content-type match.
	PathHeuristicBoost    = 0.15 // Rule 3: API path segment boost.
	HTTPMethodConfidence  = 0.7  // Rule 4: Non-GET HTTP method signal.
	JSONBodyConfidence    = 0.85 // Rule 5: JSON response structure.
	// StaticJSConfidence is the floor for an offline JS-static candidate whose
	// path carries an API indicator (Rule 6). It equals the default --confidence
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
//  6. Offline JS-static candidate floor → confidence max(current, StaticJSConfidence) when the path carries an API indicator
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

	// Rule 2: Content-type filter.
	ct := strings.ToLower(req.Response.ContentType)
	if ct == "" {
		for k, v := range req.Response.Headers {
			if strings.EqualFold(k, "content-type") {
				ct = strings.ToLower(v)
				break
			}
		}
	}
	// Strip charset parameters (e.g., "application/json; charset=utf-8").
	if idx := strings.Index(ct, ";"); idx != -1 {
		ct = strings.TrimSpace(ct[:idx])
	}
	for _, apiCT := range apiContentTypes {
		if ct == apiCT {
			confidence = ContentTypeConfidence
			reason = "content-type:" + apiCT
			break
		}
	}

	// Rule 3: Path heuristics.
	pathMatched := false
	for _, seg := range apiPathSegments {
		if strings.Contains(lowerPath, seg) {
			pathMatched = true
			break
		}
	}
	if !pathMatched && apiVersionPathPattern.MatchString(lowerPath) {
		pathMatched = true
	}
	if pathMatched {
		confidence += PathHeuristicBoost
		if confidence > 1.0 {
			confidence = 1.0
		}
		if reason == "" {
			reason = "path-heuristic"
		} else {
			reason += "+path-heuristic"
		}
	}

	// Rule 4: HTTP method signal.
	upper := strings.ToUpper(req.Method)
	if upper == "POST" || upper == "PUT" || upper == "PATCH" || upper == "DELETE" {
		if confidence < HTTPMethodConfidence {
			confidence = HTTPMethodConfidence
		}
		if reason == "" {
			reason = "method:" + upper
		}
	}

	// Rule 5: Response structure (JSON body).
	// Forward-only scan: find first non-whitespace byte without scanning
	// the entire body from both ends (avoids O(n) scan on large bodies).
	if len(req.Response.Body) > 0 {
		if b, ok := firstNonSpace(req.Response.Body); ok && (b == '{' || b == '[') {
			if confidence < JSONBodyConfidence {
				confidence = JSONBodyConfidence
			}
			if reason == "" {
				reason = "response-structure:json"
			}
		}
	}

	// Rule 6: Offline JS-static candidate floor (LAB-4992). A path reconstructed
	// from a JS bundle carries an API indicator but, when generated fully
	// offline, has no probed response — Rules 2/4/5 never fire and Rule 3 alone
	// (0.15) leaves it below the default 0.5 threshold, silently dropping the
	// very concat/service-prefix endpoints jsstatic recovered. Floor such
	// candidates to StaticJSConfidence so they survive default-confidence
	// generation as unprobed candidates. Gated on the path heuristic so
	// non-API-looking static:js entries are not promoted.
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
	if pathMatched && confidence < StaticJSConfidence && crawl.IsJSStaticSource(req.Source) {
		confidence = StaticJSConfidence
		if reason == "" {
			reason = "static-js-candidate"
		} else {
			reason += "+static-js-candidate"
		}
	}

	return confidence > 0, confidence, reason
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
