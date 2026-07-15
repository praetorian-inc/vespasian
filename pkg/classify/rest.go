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

// apiPathSegments lists path segments that indicate API endpoints.
var apiPathSegments = []string{
	"/api/", "/v1/", "/v2/", "/v3/", "/rest/", "/rpc/", "/graphql",
}

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
	for _, seg := range apiPathSegments {
		if strings.Contains(lowerPath, seg) {
			confidence += PathHeuristicBoost
			if confidence > 1.0 {
				confidence = 1.0
			}
			if reason == "" {
				reason = "path-heuristic"
			} else {
				reason += "+path-heuristic"
			}
			break
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
	pathIsAPI := false
	for _, seg := range apiPathSegments {
		if strings.Contains(lowerPath, seg) {
			pathIsAPI = true
			break
		}
	}
	if pathIsAPI {
		signal := ""
		if apiCT := acceptSignalsAPI(getHeader(req.Headers, "accept")); apiCT != "" {
			signal = "accept:" + apiCT
		}
		if signal == "" {
			reqCT := strings.ToLower(getHeader(req.Headers, "content-type"))
			if idx := strings.Index(reqCT, ";"); idx != -1 {
				reqCT = strings.TrimSpace(reqCT[:idx])
			}
			for _, apiCT := range apiContentTypes {
				if reqCT == apiCT {
					signal = "content-type:" + apiCT
					break
				}
			}
		}
		if signal != "" && confidence < RequestSignalConfidence {
			confidence = RequestSignalConfidence
			if reason == "" {
				reason = "request-signal:" + signal
			} else {
				reason += "+request-signal:" + signal
			}
		}
	}

	return confidence > 0, confidence, reason
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
			for _, apiCT := range apiContentTypes {
				if mt == apiCT {
					match = apiCT
					break
				}
			}
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
