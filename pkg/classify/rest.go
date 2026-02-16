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
func (c *RESTClassifier) ClassifyDetail(req crawl.ObservedRequest) (bool, float64, string) {
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
