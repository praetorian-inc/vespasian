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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/vespasian/pkg/crawl"
)

func TestRESTClassifier_Name(t *testing.T) {
	c := &RESTClassifier{}
	assert.Equal(t, "rest", c.Name())
}

func TestRESTClassifier_Classify(t *testing.T) {
	c := &RESTClassifier{}

	tests := []struct {
		name          string
		req           crawl.ObservedRequest
		wantIsAPI     bool
		wantMinConf   float64
		wantMaxConf   float64
		wantReasonSub string // substring expected in reason
	}{
		{
			name: "JSON API response",
			req: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://example.com/data",
				Response: crawl.ObservedResponse{
					StatusCode:  200,
					ContentType: "application/json",
				},
			},
			wantIsAPI:     true,
			wantMinConf:   ContentTypeConfidence,
			wantMaxConf:   1.0,
			wantReasonSub: "content-type",
		},
		{
			name: "JSON with charset",
			req: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://example.com/data",
				Response: crawl.ObservedResponse{
					StatusCode:  200,
					ContentType: "application/json; charset=utf-8",
				},
			},
			wantIsAPI:     true,
			wantMinConf:   ContentTypeConfidence,
			wantMaxConf:   1.0,
			wantReasonSub: "content-type",
		},
		{
			name: "XML API response",
			req: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://example.com/data.xml",
				Response: crawl.ObservedResponse{
					StatusCode:  200,
					ContentType: "application/xml",
				},
			},
			wantIsAPI:     true,
			wantMinConf:   ContentTypeConfidence,
			wantMaxConf:   1.0,
			wantReasonSub: "content-type",
		},
		{
			name: "vendor JSON:API content-type",
			req: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://example.com/data",
				Response: crawl.ObservedResponse{
					StatusCode:  200,
					ContentType: "application/vnd.api+json",
				},
			},
			wantIsAPI:     true,
			wantMinConf:   ContentTypeConfidence,
			wantMaxConf:   1.0,
			wantReasonSub: "content-type",
		},
		{
			name: "HAL JSON content-type",
			req: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://example.com/data",
				Response: crawl.ObservedResponse{
					StatusCode:  200,
					ContentType: "application/hal+json",
				},
			},
			wantIsAPI:     true,
			wantMinConf:   ContentTypeConfidence,
			wantMaxConf:   1.0,
			wantReasonSub: "content-type",
		},
		{
			name: "Static JS file",
			req: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://example.com/static/app.js",
				Response: crawl.ObservedResponse{
					StatusCode:  200,
					ContentType: "application/javascript",
				},
			},
			wantIsAPI:   false,
			wantMinConf: 0,
			wantMaxConf: 0,
		},
		{
			name: "Static CSS file",
			req: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://example.com/assets/style.css",
				Response: crawl.ObservedResponse{
					StatusCode: 200,
				},
			},
			wantIsAPI:   false,
			wantMinConf: 0,
			wantMaxConf: 0,
		},
		{
			name: "Image file PNG",
			req: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://example.com/images/logo.png",
				Response: crawl.ObservedResponse{
					StatusCode:  200,
					ContentType: "image/png",
				},
			},
			wantIsAPI:   false,
			wantMinConf: 0,
			wantMaxConf: 0,
		},
		{
			name: "Font file WOFF2",
			req: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://example.com/fonts/roboto.woff2",
				Response: crawl.ObservedResponse{
					StatusCode: 200,
				},
			},
			wantIsAPI:   false,
			wantMinConf: 0,
			wantMaxConf: 0,
		},
		{
			name: "API path with JSON content-type",
			req: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://example.com/api/v1/users",
				Response: crawl.ObservedResponse{
					StatusCode:  200,
					ContentType: "application/json",
					Body:        []byte(`[{"id":1,"name":"Alice"}]`),
				},
			},
			wantIsAPI:     true,
			wantMinConf:   0.95, // 0.8 (content-type) + 0.15 (path)
			wantMaxConf:   1.0,
			wantReasonSub: "path-heuristic",
		},
		{
			name: "API path only, no content-type, no body",
			req: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://example.com/api/v2/data",
				Response: crawl.ObservedResponse{
					StatusCode: 200,
				},
			},
			wantIsAPI:     true,
			wantMinConf:   PathHeuristicBoost,
			wantMaxConf:   PathHeuristicBoost,
			wantReasonSub: "path-heuristic",
		},
		{
			name: "POST request no other signals",
			req: crawl.ObservedRequest{
				Method: "POST",
				URL:    "https://example.com/submit",
				Response: crawl.ObservedResponse{
					StatusCode: 200,
				},
			},
			wantIsAPI:     true,
			wantMinConf:   HTTPMethodConfidence,
			wantMaxConf:   HTTPMethodConfidence,
			wantReasonSub: "method",
		},
		{
			name: "PUT request no other signals",
			req: crawl.ObservedRequest{
				Method: "PUT",
				URL:    "https://example.com/resource/123",
				Response: crawl.ObservedResponse{
					StatusCode: 200,
				},
			},
			wantIsAPI:   true,
			wantMinConf: HTTPMethodConfidence,
			wantMaxConf: HTTPMethodConfidence,
		},
		{
			name: "DELETE request no other signals",
			req: crawl.ObservedRequest{
				Method: "DELETE",
				URL:    "https://example.com/resource/123",
				Response: crawl.ObservedResponse{
					StatusCode: 204,
				},
			},
			wantIsAPI:   true,
			wantMinConf: HTTPMethodConfidence,
			wantMaxConf: HTTPMethodConfidence,
		},
		{
			name: "JSON body without content-type",
			req: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://example.com/endpoint",
				Response: crawl.ObservedResponse{
					StatusCode: 200,
					Body:       []byte(`{"status":"ok"}`),
				},
			},
			wantIsAPI:     true,
			wantMinConf:   JSONBodyConfidence,
			wantMaxConf:   JSONBodyConfidence,
			wantReasonSub: "response-structure",
		},
		{
			name: "HTML response no API signals",
			req: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://example.com/page",
				Response: crawl.ObservedResponse{
					StatusCode:  200,
					ContentType: "text/html",
					Body:        []byte(`<html><body>Hello</body></html>`),
				},
			},
			wantIsAPI:   false,
			wantMinConf: 0,
			wantMaxConf: 0,
		},
		{
			name: "Empty response no signals",
			req: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://example.com/empty",
				Response: crawl.ObservedResponse{
					StatusCode: 200,
				},
			},
			wantIsAPI:   false,
			wantMinConf: 0,
			wantMaxConf: 0,
		},
		{
			name: "GraphQL path heuristic",
			req: crawl.ObservedRequest{
				Method: "POST",
				URL:    "https://example.com/graphql",
				Response: crawl.ObservedResponse{
					StatusCode:  200,
					ContentType: "application/json",
					Body:        []byte(`{"data":{"user":{"id":1}}}`),
				},
			},
			wantIsAPI:     true,
			wantMinConf:   0.95,
			wantMaxConf:   1.0,
			wantReasonSub: "path-heuristic",
		},
		{
			name: "JSON array body",
			req: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://example.com/list",
				Response: crawl.ObservedResponse{
					StatusCode: 200,
					Body:       []byte(`[1,2,3]`),
				},
			},
			wantIsAPI:     true,
			wantMinConf:   JSONBodyConfidence,
			wantMaxConf:   JSONBodyConfidence,
			wantReasonSub: "response-structure",
		},
		{
			name: "Bundle path excluded",
			req: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://example.com/bundle/main.chunk.js",
				Response: crawl.ObservedResponse{
					StatusCode: 200,
				},
			},
			wantIsAPI:   false,
			wantMinConf: 0,
			wantMaxConf: 0,
		},
		{
			name: "Problem JSON content-type",
			req: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://example.com/error",
				Response: crawl.ObservedResponse{
					StatusCode:  400,
					ContentType: "application/problem+json",
					Body:        []byte(`{"type":"about:blank","title":"Bad Request"}`),
				},
			},
			wantIsAPI:     true,
			wantMinConf:   ContentTypeConfidence,
			wantMaxConf:   1.0,
			wantReasonSub: "content-type",
		},
		{
			name: "REST path segment",
			req: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://example.com/rest/endpoint",
				Response: crawl.ObservedResponse{
					StatusCode:  200,
					ContentType: "application/json",
				},
			},
			wantIsAPI:     true,
			wantMinConf:   0.95,
			wantMaxConf:   1.0,
			wantReasonSub: "path-heuristic",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isAPI, confidence, reason := c.ClassifyDetail(tt.req)
			assert.Equal(t, tt.wantIsAPI, isAPI, "isAPI")
			assert.GreaterOrEqual(t, confidence, tt.wantMinConf, "confidence lower bound")
			assert.LessOrEqual(t, confidence, tt.wantMaxConf, "confidence upper bound")
			if tt.wantReasonSub != "" {
				assert.Contains(t, reason, tt.wantReasonSub, "reason")
			}
		})
	}
}

func TestRESTClassifier_ClassifyWrapper(t *testing.T) {
	c := &RESTClassifier{}

	// Positive: JSON content-type response should be detected as REST API.
	pos := crawl.ObservedRequest{
		Method: "GET",
		URL:    "https://example.com/data",
		Response: crawl.ObservedResponse{
			StatusCode:  200,
			ContentType: "application/json",
		},
	}
	isAPI, confidence := c.Classify(pos)
	assert.True(t, isAPI, "expected JSON API response to be classified as REST")
	assert.GreaterOrEqual(t, confidence, ContentTypeConfidence)

	// Negative: HTML response should not be detected as REST API.
	neg := crawl.ObservedRequest{
		Method: "GET",
		URL:    "https://example.com/page",
		Response: crawl.ObservedResponse{
			StatusCode:  200,
			ContentType: "text/html",
			Body:        []byte(`<html><body>Hello</body></html>`),
		},
	}
	isAPI, confidence = c.Classify(neg)
	assert.False(t, isAPI, "expected HTML response to not be classified as REST")
	assert.Equal(t, 0.0, confidence)
}

func TestRESTClassifier_ImplementsDetailedClassifier(t *testing.T) {
	var c APIClassifier = &RESTClassifier{}
	assert.Implements(t, (*DetailedClassifier)(nil), c)
}

// TestClassifyDetail_StaticJSCandidateFloor pins Rule 7 (LAB-4992): an unprobed
// JS-static candidate whose path carries an API indicator is floored to
// StaticJSConfidence (0.5) so it survives default-confidence generation instead
// of being dropped at Rule 3's 0.15. Only fires for JS-static sources with a
// matching path heuristic — plain dynamic GETs and non-API static:js entries
// are unaffected.
func TestClassifyDetail_StaticJSCandidateFloor(t *testing.T) {
	c := &RESTClassifier{}

	tests := []struct {
		name      string
		req       crawl.ObservedRequest
		wantIsAPI bool
		wantConf  float64
	}{
		{
			name: "static:js concat GET with API path floored to 0.5",
			req: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://example.com/api/users/0/orders",
				Source: crawl.SourceStaticJSConcat,
			},
			wantIsAPI: true,
			wantConf:  StaticJSConfidence,
		},
		{
			name: "static:js literal GET with API path floored to 0.5",
			req: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://example.com/api/items",
				Source: crawl.SourceStaticJS,
			},
			wantIsAPI: true,
			wantConf:  StaticJSConfidence,
		},
		{
			// HIGH fix: version segments beyond the old literal list (v1-v3)
			// must still satisfy apiVersionPathPattern so Rule 7 fires —
			// otherwise crawl-extracted /v4+/ concat candidates are dropped.
			// apiVersionPathPattern feeds the shared pathIsAPI computed BEFORE
			// Rule 3 (not a Rule-3-local variable), so it now gates Rule 6 too
			// — see TEST-010 in TestRESTClassifier_RequestSideSignal.
			name: "static:js GET on /v4/ path floored to 0.5 (version beyond literal list)",
			req: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://example.com/v4/users/0",
				Source: crawl.SourceStaticJSConcat,
			},
			wantIsAPI: true,
			wantConf:  StaticJSConfidence,
		},
		{
			name: "static:js GET WITHOUT API indicator is not floored",
			req: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://example.com/dashboard/home",
				Source: crawl.SourceStaticJS,
			},
			wantIsAPI: false,
			wantConf:  0,
		},
		{
			name: "dynamic (non-static-js) GET with API path keeps 0.15",
			req: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://example.com/api/users",
				Source: "katana",
			},
			wantIsAPI: true,
			wantConf:  PathHeuristicBoost,
		},
		{
			name: "static:js POST with API path keeps its stronger method score",
			req: crawl.ObservedRequest{
				Method: "POST",
				URL:    "https://example.com/api/users",
				Source: crawl.SourceStaticJS,
			},
			wantIsAPI: true,
			wantConf:  HTTPMethodConfidence,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isAPI, conf, _ := c.ClassifyDetail(tt.req)
			assert.Equal(t, tt.wantIsAPI, isAPI)
			assert.InDelta(t, tt.wantConf, conf, 1e-9)
		})
	}
}

// TestStaticJSFloor pins the extracted Rule 7 helper (QUAL-003) directly,
// independent of ClassifyDetail's other rules.
func TestStaticJSFloor(t *testing.T) {
	tests := []struct {
		name           string
		req            crawl.ObservedRequest
		pathIsAPI      bool
		inConfidence   float64
		inReason       string
		wantConfidence float64
		wantReason     string
	}{
		{
			name:           "floors a low-confidence static:js candidate with matched path",
			req:            crawl.ObservedRequest{Source: crawl.SourceStaticJSConcat},
			pathIsAPI:      true,
			inConfidence:   PathHeuristicBoost,
			inReason:       "path-heuristic",
			wantConfidence: StaticJSConfidence,
			wantReason:     "path-heuristic+static-js-candidate",
		},
		{
			name:           "sets reason from scratch when no prior reason",
			req:            crawl.ObservedRequest{Source: crawl.SourceStaticJS},
			pathIsAPI:      true,
			inConfidence:   0,
			inReason:       "",
			wantConfidence: StaticJSConfidence,
			wantReason:     "static-js-candidate",
		},
		{
			name:           "does not floor when path did not match",
			req:            crawl.ObservedRequest{Source: crawl.SourceStaticJS},
			pathIsAPI:      false,
			inConfidence:   0,
			inReason:       "",
			wantConfidence: 0,
			wantReason:     "",
		},
		{
			name:           "does not floor a non-JS-static source",
			req:            crawl.ObservedRequest{Source: "katana"},
			pathIsAPI:      true,
			inConfidence:   PathHeuristicBoost,
			inReason:       "path-heuristic",
			wantConfidence: PathHeuristicBoost,
			wantReason:     "path-heuristic",
		},
		{
			name:           "leaves an already-higher confidence untouched",
			req:            crawl.ObservedRequest{Source: crawl.SourceStaticJS},
			pathIsAPI:      true,
			inConfidence:   HTTPMethodConfidence,
			inReason:       "method:POST",
			wantConfidence: HTTPMethodConfidence,
			wantReason:     "method:POST",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotConf, gotReason := staticJSFloor(tt.req, tt.pathIsAPI, tt.inConfidence, tt.inReason)
			assert.InDelta(t, tt.wantConfidence, gotConf, 1e-9)
			assert.Equal(t, tt.wantReason, gotReason)
		})
	}
}

// TestClassifyDetail_FallbackToHeaders verifies the classifier falls back to
// Response.Headers when ContentType is empty, as happens when headers have
// non-standard casing and ContentType wasn't populated by the crawler.
func TestClassifyDetail_FallbackToHeaders(t *testing.T) {
	c := &RESTClassifier{}

	tests := []struct {
		name          string
		req           crawl.ObservedRequest
		wantIsAPI     bool
		wantMinConf   float64
		wantReasonSub string
	}{
		{
			name: "empty ContentType with lowercase content-type in Headers",
			req: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://example.com/data",
				Response: crawl.ObservedResponse{
					StatusCode:  200,
					ContentType: "",
					Headers:     map[string]string{"content-type": "application/json"},
				},
			},
			wantIsAPI:     true,
			wantMinConf:   ContentTypeConfidence,
			wantReasonSub: "content-type",
		},
		{
			name: "empty ContentType with mixed-case Content-Type in Headers",
			req: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://example.com/data",
				Response: crawl.ObservedResponse{
					StatusCode:  200,
					ContentType: "",
					Headers:     map[string]string{"Content-Type": "application/xml"},
				},
			},
			wantIsAPI:     true,
			wantMinConf:   ContentTypeConfidence,
			wantReasonSub: "content-type",
		},
		{
			name: "empty ContentType with no content-type in Headers",
			req: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://example.com/data",
				Response: crawl.ObservedResponse{
					StatusCode:  200,
					ContentType: "",
					Headers:     map[string]string{"X-Request-Id": "abc123"},
				},
			},
			wantIsAPI:   false,
			wantMinConf: 0,
		},
		{
			name: "empty ContentType with content-type charset in Headers",
			req: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://example.com/data",
				Response: crawl.ObservedResponse{
					StatusCode:  200,
					ContentType: "",
					Headers:     map[string]string{"content-type": "application/json; charset=utf-8"},
				},
			},
			wantIsAPI:     true,
			wantMinConf:   ContentTypeConfidence,
			wantReasonSub: "content-type",
		},
		{
			name: "empty ContentType and nil Headers",
			req: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://example.com/data",
				Response: crawl.ObservedResponse{
					StatusCode:  200,
					ContentType: "",
					Headers:     nil,
				},
			},
			wantIsAPI:   false,
			wantMinConf: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isAPI, confidence, reason := c.ClassifyDetail(tt.req)
			assert.Equal(t, tt.wantIsAPI, isAPI, "isAPI")
			assert.GreaterOrEqual(t, confidence, tt.wantMinConf, "confidence lower bound")
			if tt.wantReasonSub != "" {
				assert.Contains(t, reason, tt.wantReasonSub, "reason")
			}
		})
	}
}

// TestRESTClassifier_RequestSideSignal covers Rule 6 (LAB-4678, B2): a JSON API
// reached by GET whose response was not captured (empty content-type and body)
// must still classify as REST when the request itself shows API intent on an
// API path, so the REST-vs-not verdict does not flip with response timing.
func TestRESTClassifier_RequestSideSignal(t *testing.T) {
	c := &RESTClassifier{}

	tests := []struct {
		name          string
		req           crawl.ObservedRequest
		wantIsAPI     bool
		wantMinConf   float64
		wantReasonSub string
	}{
		{
			name: "JSON GET on api path with Accept:json, no response",
			req: crawl.ObservedRequest{
				Method:  "GET",
				URL:     "https://example.com/api/users",
				Headers: map[string]string{"Accept": "application/json, text/plain, */*"},
				// no Response captured (half-captured)
			},
			wantIsAPI:     true,
			wantMinConf:   RequestSignalConfidence,
			wantReasonSub: "request-signal:accept",
		},
		{
			name: "GET on api path, Accept:*/* only, no response -> not enough",
			req: crawl.ObservedRequest{
				Method:  "GET",
				URL:     "https://example.com/api/users",
				Headers: map[string]string{"Accept": "*/*"},
			},
			// Only the path boost (0.15) applies — must stay below threshold so
			// plain navigations under /api/ are not over-classified.
			wantIsAPI:   true, // confidence 0.15 > 0, but...
			wantMinConf: 0,
		},
		{
			name: "GET on api path with json request content-type, no response",
			req: crawl.ObservedRequest{
				Method:  "GET",
				URL:     "https://example.com/api/users",
				Headers: map[string]string{"Content-Type": "application/json; charset=utf-8"},
			},
			wantIsAPI:     true,
			wantMinConf:   RequestSignalConfidence,
			wantReasonSub: "request-signal:content-type",
		},
		{
			// LAB-4678 Phase 3: an explicit JSON Accept is API intent on ANY
			// path, not only allowlisted ones, so a JSON API on a non-standard
			// path is no longer blind-spotted. The text/html and */* guards
			// (asserted below) keep this from over-classifying navigations.
			name: "non-allowlist path with explicit Accept:json -> request signal fires",
			req: crawl.ObservedRequest{
				Method:  "GET",
				URL:     "https://example.com/dashboard",
				Headers: map[string]string{"Accept": "application/json"},
			},
			wantIsAPI:     true,
			wantMinConf:   RequestSignalConfidence,
			wantReasonSub: "request-signal:accept",
		},
		{
			// TEST-010: pins the version-segment arm of the shared pathIsAPI gate
			// for Rule 6. Before the LAB-4678 x LAB-4992 merge, apiPathSegments
			// held the literals "/v1/", "/v2/", "/v3/", so a /v4+/ path was not
			// a gate member at all and this request classified (false, 0, "").
			// The merge replaced those literals with apiVersionPathPattern
			// (/v[1-9][0-9]*/) and hoisted the result into the single pathIsAPI
			// that Rule 6 also consumes, which widened Rule 6's admission set to
			// EVERY version segment. That widening was previously unpinned in
			// both directions — see the /v4/docs entry in the browser-navigation
			// guard below for the negative arm.
			name: "json GET on /v4 version-segment path, no response",
			req: crawl.ObservedRequest{
				Method:  "GET",
				URL:     "https://example.com/v4/users",
				Headers: map[string]string{"Accept": "application/json"},
			},
			wantIsAPI:     true,
			wantMinConf:   RequestSignalConfidence,
			wantReasonSub: "request-signal:accept",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isAPI, confidence, reason := c.ClassifyDetail(tt.req)
			assert.Equal(t, tt.wantIsAPI, isAPI, "isAPI")
			assert.GreaterOrEqual(t, confidence, tt.wantMinConf, "confidence lower bound")
			if tt.wantReasonSub != "" {
				assert.Contains(t, reason, tt.wantReasonSub, "reason")
			}
		})
	}

	// The Accept:*/* case must specifically NOT clear the default threshold, or
	// the request signal would over-classify.
	_, conf, _ := c.ClassifyDetail(crawl.ObservedRequest{
		Method:  "GET",
		URL:     "https://example.com/api/users",
		Headers: map[string]string{"Accept": "*/*"},
	})
	assert.Less(t, conf, DefaultConfidenceThreshold,
		"api-path + Accept:*/* must stay below threshold (path boost only)")

	// A standard browser document-navigation Accept header contains
	// application/xml (with a q-value) AND text/html. A crawled HTML page under
	// an api-like path (e.g. a Swagger UI at /api/docs) must NOT be classified
	// as a REST API by the request-side signal (review finding 001).
	//
	// TEST-010: "/v4/docs" covers the apiVersionPathPattern arm of pathIsAPI.
	// The other entries were already literal apiPathSegments members before the
	// LAB-4678 x LAB-4992 merge; /v4+/ became a gate member only as a result of
	// it, so without this entry an over-classification regression on a document
	// navigation under a high version segment would ship silently.
	const navAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
	// Includes non-allowlist paths (/dashboard, /profile): now that the request
	// signal is path-independent (Phase 3), the navigation guard must hold there
	// too — a browser page load must not classify regardless of path.
	for _, p := range []string{"/api/docs", "/graphql", "/v2/dashboard", "/v4/docs", "/dashboard", "/profile"} {
		_, navConf, navReason := c.ClassifyDetail(crawl.ObservedRequest{
			Method:  "GET",
			URL:     "https://example.com" + p,
			Headers: map[string]string{"Accept": navAccept},
		})
		assert.Less(t, navConf, DefaultConfidenceThreshold,
			"browser navigation to %s must stay below threshold", p)
		assert.NotContains(t, navReason, "request-signal",
			"navigation to %s must not fire the request-side signal", p)
	}

	// QUAL-005: when Rule 2 already recorded a content-type signal for a media
	// type, Rule 6 must NOT re-report the same media type as a request-side
	// content-type signal — the two tags convey the same fact and only add
	// noise to the -v reason.
	_, _, dupReason := c.ClassifyDetail(crawl.ObservedRequest{
		Method:   "GET",
		URL:      "https://example.com/api/items",
		Headers:  map[string]string{"Content-Type": "application/json"},
		Response: crawl.ObservedResponse{ContentType: "application/json"},
	})
	assert.Contains(t, dupReason, "content-type:application/json",
		"Rule 2 response content-type signal must be recorded")
	assert.NotContains(t, dupReason, "request-signal:content-type",
		"Rule 6 must not duplicate Rule 2's content-type signal for the same media type")

	// A request content-type that differs from the response content-type is a
	// genuinely distinct signal and must still be surfaced by Rule 6.
	_, _, xmlReason := c.ClassifyDetail(crawl.ObservedRequest{
		Method:   "GET",
		URL:      "https://example.com/api/items",
		Headers:  map[string]string{"Content-Type": "application/xml"},
		Response: crawl.ObservedResponse{ContentType: "application/json"},
	})
	assert.Contains(t, xmlReason, "request-signal:content-type:application/xml",
		"a request content-type distinct from the response content-type must still fire Rule 6")
}

// TestRESTClassifier_ReasonListsAllSignals verifies the classification reason
// records every contributing signal and matches the confidence, rather than
// attributing the score to whichever rule set the reason first. A POST on an
// /api/ path gets its confidence from the method rule (0.70) but also matches
// the path heuristic; the reason must name both (regression for the -v
// mislabeling surfaced by LAB-4678 live validation).
func TestRESTClassifier_ReasonListsAllSignals(t *testing.T) {
	c := &RESTClassifier{}
	_, conf, reason := c.ClassifyDetail(crawl.ObservedRequest{
		Method: "POST",
		URL:    "https://example.com/api/apps",
		// no response captured — mirrors the live lab observation
	})
	assert.InDelta(t, HTTPMethodConfidence, conf, 0.001, "POST confidence comes from the method rule")
	assert.Contains(t, reason, "path-heuristic", "reason must record the path signal")
	assert.Contains(t, reason, "method:POST", "reason must record the method signal that set the confidence")
}

// TestRESTClassifier_Deterministic verifies ClassifyDetail is a pure function of
// its input: the same request yields identical (isAPI, confidence, reason) every
// call, which is what makes the REST-vs-not verdict stable for a given input
// (LAB-4678).
func TestRESTClassifier_Deterministic(t *testing.T) {
	c := &RESTClassifier{}
	req := crawl.ObservedRequest{
		Method:  "GET",
		URL:     "https://example.com/api/users",
		Headers: map[string]string{"Accept": "application/json"},
	}
	isAPI0, conf0, reason0 := c.ClassifyDetail(req)
	for i := 0; i < 20; i++ {
		isAPI, conf, reason := c.ClassifyDetail(req)
		assert.Equal(t, isAPI0, isAPI)
		assert.Equal(t, conf0, conf)
		assert.Equal(t, reason0, reason)
	}
}

// TestMatchAPIContentType_StructuredSuffix pins the LAB-4678 audit item-4 fix:
// classification must not be limited to the hardcoded apiContentTypes list.
// Any RFC 6839 application/<vendor>+json or +xml structured syntax suffix is an
// API media type, while navigation and non-application types are not.
func TestMatchAPIContentType_StructuredSuffix(t *testing.T) {
	tests := []struct {
		name string
		ct   string
		want string
	}{
		// Tier 1: exact entries still return themselves, unchanged.
		{"exact json", "application/json", "application/json"},
		{"exact json with charset", "application/json; charset=utf-8", "application/json"},
		{"exact text/xml", "text/xml", "text/xml"},
		{"exact hal", "application/hal+json", "application/hal+json"},

		// Tier 2: the open set the hardcoded list was blind to.
		{"json-ld", "application/ld+json", SuffixFamilyJSON},
		{"geo+json", "application/geo+json", SuffixFamilyJSON},
		{"vendor github", "application/vnd.github+json", SuffixFamilyJSON},
		{"vendor with params", "application/vnd.acme.v2+json; charset=utf-8", SuffixFamilyJSON},
		// Syndication feeds carry a structured suffix but are documents for
		// feed readers, not endpoints. The classifier-edge live test asserts a
		// feed stays out of the spec.
		{"atom feed is not an API", "application/atom+xml", ""},
		{"rss feed is not an API", "application/rss+xml", ""},
		{"json feed is not an API", "application/feed+json", ""},
		{"soap+xml belongs to WSDLClassifier", "application/soap+xml", ""},
		// A web app manifest is browser install metadata, served by essentially
		// every modern SPA. It matched the +json arm and became a false operation
		// in most REST specs (LAB-4678 review, QUAL-003).
		{"web app manifest is not an API", "application/manifest+json", ""},
		{"web app manifest with charset", "application/manifest+json; charset=utf-8", ""},

		// Excluded: navigation types, one of which carries a +xml suffix and
		// would otherwise match tier 2 on every HTML page load.
		{"xhtml is navigation", "application/xhtml+xml", ""},
		{"html is navigation", "text/html", ""},

		// Excluded: suffix rule requires the application/ top-level type.
		{"text plus json is not application", "text/x-thing+json", ""},
		{"image plus xml is not application", "image/svg+xml", ""},

		// Excluded: no suffix, no exact match.
		{"plain text", "text/plain", ""},
		{"octet stream", "application/octet-stream", ""},
		{"empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, matchAPIContentType(tt.ct))
		})
	}
}

// TestRESTClassifier_VendorJSONResponseClassifies pins the end-to-end effect of
// the suffix tier: a real API returning a vendor JSON media type that is absent
// from apiContentTypes now clears the confidence threshold instead of scoring 0.
func TestRESTClassifier_VendorJSONResponseClassifies(t *testing.T) {
	c := &RESTClassifier{}
	req := crawl.ObservedRequest{
		Method: "GET",
		URL:    "https://example.com/widgets",
		Response: crawl.ObservedResponse{
			StatusCode:  200,
			ContentType: "application/vnd.acme.widget+json",
		},
	}

	isAPI, confidence, reason := c.ClassifyDetail(req)
	assert.True(t, isAPI)
	assert.GreaterOrEqual(t, confidence, DefaultConfidenceThreshold,
		"a vendor +json response must clear the threshold on its content type alone")
	assert.Contains(t, reason, "content-type:"+SuffixFamilyJSON,
		"the reason must report the stable suffix family, not the unbounded vendor type")
}

// TestRESTClassifier_XHTMLNavigationStillNotAPI guards the suffix tier against
// the over-classification it could have introduced: application/xhtml+xml ends
// in +xml, and every browser page load carries it.
func TestRESTClassifier_XHTMLNavigationStillNotAPI(t *testing.T) {
	c := &RESTClassifier{}
	req := crawl.ObservedRequest{
		Method:   "GET",
		URL:      "https://example.com/api/docs",
		Headers:  map[string]string{"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
		Response: crawl.ObservedResponse{StatusCode: 200, ContentType: "application/xhtml+xml"},
	}

	_, confidence, _ := c.ClassifyDetail(req)
	assert.Less(t, confidence, DefaultConfidenceThreshold,
		"an xhtml page load under an /api/ path must stay below the threshold")
}

// TestRESTClassifier_NextRouteChunksCarryNoAPISignal pins the Codex review
// outcome (PR #189): a route recovered from a Next.js App Router chunk URL must
// NOT classify as an API on provenance alone. The chunk URL proves the path is
// served but not which verbs the module exports, and jsstatic can only attach one
// method to a synthesized request. Classifying it drove the generator to emit a
// `get` operation for a route that may export only POST, with nothing downstream
// to correct it. Both tags must stay sub-threshold.
func TestRESTClassifier_NextRouteChunksCarryNoAPISignal(t *testing.T) {
	c := &RESTClassifier{}
	for _, src := range []string{crawl.SourceNextRouteHandler, crawl.SourceNextPageRoute} {
		req := crawl.ObservedRequest{Method: "GET", URL: "https://app.test/api/files", Source: src}
		_, confidence, reason := c.ClassifyDetail(req)
		assert.Less(t, confidence, DefaultConfidenceThreshold,
			"source %q must not reach the API threshold on provenance alone", src)
		assert.NotContains(t, reason, "framework-route",
			"source %q must not contribute a framework-route signal", src)
	}
}

// TestRESTClassifier_RSSFeedNotAnAPI pins the regression the classifier-edge
// live test caught: adding RFC 6839 suffix matching made application/rss+xml an
// API media type, so a plain blog feed at /feed.xml landed in the OpenAPI spec.
// It must score below the threshold on both the response content-type (Rule 2)
// and the Accept header (Rule 6).
func TestRESTClassifier_RSSFeedNotAnAPI(t *testing.T) {
	c := &RESTClassifier{}
	req := crawl.ObservedRequest{
		Method:  "GET",
		URL:     "http://localhost:8080/feed.xml",
		Headers: map[string]string{"Accept": "application/rss+xml"},
		Response: crawl.ObservedResponse{
			StatusCode:  200,
			ContentType: "application/rss+xml",
			Headers:     map[string]string{"Content-Type": "application/rss+xml"},
			Body:        []byte(`<rss version="2.0"><channel><title>Test</title></channel></rss>`),
		},
	}

	isAPI, confidence, _ := c.ClassifyDetail(req)
	assert.Less(t, confidence, DefaultConfidenceThreshold,
		"an RSS feed must not clear the API confidence threshold")
	assert.False(t, isAPI, "an RSS feed is a syndication document, not an API endpoint")
}

// TestRESTClassifier_JSONFeedNotAnAPI covers the half of the feed exclusion that
// TestRESTClassifier_RSSFeedNotAnAPI could not reach. That test uses an XML feed,
// whose body never triggers Rule 5. application/feed+json is a JSON Feed: it was
// already in the exclusion set, so Rule 2 stayed silent, but its JSON object body
// scored JSONBodyConfidence (0.85) and cleared the threshold anyway. Excluding a
// media type from the content-type tier was never sufficient on its own; Rule 1b
// is what makes a document type disqualifying (LAB-4678 review, QUAL-003).
func TestRESTClassifier_JSONFeedNotAnAPI(t *testing.T) {
	c := &RESTClassifier{}
	isAPI, confidence, _ := c.ClassifyDetail(crawl.ObservedRequest{
		Method: "GET",
		URL:    "https://ex.com/feed.json",
		Response: crawl.ObservedResponse{
			StatusCode:  200,
			ContentType: "application/feed+json",
			Headers:     map[string]string{"Content-Type": "application/feed+json"},
			Body:        []byte(`{"version":"https://jsonfeed.org/version/1.1","items":[]}`),
		},
	})
	assert.Less(t, confidence, DefaultConfidenceThreshold,
		"a JSON Feed must not clear the API confidence threshold on its body structure")
	assert.False(t, isAPI, "a JSON Feed is a syndication document, not an API endpoint")
}

// TestRESTClassifier_WebAppManifestNotAnAPI drives the full classifier over the
// two shapes a web app manifest actually ships as, at their conventional
// document-root locations. Both are served by essentially every modern SPA, so
// before this exclusion the suffix tier added a false operation to most REST
// specs and inflated the restCount DetectAPIType weighs (LAB-4678 review,
// QUAL-003). /manifest.json is caught by the content-type exclusion and
// /site.webmanifest by the static-extension rule, so this covers both halves of
// the fix.
func TestRESTClassifier_WebAppManifestNotAnAPI(t *testing.T) {
	const body = `{"name":"App","short_name":"App","start_url":"/","display":"standalone"}`
	for _, tc := range []struct {
		name string
		url  string
		ct   string
	}{
		{"manifest.json served as manifest+json", "https://ex.com/manifest.json", "application/manifest+json"},
		{"site.webmanifest served as manifest+json", "https://ex.com/site.webmanifest", "application/manifest+json"},
		// A manifest served with a generic or wrong content-type must still be
		// excluded by URL. This is the case documentContentTypes alone misses.
		{"site.webmanifest served as plain json", "https://ex.com/site.webmanifest", "application/json"},
		// The COMMON case, and the one the original fix missed. The web app manifest
		// is conventionally /manifest.json, and a .json file is usually served as
		// plain application/json. Neither the .webmanifest extension rule nor the
		// application/manifest+json content-type rule fires there, so it classified
		// at 0.85 (content-type 0.8 promoted by the JSON object body) and became an
		// operation in the spec. documentPaths is what catches it.
		{"manifest.json served as plain json", "https://ex.com/manifest.json", "application/json"},
		{"manifest.json with no content-type at all", "https://ex.com/manifest.json", ""},
		// A subdirectory deployment must hit too.
		{"manifest.json under a base path", "https://ex.com/app/manifest.json", "application/json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &RESTClassifier{}
			isAPI, confidence, _ := c.ClassifyDetail(crawl.ObservedRequest{
				Method: "GET",
				URL:    tc.url,
				Response: crawl.ObservedResponse{
					StatusCode:  200,
					ContentType: tc.ct,
					Headers:     map[string]string{"Content-Type": tc.ct},
					Body:        []byte(body),
				},
			})
			assert.Less(t, confidence, DefaultConfidenceThreshold,
				"a web app manifest must not clear the API confidence threshold")
			assert.False(t, isAPI, "a web app manifest is browser install metadata, not an API endpoint")
		})
	}
}

// TestNextRouteProvenanceConfidence_IsReportingOnly pins the two bounds that make
// Rule 7 a reporting signal rather than an API signal. Both directions have already
// been wrong once: the rule shipped at 0 (invisible everywhere, see
// TestRESTClassifier_NextRouteIsReportedAsNearMiss), and classifying on provenance
// at full strength is what made the generator invent a `get` operation.
func TestNextRouteProvenanceConfidence_IsReportingOnly(t *testing.T) {
	assert.GreaterOrEqual(t, NextRouteProvenanceConfidence, NearMissFloor,
		"below NearMissFloor the recovered route is dropped from -v too, so the whole "+
			"Next.js recovery feature produces no observable output")
	assert.Less(t, NextRouteProvenanceConfidence, DefaultConfidenceThreshold,
		"at or above the threshold a recovered route becomes a spec operation with a "+
			"verb the chunk URL never revealed")
}

// TestRESTClassifier_NextRouteIsReportedAsNearMiss is the regression test for the
// gap between the code and three documents. README.md, CLAUDE.md and
// pkg/analyze/jsstatic/doc.go all state that recovered Next.js routes surface as
// sub-threshold near-misses under -v. They did not: a page route carries no
// apiPathSegments match, no response and no headers, so it scored 0 — below
// NearMissFloor — and appeared in neither the spec nor the near-miss list.
//
// The /vaults/{vaultId} case is the one the README leads with, and it is exactly
// the one that was invisible. /api/... routes were visible only incidentally, via
// the path heuristic.
func TestRESTClassifier_NextRouteIsReportedAsNearMiss(t *testing.T) {
	c := &RESTClassifier{}
	for _, tc := range []struct {
		name string
		url  string
		src  string
	}{
		{"page route off the api path allowlist", "https://app.test/vaults/%7BvaultId%7D", crawl.SourceNextPageRoute},
		{"page route with a plain path", "https://app.test/dashboard", crawl.SourceNextPageRoute},
		{"route handler off the api path allowlist", "https://app.test/vaults/%7Bid%7D", crawl.SourceNextRouteHandler},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, confidence, reason := c.ClassifyDetail(crawl.ObservedRequest{
				Method: "GET", URL: tc.url, Source: tc.src,
			})
			assert.GreaterOrEqual(t, confidence, NearMissFloor,
				"a recovered route must reach the near-miss floor so -v can report it")
			assert.Less(t, confidence, DefaultConfidenceThreshold,
				"a recovered route must stay out of the spec")
			assert.Contains(t, reason, "next-route-chunk",
				"the -v line must name provenance as the reason the route is listed")
		})
	}
}

// TestStaticJSFloorClearsDefaultThreshold pins the invariant Rule 7 depends on
// (TEST-003, LAB-4992): the static-JS floor must be at least the default
// confidence threshold, or every fully-offline concat/service-prefix candidate
// is dropped by RunClassifiers.
//
// StaticJSConfidence is defined as DefaultConfidenceThreshold, so this holds by
// construction today. The test exists because that binding is easy to undo:
// re-inlining a 0.5 literal here (its previous form) restores a silent-drift
// hazard where lowering the floor to 0.4 leaves every other Rule 7 test green
// (they all assert against the StaticJSConfidence symbol, so they track the
// constant whatever its value). RunClassifiers compares `>=`, so equality is
// sufficient and the floor need not exceed the threshold.
func TestStaticJSFloorClearsDefaultThreshold(t *testing.T) {
	assert.GreaterOrEqual(t, StaticJSConfidence, DefaultConfidenceThreshold,
		"Rule 7's static-JS floor must clear the default --confidence threshold or fully-offline concat candidates are dropped (LAB-4992 AC1)")
}

// TestAPIIndicatorParityWithCrawlExtraction closes the drift gap TEST-002
// identified (LAB-4992): apiVersionPathPattern and apiPathSegments together
// mirror crawl.APIIndicatorAlternation, and non-drift is the stated design
// rationale for apiVersionPathPattern — but nothing enforced it, so widening
// crawl's extraction set would produce candidates whose paths fail Rule 3.
// Rule 7's floor is gated on pathIsAPI, so such a candidate scores 0 and is
// silently dropped at the default confidence.
//
// Two assertions, deliberately paired:
//  1. every indicator crawl can extract, in SEGMENT-ANCHORED position, yields a
//     Rule 7 floor here, and
//  2. crawl's alternation is still exactly the set enumerated below.
//
// (2) is what makes this a guard rather than a snapshot: adding an indicator to
// crawl (say `v0/` or `svc/`) fails this test until the classifier's gate and
// this table are widened to match.
//
// SCOPE (TEST-004): "segment-anchored" is load-bearing and this test does NOT
// claim parity over every string crawl can extract. crawl's apiIndicatorPattern
// is unanchored, so it also matches an indicator embedded mid-token: verified
// live, `ExtractStaticConcatPaths` emits `xapi/users/1` and `/myapi/users/2`,
// which this classifier scores 0 and drops. That asymmetry is DELIBERATE, not a
// gap to close by loosening Rule 3 — `/myapi/` is an accidental substring match,
// not an API indicator, and admitting it would raise false positives for every
// source, not just JS-static ones. crawl over-extracting costs only a discarded
// candidate; the classifier over-matching would corrupt real output. The negative
// cases in TestAPIIndicatorUnanchoredNotFloored pin that decision so it reads as
// a choice rather than an oversight.
func TestAPIIndicatorParityWithCrawlExtraction(t *testing.T) {
	// Pinned so widening crawl's extraction set forces a matching widening of
	// the classifier's Rule 3 gate. Update BOTH sides plus the table below.
	assert.Equal(t, `(?:api/|v[1-9][0-9]*/|rest/|rpc/|graphql)`, crawl.APIIndicatorAlternation,
		"crawl's API-indicator set changed: widen apiPathSegments/apiVersionPathPattern and this test's table so extracted candidates still satisfy Rule 3 (LAB-4992 TEST-002)")

	// One path per arm of the alternation, in the slash-delimited form the
	// concat extractor emits after cleanConcatPath (leading slash added by
	// jsstatic's extractConcatEndpoints). The version arm is sampled across the
	// single- and multi-digit boundary that motivated apiVersionPathPattern.
	paths := []string{
		"/api/users",      // api/
		"/v1/users",       // v[1-9][0-9]*/  (single digit)
		"/v4/users",       // v[1-9][0-9]*/  (beyond the old fixed v1-v3 set)
		"/v12/users",      // v[1-9][0-9]*/  (multi digit)
		"/rest/users",     // rest/
		"/rpc/getUser",    // rpc/
		"/graphql",        // graphql
		"/identity/api/x", // service-prefix reconstruction
		"/api/users/0",    // non-literal operand sentinel
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			c := &RESTClassifier{}
			// An unprobed offline concat candidate: bare GET, no response, so
			// only Rule 3 (+0.15) and Rule 7 can fire.
			isAPI, confidence, reason := c.ClassifyDetail(crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://example.com" + path,
				Source: crawl.SourceStaticJSConcat,
			})

			assert.True(t, isAPI, "extracted indicator must classify as an API path")
			assert.Contains(t, reason, "static-js-candidate", "Rule 7 must fire for an extractable indicator")
			assert.GreaterOrEqual(t, confidence, DefaultConfidenceThreshold,
				"candidate must survive default-confidence generation, got %v", confidence)
		})
	}
}

// TestRESTClassifier_NextRouteProvenanceDoesNotPromote guards the other direction:
// Rule 7 raises a floor, it must never lower or override a stronger signal, and it
// must not push a route that ALSO has real signal over the threshold on its own.
func TestRESTClassifier_NextRouteProvenanceDoesNotPromote(t *testing.T) {
	c := &RESTClassifier{}

	// A genuine JSON API response that happens to carry the tag keeps its own
	// (higher) confidence — the floor must not clamp it down.
	_, strong, _ := c.ClassifyDetail(crawl.ObservedRequest{
		Method: "GET", URL: "https://app.test/api/files", Source: crawl.SourceNextRouteHandler,
		Response: crawl.ObservedResponse{StatusCode: 200, ContentType: "application/json"},
	})
	assert.GreaterOrEqual(t, strong, ContentTypeConfidence,
		"Rule 7 is a floor, not an assignment; it must not clamp a stronger signal")

	// Provenance plus the path heuristic must still not clear the threshold.
	_, boosted, _ := c.ClassifyDetail(crawl.ObservedRequest{
		Method: "GET", URL: "https://app.test/api/files", Source: crawl.SourceNextRouteHandler,
	})
	assert.Less(t, boosted, DefaultConfidenceThreshold,
		"provenance plus the path boost must not add up to a spec operation")
}

// TestIsDocumentPath_MatchesWholeSegmentOnly pins that the suffix match cannot
// swallow a real endpoint whose path merely ENDS with the document name. Every
// documentPaths entry begins with "/", which is what makes the suffix test a
// whole-final-segment test rather than a bare substring test.
func TestIsDocumentPath_MatchesWholeSegmentOnly(t *testing.T) {
	for _, p := range documentPaths {
		assert.True(t, strings.HasPrefix(p, "/"),
			"documentPaths entry %q must start with '/' or the suffix match degrades into "+
				"a substring match and can reject a real endpoint", p)
	}

	for _, hit := range []string{"/manifest.json", "/app/manifest.json", "/a/b/manifest.json"} {
		assert.True(t, isDocumentPath(hit), "%q should be treated as a document path", hit)
	}
	for _, miss := range []string{
		"/app-manifest.json",     // different final segment
		"/manifest.json/details", // not the final segment
		"/api/manifests",
		"/manifest",
		"",
	} {
		assert.False(t, isDocumentPath(miss), "%q must NOT be excluded as a document path", miss)
	}
}

func TestNextRoute_NeverAnOperationAtAnyThreshold(t *testing.T) {
	reqs := []crawl.ObservedRequest{
		{Method: "GET", URL: "https://ex.com/vaults/{vaultId}", Source: crawl.SourceNextPageRoute},
		{Method: "GET", URL: "https://ex.com/admin/reports", Source: crawl.SourceNextRouteHandler},
	}
	classifiers := []APIClassifier{&RESTClassifier{}}

	for _, threshold := range []float64{0.5, 0.2, NearMissFloor, 0.05, 0.01} {
		got := RunClassifiers(classifiers, reqs, threshold)
		if len(got) != 0 {
			t.Errorf("--confidence %.2f classified %d Next.js-recovered routes; they must never "+
				"reach the generator, which would invent a verb the chunk URL never revealed",
				threshold, len(got))
		}
	}

	// ...and they are still visible to the operator under -v.
	nm := NearMisses(classifiers, reqs, NearMissFloor, DefaultConfidenceThreshold)
	if len(nm) != len(reqs) {
		t.Errorf("NearMisses reported %d of %d recovered routes; excluding them from the spec "+
			"must not also make them invisible", len(nm), len(reqs))
	}
}

// TestAPIIndicatorUnanchoredNotFloored pins the negative direction of the
// extraction/classification asymmetry (TEST-004, LAB-4992).
//
// crawl.apiIndicatorPattern is unanchored, so crawl extracts paths whose "API
// indicator" is only an accidental substring of a larger token — verified live,
// ExtractStaticConcatPaths emits `xapi/users/1` for `"xapi/".concat("users/1")`
// and `/myapi/users/2` for `"/myapi/".concat("users/2")`. This classifier
// requires a segment-delimited indicator ("/api/", or a bare version segment), so
// those score 0 and are dropped at the default confidence.
//
// This is the intended contract, and the asymmetry is safe in exactly one
// direction: crawl over-extracting merely wastes a candidate, whereas the
// classifier over-matching would promote genuinely non-API paths for EVERY
// source. Do not "fix" a failure here by loosening apiPathSegments to a substring
// match — that would make /myapi/, /xapi/ and /notgraphql look like API paths
// everywhere in the pipeline.
func TestAPIIndicatorUnanchoredNotFloored(t *testing.T) {
	// The paths these extractions normalize to once jsstatic prefixes an origin —
	// NOT the extractor's raw output. Verified against ExtractStaticConcatPaths:
	//   "xapi/".concat("users/1")        -> "xapi/users/1"    (no leading slash;
	//                                       extractConcatEndpoints adds it)
	//   "/myapi/".concat("users/2")      -> "/myapi/users/2"
	//   "/notgraphql/".concat("query")   -> "/notgraphql/query"
	// The earlier comment claimed these were "exactly the strings crawl's
	// extractor produces", which overstated it for the first entry and cited no
	// bundle for the third (TEST-004).
	unanchored := []string{
		"/xapi/users/1",
		"/myapi/users/2",
		"/notgraphql/query",
	}

	for _, path := range unanchored {
		t.Run(path, func(t *testing.T) {
			c := &RESTClassifier{}
			isAPI, confidence, reason := c.ClassifyDetail(crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://example.com" + path,
				Source: crawl.SourceStaticJSConcat,
			})

			assert.NotContains(t, reason, "static-js-candidate",
				"Rule 7 must NOT fire for a substring-embedded indicator: %s", path)
			assert.Less(t, confidence, DefaultConfidenceThreshold,
				"a substring-embedded indicator must stay below the default threshold, got %v", confidence)
			assert.False(t, isAPI,
				"a substring-embedded indicator must not classify as an API path")
		})
	}
}

// TestNextRoute_NotPromotedByStaticJSFloor pins the rule ordering the LAB-4678 x
// LAB-4992 merge created. Both branches added a rule numbered 7: the Next.js
// chunk-provenance disqualifier (now Rule 6a) and the offline JS-static floor
// (Rule 7). They interact, because crawl.IsJSStaticSource — the gate on Rule 7's
// floor — accepts both Next.js chunk sources.
//
// A recovered route on an /api/-style path therefore satisfies Rule 7's gate.
// Reaching it would floor the route to StaticJSConfidence, which IS the default
// --confidence, and return isAPI=true from `confidence > 0` — putting a guessed
// verb in the spec for a route whose chunk URL never revealed one. That is the
// exact defect Rule 6a exists to prevent, reintroduced by rule order alone.
//
// Rule 6a's early return is what prevents it. The paths below all carry an API
// indicator, so each one fails this test if Rule 6a is moved after Rule 7 or its
// `return` is softened to a fallthrough.
func TestNextRoute_NotPromotedByStaticJSFloor(t *testing.T) {
	c := &RESTClassifier{}
	for _, tc := range []struct {
		name, url, src string
	}{
		{"route handler under /api/", "https://app.test/api/vaults/%7BvaultId%7D", crawl.SourceNextRouteHandler},
		{"page route under /api/", "https://app.test/api/dashboard", crawl.SourceNextPageRoute},
		{"route handler under a version segment", "https://app.test/v2/vaults", crawl.SourceNextRouteHandler},
		{"page route under /rest/", "https://app.test/rest/reports", crawl.SourceNextPageRoute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isAPI, confidence, reason := c.ClassifyDetail(crawl.ObservedRequest{
				Method: "GET", URL: tc.url, Source: tc.src,
			})

			assert.False(t, isAPI,
				"an API-looking path must not turn a chunk-URL route into an API: Rule 6a has to "+
					"return before Rule 7's static-JS floor")
			assert.Less(t, confidence, DefaultConfidenceThreshold,
				"Rule 7's floor is StaticJSConfidence (== the default threshold), so reaching it "+
					"puts the route in the spec at default --confidence")
			assert.NotContains(t, reason, "static-js-candidate",
				"the static-JS floor must not fire for a Next.js chunk source")
			assert.Contains(t, reason, "next-route-chunk",
				"the -v line must name provenance as the reason the route is listed")
		})
	}
}
