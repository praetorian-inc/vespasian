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
			name: "non-api path with Accept:json -> request signal does NOT fire",
			req: crawl.ObservedRequest{
				Method:  "GET",
				URL:     "https://example.com/dashboard",
				Headers: map[string]string{"Accept": "application/json"},
			},
			wantIsAPI:   false,
			wantMinConf: 0,
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
	for _, p := range []string{"/api/docs", "/graphql", "/v2/dashboard", "/v4/docs"} {
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
//  1. every indicator crawl can extract yields a Rule 7 floor here, and
//  2. crawl's alternation is still exactly the set enumerated below.
//
// (2) is what makes this a guard rather than a snapshot: adding an indicator to
// crawl (say `v0/` or `svc/`) fails this test until the classifier's gate and
// this table are widened to match.
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
