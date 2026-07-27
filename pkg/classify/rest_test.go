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
	const navAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
	for _, p := range []string{"/api/docs", "/graphql", "/v2/dashboard"} {
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
