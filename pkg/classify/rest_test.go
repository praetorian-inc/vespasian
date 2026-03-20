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

	"github.com/praetorian-inc/vespasian/pkg/crawl"
	"github.com/stretchr/testify/assert"
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
