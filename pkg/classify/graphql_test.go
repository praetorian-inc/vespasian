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

func TestGraphQLClassifier_Classify(t *testing.T) {
	c := &GraphQLClassifier{}

	tests := []struct {
		name          string
		req           crawl.ObservedRequest
		wantIsAPI     bool
		wantMinConf   float64
		wantMaxConf   float64
		wantReasonSub string
	}{
		// Positive cases
		{
			name: "POST /graphql with GraphQL body",
			req: crawl.ObservedRequest{
				Method: "POST",
				URL:    "https://example.com/graphql",
				Body:   []byte(`{"query":"{ users { id name } }"}`),
				Response: crawl.ObservedResponse{
					StatusCode:  200,
					ContentType: "application/json",
					Body:        []byte(`{"data":{"users":[]}}`),
				},
			},
			wantIsAPI:     true,
			wantMinConf:   0.95,
			wantMaxConf:   1.0,
			wantReasonSub: "graphql-path+graphql-body",
		},
		{
			name: "POST /graphql without body (path only)",
			req: crawl.ObservedRequest{
				Method: "POST",
				URL:    "https://example.com/graphql",
			},
			wantIsAPI:     true,
			wantMinConf:   0.70,
			wantMaxConf:   0.70,
			wantReasonSub: "graphql-path",
		},
		{
			name: "GET /graphql (no body)",
			req: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://example.com/graphql",
			},
			wantIsAPI:     true,
			wantMinConf:   0.70,
			wantMaxConf:   0.70,
			wantReasonSub: "graphql-path",
		},
		{
			name: "POST to non-graphql path with GraphQL body",
			req: crawl.ObservedRequest{
				Method: "POST",
				URL:    "https://example.com/api/data",
				Body:   []byte(`{"query":"query GetUsers { users { id } }","operationName":"GetUsers"}`),
				Response: crawl.ObservedResponse{
					StatusCode:  200,
					ContentType: "application/json",
				},
			},
			wantIsAPI:     true,
			wantMinConf:   0.85,
			wantMaxConf:   0.85,
			wantReasonSub: "graphql-body",
		},
		{
			name: "POST /graphql with mutation body",
			req: crawl.ObservedRequest{
				Method: "POST",
				URL:    "https://example.com/graphql",
				Body:   []byte(`{"query":"mutation { createUser(name: \"test\") { id } }"}`),
				Response: crawl.ObservedResponse{
					StatusCode:  200,
					ContentType: "application/json",
				},
			},
			wantIsAPI:     true,
			wantMinConf:   0.95,
			wantMaxConf:   1.0,
			wantReasonSub: "graphql-path+graphql-body",
		},
		{
			name: "Path variation /v1/graphql",
			req: crawl.ObservedRequest{
				Method: "POST",
				URL:    "https://example.com/v1/graphql",
				Body:   []byte(`{"query":"{ hello }"}`),
			},
			wantIsAPI:     true,
			wantMinConf:   0.95,
			wantMaxConf:   1.0,
			wantReasonSub: "graphql-path+graphql-body",
		},
		{
			name: "Path variation /api/graphql",
			req: crawl.ObservedRequest{
				Method: "POST",
				URL:    "https://example.com/api/graphql",
				Body:   []byte(`{"query":"{ hello }"}`),
			},
			wantIsAPI:     true,
			wantMinConf:   0.95,
			wantMaxConf:   1.0,
			wantReasonSub: "graphql-path+graphql-body",
		},
		{
			name: "Path variation /graphql/ (trailing slash)",
			req: crawl.ObservedRequest{
				Method: "POST",
				URL:    "https://example.com/graphql/",
				Body:   []byte(`{"query":"{ hello }"}`),
			},
			wantIsAPI:     true,
			wantMinConf:   0.95,
			wantMaxConf:   1.0,
			wantReasonSub: "graphql-path+graphql-body",
		},
		{
			name: "GraphQL response structure boosts confidence",
			req: crawl.ObservedRequest{
				Method: "POST",
				URL:    "https://example.com/api/data",
				Body:   []byte(`{"query":"subscription { messages { text } }"}`),
				Response: crawl.ObservedResponse{
					StatusCode:  200,
					ContentType: "application/json",
					Body:        []byte(`{"data":{"messages":[{"text":"hi"}]}}`),
				},
			},
			wantIsAPI:     true,
			wantMinConf:   0.85,
			wantMaxConf:   1.0,
			wantReasonSub: "graphql-body",
		},
		{
			name: "GraphQL response with errors key",
			req: crawl.ObservedRequest{
				Method: "POST",
				URL:    "https://example.com/graphql",
				Body:   []byte(`{"query":"{ bad }"}`),
				Response: crawl.ObservedResponse{
					StatusCode:  200,
					ContentType: "application/json",
					Body:        []byte(`{"errors":[{"message":"Cannot query field bad"}]}`),
				},
			},
			wantIsAPI:     true,
			wantMinConf:   0.95,
			wantMaxConf:   1.0,
			wantReasonSub: "graphql-path+graphql-body",
		},
		{
			name: "application/graphql+json content type",
			req: crawl.ObservedRequest{
				Method: "POST",
				URL:    "https://example.com/api/endpoint",
				Body:   []byte(`{"query":"{ users { id } }"}`),
				Response: crawl.ObservedResponse{
					StatusCode:  200,
					ContentType: "application/graphql+json",
					Body:        []byte(`{"data":{"users":[]}}`),
				},
			},
			wantIsAPI:     true,
			wantMinConf:   0.85,
			wantMaxConf:   1.0,
			wantReasonSub: "graphql-body",
		},
		{
			name: "Response-only signal (no body match, path match + response)",
			req: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://example.com/graphql",
				Response: crawl.ObservedResponse{
					StatusCode:  200,
					ContentType: "application/json",
					Body:        []byte(`{"data":{"__schema":{"types":[]}}}`),
				},
			},
			wantIsAPI:     true,
			wantMinConf:   0.80,
			wantMaxConf:   1.0,
			wantReasonSub: "graphql-path",
		},

		// False positive exclusions
		{
			name: "Search API with plain query string",
			req: crawl.ObservedRequest{
				Method: "POST",
				URL:    "https://example.com/api/search",
				Body:   []byte(`{"query":"shoes"}`),
				Response: crawl.ObservedResponse{
					StatusCode:  200,
					ContentType: "application/json",
					Body:        []byte(`{"results":[{"name":"shoes"}]}`),
				},
			},
			wantIsAPI:   false,
			wantMinConf: 0,
			wantMaxConf: 0,
		},
		{
			name: "Search API with numeric query",
			req: crawl.ObservedRequest{
				Method: "POST",
				URL:    "https://example.com/api/search",
				Body:   []byte(`{"query":12345}`),
				Response: crawl.ObservedResponse{
					StatusCode:  200,
					ContentType: "application/json",
				},
			},
			wantIsAPI:   false,
			wantMinConf: 0,
			wantMaxConf: 0,
		},
		{
			name: "JSON POST with data in response but no GraphQL signals",
			req: crawl.ObservedRequest{
				Method: "POST",
				URL:    "https://example.com/api/items",
				Body:   []byte(`{"name":"test"}`),
				Response: crawl.ObservedResponse{
					StatusCode:  200,
					ContentType: "application/json",
					Body:        []byte(`{"data":[1,2,3]}`),
				},
			},
			wantIsAPI:   false,
			wantMinConf: 0,
			wantMaxConf: 0,
		},

		// Negative cases
		{
			name: "Static asset .js",
			req: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://example.com/graphql.js",
			},
			wantIsAPI:   false,
			wantMinConf: 0,
			wantMaxConf: 0,
		},
		{
			name: "Static asset .css",
			req: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://example.com/app.css",
			},
			wantIsAPI:   false,
			wantMinConf: 0,
			wantMaxConf: 0,
		},
		{
			name: "HTML response",
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
			name: "REST JSON API",
			req: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://example.com/api/users",
				Response: crawl.ObservedResponse{
					StatusCode:  200,
					ContentType: "application/json",
					Body:        []byte(`{"users":[{"id":1}]}`),
				},
			},
			wantIsAPI:   false,
			wantMinConf: 0,
			wantMaxConf: 0,
		},
		{
			name: "SOAP request",
			req: crawl.ObservedRequest{
				Method: "POST",
				URL:    "https://example.com/service",
				Headers: map[string]string{
					"SOAPAction": `"urn:GetUser"`,
				},
				Body: []byte(`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><GetUser/></soap:Body></soap:Envelope>`),
				Response: crawl.ObservedResponse{
					StatusCode:  200,
					ContentType: "application/soap+xml",
				},
			},
			wantIsAPI:   false,
			wantMinConf: 0,
			wantMaxConf: 0,
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

func TestGraphQLClassifier_Name(t *testing.T) {
	c := &GraphQLClassifier{}
	assert.Equal(t, "graphql", c.Name())
}

func TestGraphQLClassifier_ClassifyWrapper(t *testing.T) {
	c := &GraphQLClassifier{}

	// Positive: POST to /graphql with GraphQL body should be detected.
	pos := crawl.ObservedRequest{
		Method: "POST",
		URL:    "https://example.com/graphql",
		Body:   []byte(`{"query":"{ users { id } }"}`),
	}
	isAPI, confidence := c.Classify(pos)
	assert.True(t, isAPI, "expected GraphQL request to be classified as API")
	assert.GreaterOrEqual(t, confidence, GraphQLFullMatchConfidence)

	// Negative: plain REST JSON endpoint should not be detected.
	neg := crawl.ObservedRequest{
		Method: "GET",
		URL:    "https://example.com/api/users",
		Response: crawl.ObservedResponse{
			StatusCode:  200,
			ContentType: "application/json",
			Body:        []byte(`{"users":[]}`),
		},
	}
	isAPI, confidence = c.Classify(neg)
	assert.False(t, isAPI, "expected REST request to not be classified as GraphQL")
	assert.Equal(t, 0.0, confidence)
}

func TestGraphQLClassifier_ImplementsDetailedClassifier(t *testing.T) {
	var c APIClassifier = &GraphQLClassifier{}
	assert.Implements(t, (*DetailedClassifier)(nil), c)
}
