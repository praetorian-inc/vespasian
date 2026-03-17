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

package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"

	"github.com/praetorian-inc/vespasian/pkg/classify"
)

// maxIntrospectionBodySize limits the response body read for GraphQL introspection.
const maxIntrospectionBodySize = 5 << 20 // 5 MB

// introspectionQuery is the GraphQL introspection query sent to discovered endpoints.
const introspectionQuery = `{"query":"{ __schema { types { name kind fields { name type { name kind ofType { name } } } } } }"}`

// GraphQLProbe sends an introspection query to discovered GraphQL endpoints
// and parses the response into a structured schema representation.
type GraphQLProbe struct {
	config Config
}

// NewGraphQLProbe creates a GraphQLProbe with the given configuration.
func NewGraphQLProbe(cfg Config) *GraphQLProbe {
	return &GraphQLProbe{config: cfg.withDefaults()}
}

// Name returns the probe name.
func (p *GraphQLProbe) Name() string {
	return "graphql"
}

// Probe sends introspection queries to GraphQL endpoints and enriches them
// with schema information. Only endpoints with APIType=="graphql" are probed.
// Endpoints are deduplicated by URL to avoid redundant requests.
func (p *GraphQLProbe) Probe(ctx context.Context, endpoints []classify.ClassifiedRequest) ([]classify.ClassifiedRequest, error) {
	// Deduplicate: probe each unique URL once
	schemas := make(map[string]*classify.GraphQLIntrospection)
	seen := make(map[string]bool)

	for _, ep := range endpoints {
		if ep.APIType != "graphql" {
			continue
		}

		if seen[ep.URL] {
			continue
		}
		if len(seen) >= p.config.MaxEndpoints {
			break
		}
		seen[ep.URL] = true

		result := p.probeEndpoint(ctx, ep.URL)
		if result != nil {
			schemas[ep.URL] = result
		}
	}

	// Copy endpoints to avoid mutating the caller's slice
	result := make([]classify.ClassifiedRequest, len(endpoints))
	copy(result, endpoints)

	for i := range result {
		if result[i].APIType != "graphql" {
			continue
		}
		if schema, ok := schemas[result[i].URL]; ok {
			result[i].GraphQLSchema = schema
		}
	}

	return result, nil
}

// probeEndpoint sends an introspection query to the given URL and parses the response.
func (p *GraphQLProbe) probeEndpoint(ctx context.Context, targetURL string) *classify.GraphQLIntrospection {
	if err := p.config.URLValidator(targetURL); err != nil {
		slog.DebugContext(ctx, "graphql probe: URL validation failed", "url", targetURL, "error", err)
		return nil
	}

	reqCtx, cancel := context.WithTimeout(ctx, p.config.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, targetURL, bytes.NewReader([]byte(introspectionQuery)))
	if err != nil {
		return nil
	}

	req.Header.Set("Content-Type", "application/json")
	for k, v := range p.config.AuthHeaders {
		req.Header.Set(k, v)
	}

	resp, err := p.config.Client.Do(req)
	if err != nil {
		slog.DebugContext(ctx, "graphql probe: request failed", "url", targetURL, "error", err)
		return nil
	}
	defer func() {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)) //nolint:errcheck // best-effort drain
		resp.Body.Close()                                     //nolint:errcheck // best-effort close
	}()

	if resp.StatusCode >= 400 {
		slog.DebugContext(ctx, "graphql probe: non-success status", "url", targetURL, "status", resp.StatusCode)
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxIntrospectionBodySize))
	if err != nil {
		return nil
	}

	return parseIntrospectionResponse(body)
}

// parseIntrospectionResponse parses a GraphQL introspection JSON response.
func parseIntrospectionResponse(body []byte) *classify.GraphQLIntrospection {
	var envelope struct {
		Data struct {
			Schema struct {
				Types []struct {
					Name   string `json:"name"`
					Kind   string `json:"kind"`
					Fields []struct {
						Name string `json:"name"`
						Type struct {
							Name   *string `json:"name"`
							Kind   string  `json:"kind"`
							OfType *struct {
								Name *string `json:"name"`
							} `json:"ofType"`
						} `json:"type"`
					} `json:"fields"`
				} `json:"types"`
			} `json:"__schema"`
		} `json:"data"`
		Errors []interface{} `json:"errors"`
	}

	if err := json.Unmarshal(body, &envelope); err != nil {
		return &classify.GraphQLIntrospection{IntrospectionEnabled: false}
	}

	// If errors are present and no types, introspection is disabled
	if len(envelope.Errors) > 0 && len(envelope.Data.Schema.Types) == 0 {
		return &classify.GraphQLIntrospection{IntrospectionEnabled: false}
	}

	if len(envelope.Data.Schema.Types) == 0 {
		return &classify.GraphQLIntrospection{IntrospectionEnabled: false}
	}

	types := make([]classify.GraphQLType, 0, len(envelope.Data.Schema.Types))
	for _, t := range envelope.Data.Schema.Types {
		gt := classify.GraphQLType{
			Name: t.Name,
			Kind: t.Kind,
		}
		for _, f := range t.Fields {
			gf := classify.GraphQLField{
				Name: f.Name,
				Type: classify.GraphQLTypeRef{
					Name: f.Type.Name,
					Kind: f.Type.Kind,
				},
			}
			if f.Type.OfType != nil {
				gf.Type.OfType = &classify.GraphQLTypeRef{
					Name: f.Type.OfType.Name,
				}
			}
			gt.Fields = append(gt.Fields, gf)
		}
		types = append(types, gt)
	}

	return &classify.GraphQLIntrospection{
		IntrospectionEnabled: true,
		Types:                types,
		RawResponse:          body,
	}
}
