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

// Tiered introspection queries, tried in order from most complete to least.
// Some servers reject large introspection queries via WAFs or custom validation,
// so we fall back to progressively simpler queries.

// introspectionQueryTier1 is the canonical full introspection query matching
// graphql-js getIntrospectionQuery(). Includes descriptions, deprecation info,
// directives, and 9-level TypeRef depth.
var introspectionQueryTier1 = mustMarshalQuery(`query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}

fragment InputValue on __InputValue {
  name
  description
  type { ...TypeRef }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                }
              }
            }
          }
        }
      }
    }
  }
}`)

// introspectionQueryTier2 is a minimal-complete query. Strips descriptions,
// deprecation, and directives but retains all structurally important fields
// (args, inputFields, enumValues, interfaces, possibleTypes).
var introspectionQueryTier2 = mustMarshalQuery(`{ __schema {
  queryType { name }
  mutationType { name }
  subscriptionType { name }
  types {
    kind
    name
    fields(includeDeprecated: true) {
      name
      args { name type { ...TypeRef } }
      type { ...TypeRef }
    }
    inputFields { name type { ...TypeRef } }
    interfaces { ...TypeRef }
    enumValues { name }
    possibleTypes { ...TypeRef }
  }
}}

fragment TypeRef on __Type {
  kind name ofType { kind name ofType { kind name ofType { kind name
  ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } }
}`)

// introspectionQueryTier3 is the minimal last-resort query. Smallest payload,
// most likely to pass restrictive filters. Produces partial SDL (no args/enums/inputs)
// but useful for type and field name discovery.
const introspectionQueryTier3 = `{"query":"{ __schema { types { name kind fields { name type { name kind ofType { name kind ofType { name kind ofType { name kind ofType { name kind ofType { name kind ofType { name kind ofType { name kind } } } } } } } } } } } }"}`

// mustMarshalQuery wraps a GraphQL query string as a JSON {"query": "..."} body.
// Panics if marshalling fails (only called with compile-time constants).
func mustMarshalQuery(query string) string {
	b, err := json.Marshal(map[string]string{"query": query})
	if err != nil {
		panic("failed to marshal introspection query: " + err.Error())
	}
	return string(b)
}

// introspectionQueries lists queries from most to least complete for tiered fallback.
var introspectionQueries = []string{
	introspectionQueryTier1,
	introspectionQueryTier2,
	introspectionQueryTier3,
}

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

// probeEndpoint sends tiered introspection queries to the given URL.
// It tries each tier in order, returning the first successful result.
// If all tiers are rejected, returns IntrospectionEnabled: false so that
// downstream code can distinguish "probed but disabled" from "not probed".
func (p *GraphQLProbe) probeEndpoint(ctx context.Context, targetURL string) *classify.GraphQLIntrospection {
	if err := p.config.URLValidator(targetURL); err != nil {
		slog.DebugContext(ctx, "graphql probe: URL validation failed", "url", targetURL, "error", err)
		return nil
	}

	var lastParsed *classify.GraphQLIntrospection
	for tier, query := range introspectionQueries {
		result, parsed := p.sendIntrospection(ctx, targetURL, query, tier+1)
		if result != nil {
			return result
		}
		if parsed != nil {
			lastParsed = parsed
		}
	}

	// All tiers were rejected — return the last parsed response (IntrospectionEnabled: false)
	// so the caller can distinguish "probed but disabled" from "not probed at all".
	return lastParsed
}

// sendIntrospection sends a single introspection query and parses the response.
// Returns (result, parsed) where result is non-nil only on success (IntrospectionEnabled: true),
// and parsed is the raw parse result (may have IntrospectionEnabled: false) for fallback tracking.
func (p *GraphQLProbe) sendIntrospection(ctx context.Context, targetURL, query string, tier int) (result *classify.GraphQLIntrospection, parsed *classify.GraphQLIntrospection) {
	reqCtx, cancel := context.WithTimeout(ctx, p.config.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, targetURL, bytes.NewReader([]byte(query)))
	if err != nil {
		return nil, nil
	}

	req.Header.Set("Content-Type", "application/json")
	for k, v := range p.config.AuthHeaders {
		req.Header.Set(k, v)
	}

	resp, err := p.config.Client.Do(req)
	if err != nil {
		slog.DebugContext(ctx, "graphql probe: request failed", "url", targetURL, "tier", tier, "error", err)
		return nil, nil
	}
	defer func() {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)) //nolint:errcheck,gosec // best-effort drain
		resp.Body.Close()                                     //nolint:errcheck,gosec // best-effort close
	}()

	if resp.StatusCode >= 400 {
		slog.DebugContext(ctx, "graphql probe: non-success status", "url", targetURL, "tier", tier, "status", resp.StatusCode)
		return nil, nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxIntrospectionBodySize))
	if err != nil {
		return nil, nil
	}

	p2 := parseIntrospectionResponse(body)
	if p2 == nil || !p2.IntrospectionEnabled {
		slog.DebugContext(ctx, "graphql probe: tier rejected or empty", "url", targetURL, "tier", tier)
		return nil, p2
	}

	slog.DebugContext(ctx, "graphql probe: introspection succeeded", "url", targetURL, "tier", tier, "types", len(p2.Types))
	return p2, p2
}

// parseIntrospectionResponse parses a GraphQL introspection JSON response.
func parseIntrospectionResponse(body []byte) *classify.GraphQLIntrospection {
	var envelope struct {
		Data struct {
			Schema struct {
				QueryType        *struct{ Name string } `json:"queryType"`
				MutationType     *struct{ Name string } `json:"mutationType"`
				SubscriptionType *struct{ Name string } `json:"subscriptionType"`
				Types            []struct {
					Name        string `json:"name"`
					Kind        string `json:"kind"`
					Description string `json:"description"`
					Fields      []struct {
						Name              string              `json:"name"`
						Description       string              `json:"description"`
						Type              json.RawMessage     `json:"type"`
						Args              []json.RawMessage   `json:"args"`
						IsDeprecated      bool                `json:"isDeprecated"`
						DeprecationReason string              `json:"deprecationReason"`
					} `json:"fields"`
					InputFields   []json.RawMessage `json:"inputFields"`
					EnumValues    []struct {
						Name              string `json:"name"`
						Description       string `json:"description"`
						IsDeprecated      bool   `json:"isDeprecated"`
						DeprecationReason string `json:"deprecationReason"`
					} `json:"enumValues"`
					Interfaces    []json.RawMessage `json:"interfaces"`
					PossibleTypes []json.RawMessage `json:"possibleTypes"`
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

	result := &classify.GraphQLIntrospection{
		IntrospectionEnabled: true,
		RawResponse:          body,
	}

	// Extract root type names
	if envelope.Data.Schema.QueryType != nil {
		result.QueryTypeName = envelope.Data.Schema.QueryType.Name
	}
	if envelope.Data.Schema.MutationType != nil {
		result.MutationTypeName = envelope.Data.Schema.MutationType.Name
	}
	if envelope.Data.Schema.SubscriptionType != nil {
		result.SubscriptionTypeName = envelope.Data.Schema.SubscriptionType.Name
	}

	types := make([]classify.GraphQLType, 0, len(envelope.Data.Schema.Types))
	for _, t := range envelope.Data.Schema.Types {
		gt := classify.GraphQLType{
			Name:        t.Name,
			Kind:        t.Kind,
			Description: t.Description,
		}

		// Parse fields
		for _, f := range t.Fields {
			var typeRef classify.GraphQLTypeRef
			if err := json.Unmarshal(f.Type, &typeRef); err != nil {
				continue
			}
			gf := classify.GraphQLField{
				Name:              f.Name,
				Description:       f.Description,
				Type:              typeRef,
				IsDeprecated:      f.IsDeprecated,
				DeprecationReason: f.DeprecationReason,
			}
			// Parse field args
			for _, rawArg := range f.Args {
				iv := parseInputValue(rawArg)
				if iv != nil {
					gf.Args = append(gf.Args, *iv)
				}
			}
			gt.Fields = append(gt.Fields, gf)
		}

		// Parse inputFields
		for _, rawIF := range t.InputFields {
			iv := parseInputValue(rawIF)
			if iv != nil {
				gt.InputFields = append(gt.InputFields, *iv)
			}
		}

		// Parse enumValues
		for _, ev := range t.EnumValues {
			gt.EnumValues = append(gt.EnumValues, classify.GraphQLEnumValue{
				Name:              ev.Name,
				Description:       ev.Description,
				IsDeprecated:      ev.IsDeprecated,
				DeprecationReason: ev.DeprecationReason,
			})
		}

		// Parse interfaces
		for _, rawIface := range t.Interfaces {
			var ref classify.GraphQLTypeRef
			if err := json.Unmarshal(rawIface, &ref); err == nil {
				gt.Interfaces = append(gt.Interfaces, ref)
			}
		}

		// Parse possibleTypes
		for _, rawPT := range t.PossibleTypes {
			var ref classify.GraphQLTypeRef
			if err := json.Unmarshal(rawPT, &ref); err == nil {
				gt.PossibleTypes = append(gt.PossibleTypes, ref)
			}
		}

		types = append(types, gt)
	}

	result.Types = types
	return result
}

// parseInputValue parses a raw JSON input value (arg or input field).
func parseInputValue(raw json.RawMessage) *classify.GraphQLInputValue {
	var v struct {
		Name         string          `json:"name"`
		Description  string          `json:"description"`
		Type         json.RawMessage `json:"type"`
		DefaultValue *string         `json:"defaultValue"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil
	}
	var typeRef classify.GraphQLTypeRef
	if err := json.Unmarshal(v.Type, &typeRef); err != nil {
		return nil
	}
	return &classify.GraphQLInputValue{
		Name:         v.Name,
		Description:  v.Description,
		Type:         typeRef,
		DefaultValue: v.DefaultValue,
	}
}
