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

// Package rest generates OpenAPI 3.0 specifications from classified REST requests.
package rest

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/praetorian-inc/vespasian/pkg/classify"
	"gopkg.in/yaml.v3"
)

// capitalizeFirst capitalizes the first letter of a string (UTF-8 safe).
func capitalizeFirst(s string) string {
	if s == "" {
		return s
	}
	r, size := utf8.DecodeRuneInString(s)
	return string(unicode.ToUpper(r)) + s[size:]
}

// OpenAPIGenerator generates OpenAPI 3.0 specifications.
type OpenAPIGenerator struct {
	// Format specifies the output format: "json" or "yaml" (default: "yaml")
	Format string
}

// APIType returns the API type.
func (g *OpenAPIGenerator) APIType() string {
	return "rest"
}

// Generate produces an OpenAPI specification.
func (g *OpenAPIGenerator) Generate(endpoints []classify.ClassifiedRequest) ([]byte, error) {
	if len(endpoints) == 0 {
		return nil, nil
	}

	// Create OpenAPI document
	doc := &openapi3.T{
		OpenAPI: "3.0.3",
		Info: &openapi3.Info{
			Title:   "API Specification",
			Version: "1.0.0",
		},
		Paths:   openapi3.NewPaths(),
		Servers: openapi3.Servers{},
	}

	// Extract base URL from first endpoint
	parsedURL, err := url.Parse(endpoints[0].URL)
	if err == nil {
		baseURL := parsedURL.Scheme + "://" + parsedURL.Host
		doc.Servers = openapi3.Servers{
			&openapi3.Server{URL: baseURL},
		}
		// Update title based on host
		doc.Info.Title = parsedURL.Host + " API"
	}

	// Group endpoints by (normalized path, method)
	type endpointKey struct {
		path   string
		method string
	}
	endpointGroups := make(map[endpointKey][]classify.ClassifiedRequest)

	for _, endpoint := range endpoints {
		parsedURL, err := url.Parse(endpoint.URL)
		if err != nil {
			// Skip malformed URLs; they cannot contribute to the spec.
			continue
		}

		normalizedPath := NormalizePathWithNames(parsedURL.Path)
		method := strings.ToLower(endpoint.Method)

		key := endpointKey{normalizedPath, method}
		endpointGroups[key] = append(endpointGroups[key], endpoint)
	}

	// Build paths
	for key, group := range endpointGroups {
		pathItem := doc.Paths.Find(key.path)
		if pathItem == nil {
			pathItem = &openapi3.PathItem{}
			doc.Paths.Set(key.path, pathItem)
		}

		// Create operation
		operation := &openapi3.Operation{
			Summary:   capitalizeFirst(key.method) + " " + key.path,
			Responses: openapi3.NewResponses(),
		}

		// Use first endpoint from group as representative
		if len(group) > 0 {
			endpoint := group[0]

			// Collect union of query parameters from all endpoints in group
			queryParamNames := make(map[string]struct{})
			for _, ep := range group {
				for name := range ep.QueryParams {
					queryParamNames[name] = struct{}{}
				}
			}
			if len(queryParamNames) > 0 {
				operation.Parameters = make(openapi3.Parameters, 0, len(queryParamNames))
				for name := range queryParamNames {
					param := &openapi3.Parameter{
						Name:     name,
						In:       "query",
						Required: false,
						Schema: &openapi3.SchemaRef{
							Value: &openapi3.Schema{
								Type: &openapi3.Types{"string"},
							},
						},
					}
					operation.Parameters = append(operation.Parameters, &openapi3.ParameterRef{Value: param})
				}
			}

			// Add path parameters (extract from normalized path dynamically)
			pathParamNames := extractPathParams(key.path)
			for _, paramName := range pathParamNames {
				param := &openapi3.Parameter{
					Name:     paramName,
					In:       "path",
					Required: true,
					Schema: &openapi3.SchemaRef{
						Value: &openapi3.Schema{
							Type: &openapi3.Types{"string"},
						},
					},
				}
				operation.Parameters = append(operation.Parameters, &openapi3.ParameterRef{Value: param})
			}

			// Add request body for POST/PUT/PATCH
			if (key.method == "post" || key.method == "put" || key.method == "patch") && len(endpoint.Body) > 0 {
				schema := InferSchema(endpoint.Body)
				if schema != nil {
					operation.RequestBody = &openapi3.RequestBodyRef{
						Value: &openapi3.RequestBody{
							Content: openapi3.Content{
								"application/json": &openapi3.MediaType{
									Schema: schema,
								},
							},
						},
					}
				}
			}

			// Add response
			statusCode := "200"
			statusInt := 200
			if sc := endpoint.Response.StatusCode; sc > 0 {
				statusCode = strconv.Itoa(sc)
				statusInt = sc
			}

			description := http.StatusText(statusInt)
			if description == "" {
				description = statusCode
			}
			response := &openapi3.Response{
				Description: &description,
			}

			if len(endpoint.Response.Body) > 0 {
				schema := InferSchema(endpoint.Response.Body)
				if schema != nil {
					response.Content = openapi3.Content{
						"application/json": &openapi3.MediaType{
							Schema: schema,
						},
					}
				}
			}

			operation.Responses.Set(statusCode, &openapi3.ResponseRef{Value: response})
		}

		// Set operation for the method
		switch key.method {
		case "get":
			pathItem.Get = operation
		case "post":
			pathItem.Post = operation
		case "put":
			pathItem.Put = operation
		case "delete":
			pathItem.Delete = operation
		case "patch":
			pathItem.Patch = operation
		case "head":
			pathItem.Head = operation
		case "options":
			pathItem.Options = operation
		}
	}

	// Validate the spec
	specBytes, err := yaml.Marshal(doc)
	if err != nil {
		return nil, err
	}

	loader := openapi3.NewLoader()
	_, err = loader.LoadFromData(specBytes)
	if err != nil {
		return nil, err
	}

	// Serialize based on format
	format := g.Format
	if format == "" {
		format = "yaml"
	}

	if format == "json" {
		return json.MarshalIndent(doc, "", "  ")
	}

	// Reuse the already-serialized YAML from validation
	return specBytes, nil
}

// extractPathParams extracts parameter names from a path template like "/users/{userId}/posts/{postId}".
func extractPathParams(path string) []string {
	var params []string
	segments := strings.Split(path, "/")
	for _, segment := range segments {
		if strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}") {
			paramName := strings.TrimPrefix(strings.TrimSuffix(segment, "}"), "{")
			params = append(params, paramName)
		}
	}
	return params
}

// DefaultExtension returns the default file extension.
func (g *OpenAPIGenerator) DefaultExtension() string {
	return ".yaml"
}
