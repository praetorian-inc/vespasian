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

package parser

import (
	"context"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/getkin/kin-openapi/openapi3"
)

// Parse reads an OpenAPI spec from a reader and returns normalized endpoints.
func Parse(r io.Reader) ([]Endpoint, error) {
	// Read all data from reader with size limit (50MB)
	const maxSpecSize = 50 * 1024 * 1024 // 50MB
	data, err := io.ReadAll(io.LimitReader(r, maxSpecSize))
	if err != nil {
		return nil, fmt.Errorf("reading spec: %w", err)
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("empty input")
	}

	// Load and validate spec
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData(data)
	if err != nil {
		return nil, fmt.Errorf("loading spec: %w", err)
	}

	ctx := context.Background()
	if err := doc.Validate(ctx); err != nil {
		return nil, fmt.Errorf("validating spec: %w", err)
	}

	// Extract endpoints
	var endpoints []Endpoint

	for path, pathItem := range doc.Paths.Map() {
		// Process each HTTP method
		operations := map[string]*openapi3.Operation{
			"GET":     pathItem.Get,
			"POST":    pathItem.Post,
			"PUT":     pathItem.Put,
			"DELETE":  pathItem.Delete,
			"PATCH":   pathItem.Patch,
			"OPTIONS": pathItem.Options,
			"HEAD":    pathItem.Head,
			"TRACE":   pathItem.Trace,
		}

		for method, operation := range operations {
			if operation == nil {
				continue
			}

			endpoint := Endpoint{
				Method:      method,
				Path:        path,
				OperationID: operation.OperationID,
				Summary:     operation.Summary,
				Responses:   make(map[int]ResponseSchema),
			}

			// Extract parameters (merge path-level and operation-level)
			params := mergeParameters(pathItem.Parameters, operation.Parameters)
			endpoint.Parameters = extractParameters(params)

			// Extract request body
			if operation.RequestBody != nil && operation.RequestBody.Value != nil {
				endpoint.RequestBody = extractRequestBody(operation.RequestBody.Value)
			}

			// Extract response schemas
			endpoint.Responses = extractResponses(operation.Responses)

			// Extract security requirements
			endpoint.Security = extractSecurity(operation.Security, doc.Security)

			endpoints = append(endpoints, endpoint)
		}
	}

	return endpoints, nil
}

// ParseFile is a convenience wrapper that opens a file and calls Parse.
func ParseFile(path string) (endpoints []Endpoint, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening file: %w", err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("closing file: %w", cerr)
		}
	}()

	return Parse(f)
}

// mergeParameters combines path-level and operation-level parameters.
// Operation-level parameters override path-level by name+location.
func mergeParameters(pathParams, opParams openapi3.Parameters) openapi3.Parameters {
	merged := make(openapi3.Parameters, 0, len(pathParams)+len(opParams))

	// Add path-level parameters first
	merged = append(merged, pathParams...)

	// Add operation-level parameters, replacing any duplicates
	for _, opParam := range opParams {
		if opParam == nil || opParam.Value == nil {
			continue
		}

		// Check if this parameter overrides a path-level one
		replaced := false
		for i, pathParam := range merged {
			if pathParam == nil || pathParam.Value == nil {
				continue
			}
			if pathParam.Value.Name == opParam.Value.Name &&
				pathParam.Value.In == opParam.Value.In {
				merged[i] = opParam
				replaced = true
				break
			}
		}

		if !replaced {
			merged = append(merged, opParam)
		}
	}

	return merged
}

// extractParameters converts OpenAPI parameters to normalized Parameter structs.
func extractParameters(params openapi3.Parameters) []Parameter {
	var result []Parameter

	for _, paramRef := range params {
		if paramRef == nil || paramRef.Value == nil {
			continue
		}

		param := paramRef.Value
		p := Parameter{
			Name:     param.Name,
			Location: ParameterLocation(param.In),
			Required: param.Required,
		}

		// Extract schema info
		if param.Schema != nil && param.Schema.Value != nil {
			schema := convertSchema(param.Schema)
			p.Schema = schema
			p.Type = schema.Type
			p.Format = schema.Format
		}

		result = append(result, p)
	}

	return result
}

// selectContentType selects the best content type from available options.
// Prefers application/json, falls back to first available type.
func selectContentType(content openapi3.Content) (string, *openapi3.MediaType) {
	if mt, ok := content["application/json"]; ok {
		return "application/json", mt
	}
	for ct, mt := range content {
		return ct, mt
	}
	return "", nil
}

// extractRequestBody converts an OpenAPI request body to normalized RequestBody.
func extractRequestBody(reqBody *openapi3.RequestBody) *RequestBody {
	body := &RequestBody{
		Required: reqBody.Required,
	}

	contentType, mediaType := selectContentType(reqBody.Content)
	body.ContentType = contentType
	if mediaType != nil && mediaType.Schema != nil {
		body.Schema = convertSchema(mediaType.Schema)
	}

	return body
}

// extractResponses converts OpenAPI responses to normalized ResponseSchema map.
func extractResponses(responses *openapi3.Responses) map[int]ResponseSchema {
	result := make(map[int]ResponseSchema)

	if responses == nil {
		return result
	}

	for statusStr, responseRef := range responses.Map() {
		if responseRef == nil || responseRef.Value == nil {
			continue
		}

		// Parse status code (skip non-numeric like "default")
		statusCode, err := strconv.Atoi(statusStr)
		if err != nil {
			continue
		}

		response := responseRef.Value
		description := ""
		if response.Description != nil {
			description = *response.Description
		}
		rs := ResponseSchema{
			Description: description,
		}

		// Extract schema from content
		if response.Content != nil {
			contentType, mediaType := selectContentType(response.Content)
			rs.ContentType = contentType
			if mediaType != nil && mediaType.Schema != nil {
				rs.Schema = convertSchema(mediaType.Schema)
			}
		}

		result[statusCode] = rs
	}

	return result
}

// extractSecurity extracts security requirements from operation or global level.
func extractSecurity(opSecurity *openapi3.SecurityRequirements, globalSecurity openapi3.SecurityRequirements) []SecurityRequirement {
	var result []SecurityRequirement

	// Use operation-level security if present, otherwise use global
	secReqs := globalSecurity
	if opSecurity != nil {
		secReqs = *opSecurity
	}

	for _, secReq := range secReqs {
		for scheme, scopes := range secReq {
			result = append(result, SecurityRequirement{
				Scheme: scheme,
				Scopes: scopes,
			})
		}
	}

	return result
}

// convertSchema converts an OpenAPI schema reference to simplified SchemaRef.
func convertSchema(schemaRef *openapi3.SchemaRef) *SchemaRef {
	if schemaRef == nil || schemaRef.Value == nil {
		return nil
	}

	schema := schemaRef.Value
	schemaType := ""
	if types := schema.Type.Slice(); len(types) > 0 {
		schemaType = types[0]
	}
	result := &SchemaRef{
		Type:     schemaType,
		Format:   schema.Format,
		Required: schema.Required,
	}

	// Convert enum values
	if len(schema.Enum) > 0 {
		result.Enum = schema.Enum
	}

	// Convert properties (for object types)
	if schema.Properties != nil {
		result.Properties = make(map[string]*SchemaRef)
		for propName, propRef := range schema.Properties {
			result.Properties[propName] = convertSchema(propRef)
		}
	}

	// Convert items (for array types)
	if schema.Items != nil {
		result.Items = convertSchema(schema.Items)
	}

	return result
}
