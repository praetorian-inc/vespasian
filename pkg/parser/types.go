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

// Package parser provides OpenAPI 3.x specification parsing functionality.
package parser

// ParameterLocation represents where a parameter is located in an HTTP request.
type ParameterLocation string

const (
	// LocationQuery represents a query string parameter
	LocationQuery ParameterLocation = "query"
	// LocationPath represents a path parameter
	LocationPath ParameterLocation = "path"
	// LocationHeader represents a header parameter
	LocationHeader ParameterLocation = "header"
	// LocationCookie represents a cookie parameter
	LocationCookie ParameterLocation = "cookie"
	// LocationBody represents a request body parameter
	LocationBody ParameterLocation = "body"
)

// Parameter represents a normalized API parameter.
type Parameter struct {
	Name     string
	Location ParameterLocation
	Type     string
	Format   string
	Required bool
	Schema   *SchemaRef
}

// SchemaRef represents a simplified JSON Schema reference.
type SchemaRef struct {
	Type       string
	Format     string
	Properties map[string]*SchemaRef
	Items      *SchemaRef
	Enum       []interface{}
	Required   []string
}

// RequestBody represents a normalized request body.
type RequestBody struct {
	ContentType string
	Required    bool
	Schema      *SchemaRef
}

// ResponseSchema represents a normalized response.
type ResponseSchema struct {
	Description string
	ContentType string
	Schema      *SchemaRef
}

// SecurityRequirement represents a security requirement for an endpoint.
type SecurityRequirement struct {
	Scheme string
	Scopes []string
}

// Endpoint represents a normalized API endpoint extracted from an OpenAPI spec.
type Endpoint struct {
	Method      string
	Path        string
	OperationID string
	Summary     string
	Parameters  []Parameter
	RequestBody *RequestBody
	Responses   map[int]ResponseSchema
	Security    []SecurityRequirement
}
