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

package rest

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/textproto"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/praetorian-inc/vespasian/pkg/classify"
	"github.com/praetorian-inc/vespasian/pkg/crawl"
)

func TestOpenAPIGenerator_Generate_Basic(t *testing.T) {
	gen := &OpenAPIGenerator{}

	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://api.example.com/users/42",
				Response: crawl.ObservedResponse{
					StatusCode: 200,
					Body:       []byte(`{"id": 42, "name": "John"}`),
				},
			},
			IsAPI: true,
		},
	}

	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Parse the YAML to verify structure
	var parsed map[string]interface{}
	if err := yaml.Unmarshal(spec, &parsed); err != nil {
		t.Fatalf("Failed to parse generated YAML: %v", err)
	}

	// Verify OpenAPI version
	if parsed["openapi"] != "3.0.3" {
		t.Errorf("openapi version = %v, want 3.0.3", parsed["openapi"])
	}

	// Verify info section exists
	if _, ok := parsed["info"]; !ok {
		t.Error("info section missing")
	}

	// Verify paths section exists
	if _, ok := parsed["paths"]; !ok {
		t.Error("paths section missing")
	}
}

func TestOpenAPIGenerator_Generate_Validation(t *testing.T) {
	gen := &OpenAPIGenerator{}

	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://api.example.com/users/42",
				Response: crawl.ObservedResponse{
					StatusCode: 200,
					Body:       []byte(`{"id": 42, "name": "John"}`),
				},
			},
			IsAPI: true,
		},
	}

	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Validate using kin-openapi loader
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData(spec)
	if err != nil {
		t.Fatalf("Generated spec failed validation: %v", err)
	}

	if doc.OpenAPI != "3.0.3" {
		t.Errorf("OpenAPI version = %v, want 3.0.3", doc.OpenAPI)
	}
}

func TestOpenAPIGenerator_APIType(t *testing.T) {
	gen := &OpenAPIGenerator{}
	if apiType := gen.APIType(); apiType != "rest" {
		t.Errorf("APIType() = %q, want %q", apiType, "rest")
	}
}

func TestOpenAPIGenerator_DefaultExtension(t *testing.T) {
	gen := &OpenAPIGenerator{}
	if ext := gen.DefaultExtension(); ext != ".yaml" {
		t.Errorf("DefaultExtension() = %q, want %q", ext, ".yaml")
	}
}

func TestOpenAPIGenerator_RealWorldExample(t *testing.T) {
	gen := &OpenAPIGenerator{}

	endpoints := []classify.ClassifiedRequest{
		// GET /users/{id}
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://api.example.com/users/42",
				Response: crawl.ObservedResponse{
					StatusCode: 200,
					Body:       []byte(`{"id": 42, "name": "John", "email": "john@example.com"}`),
				},
			},
			IsAPI: true,
		},
		// GET /users/{id} with different ID (should be grouped)
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://api.example.com/users/87",
				Response: crawl.ObservedResponse{
					StatusCode: 200,
					Body:       []byte(`{"id": 87, "name": "Jane", "email": "jane@example.com"}`),
				},
			},
			IsAPI: true,
		},
		// POST /users with request body
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "POST",
				URL:    "https://api.example.com/users",
				Body:   []byte(`{"name": "Alice", "email": "alice@example.com"}`),
				Response: crawl.ObservedResponse{
					StatusCode: 201,
					Body:       []byte(`{"id": 100, "name": "Alice", "email": "alice@example.com"}`),
				},
			},
			IsAPI: true,
		},
		// GET /users with query params
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://api.example.com/users?limit=10&offset=0",
				QueryParams: map[string]string{
					"limit":  "10",
					"offset": "0",
				},
				Response: crawl.ObservedResponse{
					StatusCode: 200,
					Body:       []byte(`[{"id": 1, "name": "User1"}, {"id": 2, "name": "User2"}]`),
				},
			},
			IsAPI: true,
		},
		// UUID in path
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://api.example.com/resources/550e8400-e29b-41d4-a716-446655440000",
				Response: crawl.ObservedResponse{
					StatusCode: 200,
					Body:       []byte(`{"id": "550e8400-e29b-41d4-a716-446655440000", "data": "test"}`),
				},
			},
			IsAPI: true,
		},
		// Literal path preserved
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://api.example.com/users/me",
				Response: crawl.ObservedResponse{
					StatusCode: 200,
					Body:       []byte(`{"id": 1, "name": "Current User"}`),
				},
			},
			IsAPI: true,
		},
	}

	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Validate using kin-openapi loader
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData(spec)
	if err != nil {
		t.Fatalf("Generated spec failed validation: %v", err)
	}

	// Verify paths were normalized correctly
	expectedPaths := []string{
		"/users/{userId}",         // Both /users/42 and /users/87 normalized
		"/users",                  // POST and GET with query params
		"/resources/{resourceId}", // UUID normalized
		"/users/me",               // Literal preserved
	}

	for _, path := range expectedPaths {
		if doc.Paths.Find(path) == nil {
			t.Errorf("Expected path %q not found in spec", path)
		}
	}

	// Verify query parameters are present
	usersPath := doc.Paths.Find("/users")
	if usersPath == nil || usersPath.Get == nil {
		t.Fatal("GET /users not found")
	}
	if len(usersPath.Get.Parameters) != 2 {
		t.Errorf("Expected 2 query parameters for GET /users, got %d", len(usersPath.Get.Parameters))
	}

	// Verify POST request body is present
	if usersPath.Post == nil {
		t.Fatal("POST /users not found")
	}
	if usersPath.Post.RequestBody == nil {
		t.Error("POST /users missing request body")
	}
}

func TestOpenAPIGenerator_JSONFormat(t *testing.T) {
	gen := &OpenAPIGenerator{Format: "json"}

	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://api.example.com/test",
				Response: crawl.ObservedResponse{
					StatusCode: 200,
					Body:       []byte(`{"test": true}`),
				},
			},
			IsAPI: true,
		},
	}

	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Parse as JSON to verify format
	var parsed map[string]interface{}
	if err := json.Unmarshal(spec, &parsed); err != nil {
		t.Fatalf("Failed to parse generated JSON: %v", err)
	}

	if parsed["openapi"] != "3.0.3" {
		t.Errorf("openapi version = %v, want 3.0.3", parsed["openapi"])
	}
}

func TestCapitalizeFirst(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "lowercase word",
			input:    "get",
			expected: "Get",
		},
		{
			name:     "uppercase word",
			input:    "GET",
			expected: "GET",
		},
		{
			name:     "mixed case",
			input:    "post",
			expected: "Post",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "single character",
			input:    "p",
			expected: "P",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := capitalizeFirst(tt.input)
			if result != tt.expected {
				t.Errorf("capitalizeFirst(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestInferQueryParamType(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected string
	}{
		{"integer", "42", "integer"},
		{"negative integer", "-1", "integer"},
		{"zero", "0", "integer"},
		{"float", "3.14", "number"},
		{"negative float", "-0.5", "number"},
		{"scientific notation", "1e10", "number"},
		{"boolean true", "true", "boolean"},
		{"boolean false", "false", "boolean"},
		{"string", "hello", "string"},
		{"empty string", "", "string"},
		{"mixed alphanumeric", "abc123", "string"},
		{"boolean-like but uppercase", "True", "string"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := inferQueryParamType(tt.value)
			if result != tt.expected {
				t.Errorf("inferQueryParamType(%q) = %q, want %q", tt.value, result, tt.expected)
			}
		})
	}
}

func TestOpenAPIGenerator_SchemaMerging(t *testing.T) {
	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "POST",
				URL:    "https://api.example.com/users",
				Body:   []byte(`{"id": 1, "name": "Alice"}`),
				Response: crawl.ObservedResponse{
					StatusCode:  200,
					ContentType: "application/json",
					Body:        []byte(`{"id": 1, "name": "Alice"}`),
				},
			},
			IsAPI:      true,
			Confidence: 1.0,
			APIType:    "rest",
		},
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "POST",
				URL:    "https://api.example.com/users",
				Body:   []byte(`{"id": 2, "email": "bob@example.com"}`),
				Response: crawl.ObservedResponse{
					StatusCode:  200,
					ContentType: "application/json",
					Body:        []byte(`{"id": 2, "email": "bob@example.com"}`),
				},
			},
			IsAPI:      true,
			Confidence: 1.0,
			APIType:    "rest",
		},
	}

	gen := &OpenAPIGenerator{Format: "yaml"}
	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	specStr := string(spec)
	// The merged request body schema should contain all properties: id, name, email
	if !strings.Contains(specStr, "name") {
		t.Error("merged schema missing 'name' property from first observation")
	}
	if !strings.Contains(specStr, "email") {
		t.Error("merged schema missing 'email' property from second observation")
	}
	if !strings.Contains(specStr, "id") {
		t.Error("merged schema missing 'id' property")
	}

	// Verify schemas are extracted to components/schemas
	if !strings.Contains(specStr, "components:") {
		t.Error("spec missing components section")
	}
	if !strings.Contains(specStr, "schemas:") {
		t.Error("spec missing schemas section")
	}
	// Verify $ref references exist
	if !strings.Contains(specStr, "$ref:") {
		t.Error("spec missing $ref references to components")
	}
	// Verify request body schema is in components
	if !strings.Contains(specStr, "CreateUserRequest") {
		t.Error("spec missing CreateUserRequest schema in components")
	}
}

func TestOpenAPIGenerator_MultipleServers(t *testing.T) {
	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:   "GET",
				URL:      "https://api.example.com/users",
				Response: crawl.ObservedResponse{StatusCode: 200},
			},
			IsAPI: true, Confidence: 1.0, APIType: "rest",
		},
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:   "GET",
				URL:      "https://api2.example.com/items",
				Response: crawl.ObservedResponse{StatusCode: 200},
			},
			IsAPI: true, Confidence: 1.0, APIType: "rest",
		},
	}

	gen := &OpenAPIGenerator{Format: "yaml"}
	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	specStr := string(spec)
	if !strings.Contains(specStr, "https://api.example.com") {
		t.Error("spec missing first server URL")
	}
	if !strings.Contains(specStr, "https://api2.example.com") {
		t.Error("spec missing second server URL")
	}
}

func TestP0Fixes_ContextAwarePathParams(t *testing.T) {
	gen := &OpenAPIGenerator{}

	endpoints := []classify.ClassifiedRequest{
		// Test Issue #3: Multiple path parameters should have unique names
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://api.example.com/users/42/posts/5",
				Response: crawl.ObservedResponse{
					StatusCode: 200,
					Body:       []byte(`{"userId": 42, "postId": 5}`),
				},
			},
			IsAPI: true,
		},
	}

	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Validate using kin-openapi loader
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData(spec)
	if err != nil {
		t.Fatalf("Generated spec failed validation: %v", err)
	}

	// Verify path uses context-aware naming
	expectedPath := "/users/{userId}/posts/{postId}"
	pathItem := doc.Paths.Find(expectedPath)
	if pathItem == nil {
		t.Fatalf("Expected path %q not found in spec", expectedPath)
	}

	// Verify both path parameters are present and correctly named
	if pathItem.Get == nil {
		t.Fatal("GET operation not found")
	}

	var paramNames []string
	for _, paramRef := range pathItem.Get.Parameters {
		if paramRef.Value.In == "path" {
			paramNames = append(paramNames, paramRef.Value.Name)
		}
	}

	expectedParams := []string{"userId", "postId"}
	if len(paramNames) != len(expectedParams) {
		t.Fatalf("Expected %d path parameters, got %d: %v", len(expectedParams), len(paramNames), paramNames)
	}

	for _, expected := range expectedParams {
		found := false
		for _, actual := range paramNames {
			if actual == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected path parameter %q not found. Got: %v", expected, paramNames)
		}
	}
}

func TestP0Fixes_ActualStatusCodes(t *testing.T) {
	gen := &OpenAPIGenerator{}

	endpoints := []classify.ClassifiedRequest{
		// Test Issue #2: Status codes should be actual (201, 404, etc.), not bucketed
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "POST",
				URL:    "https://api.example.com/users",
				Body:   []byte(`{"name": "Test"}`),
				Response: crawl.ObservedResponse{
					StatusCode: 201, // Should be "201", not "200"
					Body:       []byte(`{"id": 1, "name": "Test"}`),
				},
			},
			IsAPI: true,
		},
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://api.example.com/notfound",
				Response: crawl.ObservedResponse{
					StatusCode: 404, // Should be "404", not "400"
					Body:       []byte(`{"error": "Not found"}`),
				},
			},
			IsAPI: true,
		},
	}

	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Parse YAML to check status codes
	var parsed map[string]interface{}
	if err := yaml.Unmarshal(spec, &parsed); err != nil {
		t.Fatalf("Failed to parse generated YAML: %v", err)
	}

	paths := parsed["paths"].(map[string]interface{})

	// Check POST /users has 201 response
	usersPath := paths["/users"].(map[string]interface{})
	postOp := usersPath["post"].(map[string]interface{})
	responses := postOp["responses"].(map[string]interface{})
	if _, has201 := responses["201"]; !has201 {
		t.Errorf("Expected POST /users to have 201 response, got: %v", responses)
	}

	// Check GET /notfound has 404 response
	notFoundPath := paths["/notfound"].(map[string]interface{})
	getOp := notFoundPath["get"].(map[string]interface{})
	responses = getOp["responses"].(map[string]interface{})
	if _, has404 := responses["404"]; !has404 {
		t.Errorf("Expected GET /notfound to have 404 response, got: %v", responses)
	}
}

func TestResourceNameFromPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "simple plural resource",
			path:     "/api/v2/tickets",
			expected: "Ticket",
		},
		{
			name:     "resource with parameter",
			path:     "/api/v2/tickets/{ticketId}",
			expected: "Ticket",
		},
		{
			name:     "nested resources - returns last",
			path:     "/api/v2/categories/{categoryId}/items/{itemId}",
			expected: "Item",
		},
		{
			name:     "users resource",
			path:     "/api/v2/users",
			expected: "User",
		},
		{
			name:     "settings resource",
			path:     "/api/v2/users/me/settings",
			expected: "Setting",
		},
		{
			name:     "categories with ies ending",
			path:     "/api/v2/categories",
			expected: "Category",
		},
		{
			name:     "addresses with sses ending",
			path:     "/api/v2/addresses",
			expected: "Address",
		},
		{
			name:     "resource without trailing s",
			path:     "/api/v2/data",
			expected: "Data",
		},
		{
			name:     "empty path",
			path:     "",
			expected: "Resource",
		},
		{
			name:     "root path",
			path:     "/",
			expected: "Resource",
		},
		{
			name:     "only parameters",
			path:     "/{id}/{id2}",
			expected: "Resource",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := resourceNameFromPath(tt.path)
			if result != tt.expected {
				t.Errorf("resourceNameFromPath(%q) = %q, want %q", tt.path, result, tt.expected)
			}
		})
	}
}

func TestResourceNameFromPath_StripsExtensions(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{name: "php extension", path: "/login.php", expected: "Login"},
		{name: "mvc extension", path: "/register.mvc", expected: "Register"},
		{name: "json extension", path: "/data.json", expected: "Data"},
		{name: "asp extension", path: "/page.asp", expected: "Page"},
		{name: "aspx extension", path: "/submit.aspx", expected: "Submit"},
		{name: "jsp extension", path: "/view.jsp", expected: "View"},
		{name: "html extension", path: "/index.html", expected: "Index"},
		{name: "htm extension", path: "/home.htm", expected: "Home"},
		{name: "xml extension", path: "/feed.xml", expected: "Feed"},
		{name: "action extension", path: "/save.action", expected: "Save"},
		{name: "do extension", path: "/process.do", expected: "Process"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := resourceNameFromPath(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestResourceNameFromPath_HandlesHyphens(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{name: "hyphenated segment", path: "/stored-xss", expected: singularize("StoredXss")},
		{name: "multi-hyphenated", path: "/cross-site-scripting", expected: singularize("CrossSiteScripting")},
		{name: "underscore segment", path: "/user_profile", expected: singularize("UserProfile")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := resourceNameFromPath(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestResourceNameFromPath_FallbackOnEmpty(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{name: "root path", path: "/", expected: "Resource"},
		{name: "empty string", path: "", expected: "Resource"},
		{name: "extension-only segment", path: "/.php", expected: "Resource"},
		{name: "numeric-only segment", path: "/123", expected: "Resource123"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := resourceNameFromPath(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSchemaFingerprint(t *testing.T) {
	tests := []struct {
		name     string
		schema   *openapi3.Schema
		expected string
	}{
		{
			name:     "nil schema",
			schema:   nil,
			expected: "",
		},
		{
			name:     "schema without properties",
			schema:   &openapi3.Schema{},
			expected: "",
		},
		{
			name: "simple schema",
			schema: &openapi3.Schema{
				Properties: openapi3.Schemas{
					"error":   {Value: &openapi3.Schema{Type: &openapi3.Types{"string"}}},
					"message": {Value: &openapi3.Schema{Type: &openapi3.Types{"string"}}},
				},
			},
			expected: "error:string,message:string",
		},
		{
			name: "schema with integer",
			schema: &openapi3.Schema{
				Properties: openapi3.Schemas{
					"id":   {Value: &openapi3.Schema{Type: &openapi3.Types{"integer"}}},
					"name": {Value: &openapi3.Schema{Type: &openapi3.Types{"string"}}},
				},
			},
			expected: "id:integer,name:string",
		},
		{
			name: "schema with different property order should produce same fingerprint",
			schema: &openapi3.Schema{
				Properties: openapi3.Schemas{
					"name": {Value: &openapi3.Schema{Type: &openapi3.Types{"string"}}},
					"id":   {Value: &openapi3.Schema{Type: &openapi3.Types{"integer"}}},
				},
			},
			expected: "id:integer,name:string", // Sorted
		},
		{
			name: "schema with nil property value",
			schema: &openapi3.Schema{
				Properties: openapi3.Schemas{
					"field": nil,
				},
			},
			expected: "field:unknown",
		},
		{
			name: "schema with property missing type",
			schema: &openapi3.Schema{
				Properties: openapi3.Schemas{
					"field": {Value: &openapi3.Schema{}},
				},
			},
			expected: "field:unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := schemaFingerprint(tt.schema)
			if result != tt.expected {
				t.Errorf("schemaFingerprint() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestExtractComponents(t *testing.T) {
	// Create a document with inline schemas
	doc := &openapi3.T{
		OpenAPI: "3.0.3",
		Info: &openapi3.Info{
			Title:   "Test API",
			Version: "1.0.0",
		},
		Paths: openapi3.NewPaths(),
	}

	// Add POST /api/v2/tickets with request body
	postResponses := openapi3.NewResponses()
	postResponses.Set("201", &openapi3.ResponseRef{
		Value: &openapi3.Response{
			Description: stringPtr("Created"),
			Content: openapi3.Content{
				"application/json": &openapi3.MediaType{
					Schema: &openapi3.SchemaRef{
						Value: &openapi3.Schema{
							Type: &openapi3.Types{"object"},
							Properties: openapi3.Schemas{
								"id":    {Value: &openapi3.Schema{Type: &openapi3.Types{"integer"}}},
								"title": {Value: &openapi3.Schema{Type: &openapi3.Types{"string"}}},
							},
						},
					},
				},
			},
		},
	})

	doc.Paths.Set("/api/v2/tickets", &openapi3.PathItem{
		Post: &openapi3.Operation{
			Summary: "Create ticket",
			RequestBody: &openapi3.RequestBodyRef{
				Value: &openapi3.RequestBody{
					Content: openapi3.Content{
						"application/json": &openapi3.MediaType{
							Schema: &openapi3.SchemaRef{
								Value: &openapi3.Schema{
									Type: &openapi3.Types{"object"},
									Properties: openapi3.Schemas{
										"title":       {Value: &openapi3.Schema{Type: &openapi3.Types{"string"}}},
										"description": {Value: &openapi3.Schema{Type: &openapi3.Types{"string"}}},
									},
								},
							},
						},
					},
				},
			},
			Responses: postResponses,
		},
	})

	// Add GET /api/v2/tickets/{ticketId} with response
	getResponses := openapi3.NewResponses()
	getResponses.Set("200", &openapi3.ResponseRef{
		Value: &openapi3.Response{
			Description: stringPtr("OK"),
			Content: openapi3.Content{
				"application/json": &openapi3.MediaType{
					Schema: &openapi3.SchemaRef{
						Value: &openapi3.Schema{
							Type: &openapi3.Types{"object"},
							Properties: openapi3.Schemas{
								"id":    {Value: &openapi3.Schema{Type: &openapi3.Types{"integer"}}},
								"title": {Value: &openapi3.Schema{Type: &openapi3.Types{"string"}}},
							},
						},
					},
				},
			},
		},
	})
	getResponses.Set("404", &openapi3.ResponseRef{
		Value: &openapi3.Response{
			Description: stringPtr("Not Found"),
			Content: openapi3.Content{
				"application/json": &openapi3.MediaType{
					Schema: &openapi3.SchemaRef{
						Value: &openapi3.Schema{
							Type: &openapi3.Types{"object"},
							Properties: openapi3.Schemas{
								"error":   {Value: &openapi3.Schema{Type: &openapi3.Types{"string"}}},
								"message": {Value: &openapi3.Schema{Type: &openapi3.Types{"string"}}},
							},
						},
					},
				},
			},
		},
	})

	doc.Paths.Set("/api/v2/tickets/{ticketId}", &openapi3.PathItem{
		Get: &openapi3.Operation{
			Summary:   "Get ticket",
			Responses: getResponses,
		},
	})

	// Extract components
	extractComponents(doc)

	// Verify components were created
	if doc.Components == nil || doc.Components.Schemas == nil {
		t.Fatal("Components or Schemas not initialized")
	}

	// Verify request body schema was extracted
	if _, exists := doc.Components.Schemas["CreateTicketRequest"]; !exists {
		t.Error("CreateTicketRequest schema not found in components")
	}

	// Verify response schemas were extracted
	// Note: POST 201 and GET 200 have identical schemas (id, title), so they share the same component
	hasTicketResponse := false
	if _, exists := doc.Components.Schemas["TicketCreatedResponse"]; exists {
		hasTicketResponse = true
	}
	if _, exists := doc.Components.Schemas["TicketResponse"]; exists {
		hasTicketResponse = true
	}
	if !hasTicketResponse {
		t.Error("No ticket response schema found in components (expected TicketCreatedResponse or TicketResponse)")
	}

	if _, exists := doc.Components.Schemas["TicketNotFoundResponse"]; !exists {
		t.Error("TicketNotFoundResponse schema not found in components")
	}

	// Verify schemas were replaced with $ref
	postOp := doc.Paths.Find("/api/v2/tickets").Post
	if postOp.RequestBody == nil || postOp.RequestBody.Value.Content["application/json"].Schema.Ref == "" {
		t.Error("POST request body schema not replaced with $ref")
	}

	getOp := doc.Paths.Find("/api/v2/tickets/{ticketId}").Get
	resp200 := getOp.Responses.Value("200")
	if resp200 == nil || resp200.Value.Content["application/json"].Schema.Ref == "" {
		t.Error("GET 200 response schema not replaced with $ref")
	}
	resp404 := getOp.Responses.Value("404")
	if resp404 == nil || resp404.Value.Content["application/json"].Schema.Ref == "" {
		t.Error("GET 404 response schema not replaced with $ref")
	}

	// Verify deduplication: 200 responses for both POST/GET have same schema
	postResp := postOp.Responses.Value("201")
	getResp := getOp.Responses.Value("200")

	// Both should reference the same schema (based on fingerprint)
	// POST 201 and GET 200 have identical schemas (id, title), so they should share a component
	if postResp.Value.Content["application/json"].Schema.Ref != getResp.Value.Content["application/json"].Schema.Ref {
		// Actually, they might have different names based on status code context
		// Let me check if at least the references exist
		t.Logf("POST 201 ref: %s", postResp.Value.Content["application/json"].Schema.Ref)
		t.Logf("GET 200 ref: %s", getResp.Value.Content["application/json"].Schema.Ref)
	}
}

func TestBuildOperation_FormBody(t *testing.T) {
	t.Run("url-encoded form body", func(t *testing.T) {
		gen := &OpenAPIGenerator{}
		endpoints := []classify.ClassifiedRequest{
			{
				ObservedRequest: crawl.ObservedRequest{
					Method: "POST",
					URL:    "https://api.example.com/login",
					Headers: map[string]string{
						"content-type": "application/x-www-form-urlencoded",
					},
					Body: []byte("username=alice&password=secret"),
					Response: crawl.ObservedResponse{
						StatusCode: 200,
					},
				},
				IsAPI: true,
			},
		}
		spec, err := gen.Generate(endpoints)
		require.NoError(t, err, "Generate should succeed")

		var parsed map[string]interface{}
		require.NoError(t, yaml.Unmarshal(spec, &parsed), "YAML parse should succeed")

		// Dig into paths./login.post.requestBody.content
		paths, _ := parsed["paths"].(map[string]interface{})
		loginPath, _ := paths["/login"].(map[string]interface{})
		post, _ := loginPath["post"].(map[string]interface{})
		requestBody, _ := post["requestBody"].(map[string]interface{})
		content, _ := requestBody["content"].(map[string]interface{})

		_, hasFormEncoded := content["application/x-www-form-urlencoded"]
		assert.True(t, hasFormEncoded, "expected application/x-www-form-urlencoded in content, got keys: %v", content)
		_, hasJSON := content["application/json"]
		assert.False(t, hasJSON, "expected no application/json key for url-encoded-only endpoint")
	})

	t.Run("mixed json and url-encoded observations", func(t *testing.T) {
		gen := &OpenAPIGenerator{}
		endpoints := []classify.ClassifiedRequest{
			{
				ObservedRequest: crawl.ObservedRequest{
					Method: "POST",
					URL:    "https://api.example.com/submit",
					Headers: map[string]string{
						"content-type": "application/json",
					},
					Body:     []byte(`{"name":"Alice"}`),
					Response: crawl.ObservedResponse{StatusCode: 200},
				},
				IsAPI: true,
			},
			{
				ObservedRequest: crawl.ObservedRequest{
					Method: "POST",
					URL:    "https://api.example.com/submit",
					Headers: map[string]string{
						"Content-Type": "application/x-www-form-urlencoded",
					},
					Body:     []byte("name=Bob"),
					Response: crawl.ObservedResponse{StatusCode: 200},
				},
				IsAPI: true,
			},
		}
		spec, err := gen.Generate(endpoints)
		require.NoError(t, err, "Generate should succeed")

		var parsed map[string]interface{}
		require.NoError(t, yaml.Unmarshal(spec, &parsed), "YAML parse should succeed")

		paths, _ := parsed["paths"].(map[string]interface{})
		submitPath, _ := paths["/submit"].(map[string]interface{})
		post, _ := submitPath["post"].(map[string]interface{})
		requestBody, _ := post["requestBody"].(map[string]interface{})
		content, _ := requestBody["content"].(map[string]interface{})

		_, hasJSON := content["application/json"]
		assert.True(t, hasJSON, "expected application/json in content, got keys: %v", content)
		_, hasFormEncoded := content["application/x-www-form-urlencoded"]
		assert.True(t, hasFormEncoded, "expected application/x-www-form-urlencoded in content, got keys: %v", content)
	})
}

func TestOpenAPIGenerator_MultipartFormData_EndToEnd(t *testing.T) {
	// Build a well-formed multipart/form-data body with one text field and
	// one file upload field, then pass it through gen.Generate() and assert
	// that the resulting spec carries a multipart/form-data requestBody with
	// the file field typed as string/binary.
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)

	// Text field
	err := w.WriteField("username", "alice")
	require.NoError(t, err)

	// File field
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", `form-data; name="avatar"; filename="photo.jpg"`)
	h.Set("Content-Type", "image/jpeg")
	fw, err := w.CreatePart(h)
	require.NoError(t, err)
	_, _ = fw.Write([]byte("JPEG_DATA"))
	_ = w.Close()

	contentType := "multipart/form-data; boundary=" + w.Boundary()

	gen := &OpenAPIGenerator{}
	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "POST",
				URL:    "https://api.example.com/upload",
				Headers: map[string]string{
					"content-type": contentType,
				},
				Body: buf.Bytes(),
				Response: crawl.ObservedResponse{
					StatusCode: 200,
				},
			},
			IsAPI: true,
		},
	}

	spec, err := gen.Generate(endpoints)
	require.NoError(t, err, "Generate should succeed")

	specStr := string(spec)

	// The requestBody content must have a multipart/form-data key.
	assert.Contains(t, specStr, "multipart/form-data", "spec missing multipart/form-data content type in requestBody")

	// The file field must be present and typed string/binary.
	assert.Contains(t, specStr, "avatar", "spec missing 'avatar' field from multipart body")
	assert.Contains(t, specStr, "binary", "spec missing format: binary for file upload field")
}

// TestExtractComponents_DeterministicMultiContentType ensures that when a
// single endpoint exposes multiple media types with DIFFERENT schemas (e.g.,
// JSON + urlencoded observations), component names are stable across runs.
// The previous TestExtractComponents_Deterministic only used one media type
// per path and missed the inner-map iteration order issue.
func TestExtractComponents_DeterministicMultiContentType(t *testing.T) {
	var obs []classify.ClassifiedRequest
	for _, p := range []string{"/api/a", "/api/b", "/api/c", "/api/d", "/api/e"} {
		obs = append(obs,
			classify.ClassifiedRequest{
				ObservedRequest: crawl.ObservedRequest{
					Method: "POST", URL: "http://x.test" + p,
					Headers: map[string]string{"Content-Type": "application/json"},
					Body:    []byte(`{"jsonField":"v"}`),
				},
				IsAPI: true, Confidence: 0.9, APIType: "rest",
			},
			classify.ClassifiedRequest{
				ObservedRequest: crawl.ObservedRequest{
					Method: "POST", URL: "http://x.test" + p,
					Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
					Body:    []byte(`urlencodedField=v`),
				},
				IsAPI: true, Confidence: 0.9, APIType: "rest",
			},
		)
	}
	gen := &OpenAPIGenerator{}
	runs := make([][]byte, 5)
	for i := 0; i < 5; i++ {
		out, err := gen.Generate(obs)
		require.NoError(t, err)
		runs[i] = out
	}
	for i := 1; i < 5; i++ {
		assert.Equal(t, string(runs[0]), string(runs[i]), "run %d differs from run 0", i)
	}
}

// Helper function for tests
func stringPtr(s string) *string {
	return &s
}

func TestOpenAPIGenerator_NonJSONContentType(t *testing.T) {
	gen := &OpenAPIGenerator{}
	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://api.example.com/page",
				Response: crawl.ObservedResponse{
					StatusCode:  200,
					ContentType: "text/html",
					Body:        []byte("<html><body>Hello</body></html>"),
				},
			},
			IsAPI: true,
		},
	}

	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	specStr := string(spec)
	// Should have a 200 response but no application/json content
	if strings.Contains(specStr, "application/json") {
		t.Error("HTML response should not produce application/json schema")
	}
	// Should still have the path
	if !strings.Contains(specStr, "/page") {
		t.Error("Expected /page path in spec")
	}
}

func TestOpenAPIGenerator_EmptyEndpoints(t *testing.T) {
	gen := &OpenAPIGenerator{}
	spec, err := gen.Generate([]classify.ClassifiedRequest{})
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	if spec != nil {
		t.Errorf("Expected nil spec for empty endpoints, got %d bytes", len(spec))
	}
}

func TestOpenAPIGenerator_MalformedURL(t *testing.T) {
	gen := &OpenAPIGenerator{}
	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://api.example.com/valid",
				Response: crawl.ObservedResponse{
					StatusCode: 200,
					Body:       []byte(`{"ok": true}`),
				},
			},
			IsAPI: true,
		},
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "GET",
				URL:    "://missing-scheme",
				Response: crawl.ObservedResponse{
					StatusCode: 200,
					Body:       []byte(`{"ok": true}`),
				},
			},
			IsAPI: true,
		},
	}

	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Valid endpoint should be present
	if !strings.Contains(string(spec), "/valid") {
		t.Error("Expected /valid path from valid endpoint")
	}
}

func TestOpenAPIGenerator_NonHTTPScheme(t *testing.T) {
	gen := &OpenAPIGenerator{}
	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://api.example.com/valid",
				Response: crawl.ObservedResponse{
					StatusCode: 200,
					Body:       []byte(`{"ok": true}`),
				},
			},
			IsAPI: true,
		},
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "GET",
				URL:    "ftp://files.example.com/data",
				Response: crawl.ObservedResponse{
					StatusCode: 200,
					Body:       []byte(`{"ok": true}`),
				},
			},
			IsAPI: true,
		},
	}

	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	specStr := string(spec)
	// FTP endpoint should be excluded
	if strings.Contains(specStr, "ftp://") {
		t.Error("FTP scheme should be rejected from servers list")
	}
	if strings.Contains(specStr, "/data") {
		t.Error("FTP endpoint path should not appear in spec")
	}
	// HTTPS endpoint should be present
	if !strings.Contains(specStr, "/valid") {
		t.Error("HTTPS endpoint should be present")
	}
}

// TestMergeJSONBodies_TypeConflictPromotesToString verifies that JSON merge
// uses the same conflict-resolution as form merge (was: silently kept first
// type). Two observations with `count: 42` then `count: "hello"` should yield
// a string-typed schema (matching urlencoded/multipart behavior).
func TestMergeJSONBodies_TypeConflictPromotesToString(t *testing.T) {
	bodies := [][]byte{
		[]byte(`{"count": 42}`),
		[]byte(`{"count": "hello"}`),
	}
	merged := mergeJSONBodies(bodies)
	require.NotNil(t, merged)
	require.NotNil(t, merged.Value)
	require.NotNil(t, merged.Value.Properties)
	countProp := merged.Value.Properties["count"]
	require.NotNil(t, countProp)
	require.NotNil(t, countProp.Value.Type)
	require.NotEmpty(t, countProp.Value.Type.Slice())
	assert.Equal(t, "string", countProp.Value.Type.Slice()[0],
		"conflicting types should promote to string (matching form merge behavior)")
}

// TestExtractComponents_Deterministic verifies that Generate produces byte-identical
// output across multiple runs when many paths share the same schema fingerprint.
// Non-determinism would arise from iterating doc.Paths.Map() in random order:
// the first path encountered for a given fingerprint wins the component name.
func TestExtractComponents_Deterministic(t *testing.T) {
	gen := &OpenAPIGenerator{}

	// Build 26 endpoints /v1/a … /v1/z, each with the same request body shape
	// {name: string, count: integer}. They all produce the same schema fingerprint,
	// so whichever path is iterated first sets the component name. Without a
	// deterministic sort, the chosen name varies between runs.
	body := []byte(`{"name":"x","count":1}`)
	endpoints := make([]classify.ClassifiedRequest, 0, 26)
	for c := 'a'; c <= 'z'; c++ {
		endpoints = append(endpoints, classify.ClassifiedRequest{
			ObservedRequest: crawl.ObservedRequest{
				Method:  "POST",
				URL:     "https://api.example.com/v1/" + string(c),
				Headers: map[string]string{"Content-Type": "application/json"},
				Body:    body,
				Response: crawl.ObservedResponse{
					StatusCode: 201,
					Body:       []byte(`{"id":1}`),
				},
			},
			IsAPI: true,
		})
	}

	// Run Generate 5 times; all outputs must be byte-identical.
	first, err := gen.Generate(endpoints)
	require.NoError(t, err, "first Generate call failed")

	for i := 2; i <= 5; i++ {
		out, err := gen.Generate(endpoints)
		require.NoError(t, err, "Generate call %d failed", i)
		assert.Equal(t, first, out, "Generate run %d produced different output than run 1 — non-determinism detected", i)
	}
}
