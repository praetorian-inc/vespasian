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
	"encoding/json"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/praetorian-inc/vespasian/pkg/classify"
	"github.com/praetorian-inc/vespasian/pkg/crawl"
	"gopkg.in/yaml.v3"
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
		"/users/{id}",     // Both /users/42 and /users/87 normalized
		"/users",          // POST and GET with query params
		"/resources/{id}", // UUID normalized
		"/users/me",       // Literal preserved
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
