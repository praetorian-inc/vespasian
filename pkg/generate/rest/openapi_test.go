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
				QueryParams: map[string][]string{
					"limit":  {"10"},
					"offset": {"0"},
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
			assert.Equal(t, tt.expected, result, "capitalizeFirst(%q)", tt.input)
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
			assert.Equal(t, tt.expected, result, "inferQueryParamType(%q)", tt.value)
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

func TestOpenAPIGenerator_SlugObservation(t *testing.T) {
	// Three slug-shaped observations under a common prefix must be grouped
	// into a single parameterized path by Generate(). This locks in the
	// contract that observation-based slug detection (NormalizePathsWithNames)
	// is wired into groupEndpoints; a regression that reverts the wiring to
	// per-endpoint normalization would produce three distinct paths and fail
	// this test.
	gen := &OpenAPIGenerator{MergeSlugs: true}

	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://api.example.com/articles/my-first-post",
				Response: crawl.ObservedResponse{
					StatusCode: 200,
					Body:       []byte(`{"title": "first"}`),
				},
			},
			IsAPI: true,
		},
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://api.example.com/articles/another-post",
				Response: crawl.ObservedResponse{
					StatusCode: 200,
					Body:       []byte(`{"title": "another"}`),
				},
			},
			IsAPI: true,
		},
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "GET",
				URL:    "https://api.example.com/articles/yet-another-post",
				Response: crawl.ObservedResponse{
					StatusCode: 200,
					Body:       []byte(`{"title": "yet another"}`),
				},
			},
			IsAPI: true,
		},
	}

	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData(spec)
	if err != nil {
		t.Fatalf("Generated spec failed validation: %v", err)
	}

	// Exactly one path should exist; observation-based detection collapses
	// the three slug observations onto /articles/{articleSlug}.
	if doc.Paths.Len() != 1 {
		paths := append([]string{}, doc.Paths.InMatchingOrder()...)
		t.Fatalf("expected 1 path in spec, got %d: %v", doc.Paths.Len(), paths)
	}

	expectedPath := "/articles/{articleSlug}"
	pathItem := doc.Paths.Find(expectedPath)
	if pathItem == nil {
		paths := append([]string{}, doc.Paths.InMatchingOrder()...)
		t.Fatalf("expected path %q not found in spec; got: %v", expectedPath, paths)
	}
	if pathItem.Get == nil {
		t.Fatal("GET operation not found on /articles/{articleSlug}")
	}

	// Verify the path parameter is present and correctly named.
	var pathParamNames []string
	for _, paramRef := range pathItem.Get.Parameters {
		if paramRef.Value.In == "path" {
			pathParamNames = append(pathParamNames, paramRef.Value.Name)
		}
	}
	if len(pathParamNames) != 1 || pathParamNames[0] != "articleSlug" {
		t.Errorf("path parameters = %v, want exactly [articleSlug]", pathParamNames)
	}
}

// TestOpenAPIGenerator_DefaultPreservesDistinctSiblings locks in the LAB-4107
// default at the Generate() seam: a zero-value generator (MergeSlugs unset)
// must keep slug-shaped siblings as distinct paths. A wiring bug that ignored
// g.MergeSlugs, or a default flip to merge-on, would collapse them and fail
// here even though the cmd/unit/E2E layers pass. Mirrors
// TestOpenAPIGenerator_SlugObservation with merging off.
func TestOpenAPIGenerator_DefaultPreservesDistinctSiblings(t *testing.T) {
	gen := &OpenAPIGenerator{} // MergeSlugs defaults off

	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:   "GET",
				URL:      "https://api.example.com/articles/my-first-post",
				Response: crawl.ObservedResponse{StatusCode: 200, Body: []byte(`{"title": "first"}`)},
			},
			IsAPI: true,
		},
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:   "GET",
				URL:      "https://api.example.com/articles/another-post",
				Response: crawl.ObservedResponse{StatusCode: 200, Body: []byte(`{"title": "another"}`)},
			},
			IsAPI: true,
		},
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:   "GET",
				URL:      "https://api.example.com/articles/yet-another-post",
				Response: crawl.ObservedResponse{StatusCode: 200, Body: []byte(`{"title": "yet another"}`)},
			},
			IsAPI: true,
		},
	}

	spec, err := gen.Generate(endpoints)
	require.NoError(t, err)

	doc, err := openapi3.NewLoader().LoadFromData(spec)
	require.NoError(t, err)

	// Merge off: all three siblings survive as distinct paths, none collapsed.
	require.Equal(t, 3, doc.Paths.Len(), "distinct siblings must be preserved; got %v", doc.Paths.InMatchingOrder())
	for _, p := range []string{"/articles/my-first-post", "/articles/another-post", "/articles/yet-another-post"} {
		assert.NotNil(t, doc.Paths.Find(p), "expected preserved path %q", p)
	}
	assert.Nil(t, doc.Paths.Find("/articles/{articleSlug}"), "must not collapse into a slug param when merge is off")
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
	require.NotNil(t, doc.Components, "Components should be initialized")
	require.NotNil(t, doc.Components.Schemas, "Schemas should be initialized")

	// Verify request body schema was extracted
	assert.Contains(t, doc.Components.Schemas, "CreateTicketRequest",
		"CreateTicketRequest schema not found in components")

	// Verify response schemas were extracted
	// Note: POST 201 and GET 200 have identical schemas (id, title), so they share the same component
	_, hasCreatedResponse := doc.Components.Schemas["TicketCreatedResponse"]
	_, hasTicketResponse := doc.Components.Schemas["TicketResponse"]
	assert.True(t, hasCreatedResponse || hasTicketResponse,
		"No ticket response schema found in components (expected TicketCreatedResponse or TicketResponse)")

	assert.Contains(t, doc.Components.Schemas, "TicketNotFoundResponse",
		"TicketNotFoundResponse schema not found in components")

	// Verify schemas were replaced with $ref
	postOp := doc.Paths.Find("/api/v2/tickets").Post
	require.NotNil(t, postOp.RequestBody, "POST request body should not be nil")
	assert.NotEmpty(t, postOp.RequestBody.Value.Content["application/json"].Schema.Ref,
		"POST request body schema not replaced with $ref")

	getOp := doc.Paths.Find("/api/v2/tickets/{ticketId}").Get
	resp200 := getOp.Responses.Value("200")
	require.NotNil(t, resp200, "GET 200 response should not be nil")
	assert.NotEmpty(t, resp200.Value.Content["application/json"].Schema.Ref,
		"GET 200 response schema not replaced with $ref")

	resp404 := getOp.Responses.Value("404")
	require.NotNil(t, resp404, "GET 404 response should not be nil")
	assert.NotEmpty(t, resp404.Value.Content["application/json"].Schema.Ref,
		"GET 404 response schema not replaced with $ref")

	// Verify deduplication: POST 201 and GET 200 have identical schemas (id, title).
	// They may or may not share the same $ref depending on the response-vs-request
	// fingerprint maps; at minimum, both $refs must be non-empty (already checked above).
	postResp := postOp.Responses.Value("201")
	require.NotNil(t, postResp, "POST 201 response should not be nil")
	getResp := getOp.Responses.Value("200")
	require.NotNil(t, getResp, "GET 200 response should not be nil")
	t.Logf("POST 201 ref: %s", postResp.Value.Content["application/json"].Schema.Ref)
	t.Logf("GET 200 ref: %s", getResp.Value.Content["application/json"].Schema.Ref)
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

// TestExtractComponents_RequestResponseScopedRefs verifies that when a request
// body and a 200 response body share IDENTICAL property shapes (echo-style
// endpoint), the generated $ref values are DIFFERENT — the request gets a
// name ending in "Request" and the response gets a name ending in "Response".
// Pre-fix, fingerprintToName was shared between request and response extraction,
// causing the response to reuse the request's component name (e.g., the response
// would be tagged "CreateXRequest" instead of "XResponse").
func TestExtractComponents_RequestResponseScopedRefs(t *testing.T) {
	gen := &OpenAPIGenerator{}

	// Echo-style endpoint: request and response have identical property shapes.
	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "POST",
				URL:    "https://api.example.com/echo",
				Headers: map[string]string{
					"Content-Type": "application/json",
				},
				Body: []byte(`{"id": 1, "name": "x"}`),
				Response: crawl.ObservedResponse{
					StatusCode:  200,
					ContentType: "application/json",
					Body:        []byte(`{"id": 1, "name": "x"}`),
				},
			},
			IsAPI: true,
		},
	}

	spec, err := gen.Generate(endpoints)
	require.NoError(t, err, "Generate should succeed")

	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData(spec)
	require.NoError(t, err, "Generated spec should be valid OpenAPI")

	echoPath := doc.Paths.Find("/echo")
	require.NotNil(t, echoPath, "expected /echo path")
	require.NotNil(t, echoPath.Post, "expected POST on /echo")

	// Get the request body $ref.
	reqBody := echoPath.Post.RequestBody
	require.NotNil(t, reqBody, "expected requestBody")
	jsonReqMedia := reqBody.Value.Content["application/json"]
	require.NotNil(t, jsonReqMedia, "expected application/json in requestBody")
	reqRef := jsonReqMedia.Schema.Ref
	assert.NotEmpty(t, reqRef, "expected $ref in requestBody schema")
	assert.True(t, strings.HasSuffix(reqRef, "Request"),
		"requestBody $ref %q should end with 'Request'", reqRef)

	// Get the 200 response $ref.
	resp200 := echoPath.Post.Responses.Value("200")
	require.NotNil(t, resp200, "expected 200 response")
	jsonRespMedia := resp200.Value.Content["application/json"]
	require.NotNil(t, jsonRespMedia, "expected application/json in 200 response")
	respRef := jsonRespMedia.Schema.Ref
	assert.NotEmpty(t, respRef, "expected $ref in 200 response schema")
	assert.True(t, strings.HasSuffix(respRef, "Response"),
		"200 response $ref %q should end with 'Response'", respRef)

	// The two $ref values must be DIFFERENT (pre-fix they were the same).
	assert.NotEqual(t, reqRef, respRef,
		"request and response $refs must differ (echo endpoints share property shapes but not component names)")
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

// TestOpenAPIGenerator_MultipartRepeatedFileFields_E2E verifies that when a
// multipart body contains two parts with the same name="files" both carrying
// filenames, the generated spec contains exactly ONE "files" property with
// format: binary.
//
// Current intentional last-wins behavior: the second part overwrites the first
// in schema.Properties, so only one "files" entry exists. This is documented
// here so future readers understand the design decision and can change it if
// array semantics are desired.
func TestOpenAPIGenerator_MultipartRepeatedFileFields_E2E(t *testing.T) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)

	// Two file parts with the same name "files".
	for _, fname := range []string{"a.jpg", "b.png"} {
		h := make(textproto.MIMEHeader)
		h.Set("Content-Disposition", `form-data; name="files"; filename="`+fname+`"`)
		h.Set("Content-Type", "image/jpeg")
		fw, err := w.CreatePart(h)
		require.NoError(t, err)
		_, _ = fw.Write([]byte("filedata"))
	}
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

	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData(spec)
	require.NoError(t, err, "Generated spec should be valid OpenAPI")

	uploadPath := doc.Paths.Find("/upload")
	require.NotNil(t, uploadPath, "expected /upload path in spec")
	require.NotNil(t, uploadPath.Post, "expected POST operation on /upload")
	require.NotNil(t, uploadPath.Post.RequestBody, "expected requestBody on POST /upload")

	content := uploadPath.Post.RequestBody.Value.Content
	multipartMedia, ok := content["multipart/form-data"]
	require.True(t, ok, "expected multipart/form-data content type in requestBody")

	// Resolve $ref if needed
	schema := multipartMedia.Schema
	if schema.Ref != "" {
		// Look up the component
		refName := strings.TrimPrefix(schema.Ref, "#/components/schemas/")
		schema = doc.Components.Schemas[refName]
	}
	require.NotNil(t, schema, "expected schema for multipart/form-data")
	require.NotNil(t, schema.Value, "expected schema value")
	require.NotNil(t, schema.Value.Properties, "expected schema properties")

	// Exactly ONE "files" property (last-wins: second part overwrites first).
	filesProp, ok := schema.Value.Properties["files"]
	assert.True(t, ok, "expected exactly one 'files' property in schema")
	if ok {
		require.NotNil(t, filesProp.Value)
		assert.Equal(t, "string", filesProp.Value.Type.Slice()[0],
			"'files' property should be type string")
		assert.Equal(t, "binary", filesProp.Value.Format,
			"'files' property should have format: binary")
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

// --- x-vespasian-source extension tests ---

func makeClassified(method, rawURL, source string) classify.ClassifiedRequest {
	return classify.ClassifiedRequest{
		ObservedRequest: crawl.ObservedRequest{
			Method: method,
			URL:    rawURL,
			Source: source,
		},
		IsAPI:      true,
		Confidence: 0.9,
		APIType:    "rest",
	}
}

func TestOpenAPI_XVespasianSource_DynamicWins(t *testing.T) {
	gen := &OpenAPIGenerator{}
	endpoints := []classify.ClassifiedRequest{
		makeClassified("GET", "https://h/api/x", "katana"),
		makeClassified("GET", "https://h/api/x", "static:js"),
	}
	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	var parsed map[string]interface{}
	if err := yaml.Unmarshal(spec, &parsed); err != nil {
		t.Fatalf("yaml parse failed: %v", err)
	}
	paths := parsed["paths"].(map[string]interface{})
	apiX := paths["/api/x"].(map[string]interface{})
	getOp := apiX["get"].(map[string]interface{})
	ext, ok := getOp["x-vespasian-source"]
	if !ok {
		t.Fatal("expected x-vespasian-source extension to be present")
	}
	if ext != "dynamic" {
		t.Errorf("expected x-vespasian-source=dynamic, got %v", ext)
	}
}

func TestOpenAPI_XVespasianSource_JSBundleOnly(t *testing.T) {
	gen := &OpenAPIGenerator{}
	endpoints := []classify.ClassifiedRequest{
		makeClassified("GET", "https://h/api/x", "static:js"),
		makeClassified("GET", "https://h/api/x", "static:js"),
	}
	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	var parsed map[string]interface{}
	if err := yaml.Unmarshal(spec, &parsed); err != nil {
		t.Fatalf("yaml parse failed: %v", err)
	}
	paths := parsed["paths"].(map[string]interface{})
	apiX := paths["/api/x"].(map[string]interface{})
	getOp := apiX["get"].(map[string]interface{})
	ext, ok := getOp["x-vespasian-source"]
	if !ok {
		t.Fatal("expected x-vespasian-source extension to be present")
	}
	if ext != "js-bundle" {
		t.Errorf("expected x-vespasian-source=js-bundle, got %v", ext)
	}
}

func TestOpenAPI_XVespasianSource_JSSourcemap(t *testing.T) {
	gen := &OpenAPIGenerator{}
	endpoints := []classify.ClassifiedRequest{
		makeClassified("GET", "https://h/api/x", "static:js-sourcemap"),
	}
	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	var parsed map[string]interface{}
	if err := yaml.Unmarshal(spec, &parsed); err != nil {
		t.Fatalf("yaml parse failed: %v", err)
	}
	paths := parsed["paths"].(map[string]interface{})
	apiX := paths["/api/x"].(map[string]interface{})
	getOp := apiX["get"].(map[string]interface{})
	ext, ok := getOp["x-vespasian-source"]
	if !ok {
		t.Fatal("expected x-vespasian-source extension to be present")
	}
	if ext != "js-sourcemap" {
		t.Errorf("expected x-vespasian-source=js-sourcemap, got %v", ext)
	}
}

// LAB-4992 / SEC-BE-001: a group whose only source is the concat reconstruction
// tag (static:js-concat) must surface x-vespasian-source "js-bundle-concat" so
// consumers can weight never-probed reconstructions below observed literals.
func TestOpenAPI_XVespasianSource_JSBundleConcat(t *testing.T) {
	gen := &OpenAPIGenerator{}
	endpoints := []classify.ClassifiedRequest{
		makeClassified("GET", "https://h/api/x", "static:js-concat"),
	}
	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	var parsed map[string]interface{}
	if err := yaml.Unmarshal(spec, &parsed); err != nil {
		t.Fatalf("yaml parse failed: %v", err)
	}
	paths := parsed["paths"].(map[string]interface{})
	apiX := paths["/api/x"].(map[string]interface{})
	getOp := apiX["get"].(map[string]interface{})
	ext, ok := getOp["x-vespasian-source"]
	if !ok {
		t.Fatal("expected x-vespasian-source extension to be present")
	}
	if ext != "js-bundle-concat" {
		t.Errorf("expected x-vespasian-source=js-bundle-concat, got %v", ext)
	}
}

// A group mixing the concat tag with the plain js-bundle tag must resolve to
// "dynamic" (the closed allow-list treats any mixed JS-static prefixes as
// dynamic), pinning that concat is a distinct member of the allow-list.
func TestOpenAPI_XVespasianSource_MixedConcatAndBundle(t *testing.T) {
	gen := &OpenAPIGenerator{}
	endpoints := []classify.ClassifiedRequest{
		makeClassified("GET", "https://h/api/x", "static:js-concat"),
		makeClassified("GET", "https://h/api/x", "static:js"),
	}
	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	var parsed map[string]interface{}
	if err := yaml.Unmarshal(spec, &parsed); err != nil {
		t.Fatalf("yaml parse failed: %v", err)
	}
	paths := parsed["paths"].(map[string]interface{})
	apiX := paths["/api/x"].(map[string]interface{})
	getOp := apiX["get"].(map[string]interface{})
	if ext := getOp["x-vespasian-source"]; ext != "dynamic" {
		t.Errorf("expected x-vespasian-source=dynamic for mixed js-concat+js-bundle group, got %v", ext)
	}
}

func TestOpenAPI_XVespasianSource_OmittedForEmptySource(t *testing.T) {
	gen := &OpenAPIGenerator{}
	// No static: source anywhere in the input.
	endpoints := []classify.ClassifiedRequest{
		makeClassified("GET", "https://h/api/x", ""),
	}
	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	var parsed map[string]interface{}
	if err := yaml.Unmarshal(spec, &parsed); err != nil {
		t.Fatalf("yaml parse failed: %v", err)
	}
	paths := parsed["paths"].(map[string]interface{})
	apiX := paths["/api/x"].(map[string]interface{})
	getOp := apiX["get"].(map[string]interface{})
	if _, ok := getOp["x-vespasian-source"]; ok {
		t.Error("expected x-vespasian-source to be absent when source is empty")
	}
}

// Regression for QUAL-005: a group that mixes untagged (Source=="") dynamic
// entries with static:js entries must resolve to "dynamic", not "js-bundle".
// The presence of at least one static:* in the overall input still triggers
// the extension via anyStaticSource(); within the group, an empty Source is a
// dynamic signal and must not be skipped.
func TestComputeSourceTag_MixedEmptyAndStaticInGroup_ResolvesDynamic(t *testing.T) {
	gen := &OpenAPIGenerator{}
	endpoints := []classify.ClassifiedRequest{
		// Untagged dynamic entry for /api/x (pre-LAB-2108 capture style).
		makeClassified("GET", "https://h/api/x", ""),
		// Static entry for the same endpoint key.
		makeClassified("GET", "https://h/api/x", "static:js"),
		// Unrelated static entry so anyStaticSource gates the extension on.
		makeClassified("GET", "https://h/api/y", "static:js"),
	}
	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	var parsed map[string]interface{}
	if err := yaml.Unmarshal(spec, &parsed); err != nil {
		t.Fatalf("yaml parse failed: %v", err)
	}
	paths := parsed["paths"].(map[string]interface{})
	apiX := paths["/api/x"].(map[string]interface{})
	getOp := apiX["get"].(map[string]interface{})
	ext, ok := getOp["x-vespasian-source"]
	if !ok {
		t.Fatal("expected x-vespasian-source extension to be present for mixed group")
	}
	if ext != "dynamic" {
		t.Errorf("expected x-vespasian-source=dynamic when group mixes empty Source and static:js, got %v", ext)
	}
}

// Regression for CR-2: a non-JS "static:*" source (e.g. static:html from
// pkg/analyze form analysis) must NOT gate or surface in the x-vespasian-source
// extension. The extension is scoped to JS bundle / sourcemap recovery only.
func TestOpenAPI_XVespasianSource_StaticHtmlIgnored(t *testing.T) {
	gen := &OpenAPIGenerator{}
	endpoints := []classify.ClassifiedRequest{
		makeClassified("GET", "https://h/api/x", "static:html"),
		makeClassified("POST", "https://h/api/y", "static:html"),
	}
	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	var parsed map[string]interface{}
	if err := yaml.Unmarshal(spec, &parsed); err != nil {
		t.Fatalf("yaml parse failed: %v", err)
	}
	paths := parsed["paths"].(map[string]interface{})
	// Walk every operation; the extension must be absent everywhere when only
	// non-JS static sources are present in the input.
	for _, pathVal := range paths {
		pathItem := pathVal.(map[string]interface{})
		for _, opVal := range pathItem {
			op, ok := opVal.(map[string]interface{})
			if !ok {
				continue
			}
			if _, has := op["x-vespasian-source"]; has {
				t.Errorf("x-vespasian-source must be absent when only static:html (non-JS) is present; op: %v", op)
			}
		}
	}
}

// Regression for CR-2: a group containing ONLY static:html, in a corpus where
// another group has static:js (so anyStaticSource gates the extension on),
// must resolve to "dynamic" — not "html". Pre-fix this test would have failed:
// computeSourceTag's strings.TrimPrefix default would have emitted
// x-vespasian-source: "html" for the /api/x group. Post-fix the JS-only
// allow-list early-returns "dynamic" for any non-JS static source. This is
// the only single-group composition that distinguishes pre-fix from post-fix
// behavior; the StaticHtmlIgnored test above covers the corpus-gate case.
func TestComputeSourceTag_StaticHtmlOnlyGroupInJSCorpus_ResolvesDynamic(t *testing.T) {
	gen := &OpenAPIGenerator{}
	endpoints := []classify.ClassifiedRequest{
		// /api/x has ONLY static:html — pre-fix would emit "html" here.
		makeClassified("GET", "https://h/api/x", "static:html"),
		makeClassified("GET", "https://h/api/x", "static:html"),
		// Unrelated static:js entry forces anyStaticSource to fire (true under
		// both pre-fix HasPrefix("static:") AND post-fix crawl.IsJSStaticSource).
		makeClassified("GET", "https://h/api/z", "static:js"),
	}
	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	var parsed map[string]interface{}
	if err := yaml.Unmarshal(spec, &parsed); err != nil {
		t.Fatalf("yaml parse failed: %v", err)
	}
	paths := parsed["paths"].(map[string]interface{})
	apiX := paths["/api/x"].(map[string]interface{})
	getOp := apiX["get"].(map[string]interface{})
	ext, ok := getOp["x-vespasian-source"]
	if !ok {
		t.Fatal("expected x-vespasian-source extension to be present (anyStaticSource fires from /api/z)")
	}
	if ext != "dynamic" {
		t.Errorf("expected x-vespasian-source=dynamic for static:html-only group, got %v (a 'html' or other non-allowed value means the allow-list regressed)", ext)
	}
}

// mixed static-only groups (static:js + static:js-sourcemap) must resolve to "dynamic".
func TestComputeSourceTag_MixedStaticGroups(t *testing.T) {
	gen := &OpenAPIGenerator{}
	// Two entries for the same endpoint: one from js bundle, one from sourcemap.
	endpoints := []classify.ClassifiedRequest{
		makeClassified("GET", "https://h/api/x", "static:js"),
		makeClassified("GET", "https://h/api/x", "static:js-sourcemap"),
	}
	spec, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	var parsed map[string]interface{}
	if err := yaml.Unmarshal(spec, &parsed); err != nil {
		t.Fatalf("yaml parse failed: %v", err)
	}
	paths := parsed["paths"].(map[string]interface{})
	apiX := paths["/api/x"].(map[string]interface{})
	getOp := apiX["get"].(map[string]interface{})
	ext, ok := getOp["x-vespasian-source"]
	if !ok {
		t.Fatal("expected x-vespasian-source extension to be present")
	}
	if ext != "dynamic" {
		t.Errorf("expected x-vespasian-source=dynamic for mixed static group, got %v", ext)
	}
}

func TestOpenAPI_XVespasianSource_NoStaticPresent_ByteCompat(t *testing.T) {
	// When no static: sources exist anywhere in input, generate twice with
	// identical inputs and assert output is identical (byte compat).
	gen := &OpenAPIGenerator{}
	endpoints := []classify.ClassifiedRequest{
		makeClassified("GET", "https://h/api/x", "katana"),
		makeClassified("POST", "https://h/api/y", "browser"),
	}

	spec1, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate (run 1) failed: %v", err)
	}
	spec2, err := gen.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate (run 2) failed: %v", err)
	}
	if string(spec1) != string(spec2) {
		t.Error("Generate output is not deterministic / byte-compatible across runs")
	}

	// Also verify extension is absent on every operation.
	var parsed map[string]interface{}
	if err := yaml.Unmarshal(spec1, &parsed); err != nil {
		t.Fatalf("yaml parse failed: %v", err)
	}
	paths := parsed["paths"].(map[string]interface{})
	for _, pathVal := range paths {
		pathItem := pathVal.(map[string]interface{})
		for _, opVal := range pathItem {
			if op, ok := opVal.(map[string]interface{}); ok {
				if _, hasExt := op["x-vespasian-source"]; hasExt {
					t.Error("expected x-vespasian-source to be absent when no static sources in input")
				}
			}
		}
	}
}

// TestBuildOperation_EmptyValuesQueryParam is a regression test for D2: a query
// parameter with an empty observed-values slice must be silently omitted from
// the generated Operation. Prior to the D2 fix, buildOperation would panic
// with an index-out-of-range accessing info.values[0] on the scalar branch.
func TestBuildOperation_EmptyValuesQueryParam(t *testing.T) {
	// "foo" has an empty values slice — simulates a hand-crafted capture where
	// the param key is present but no values were ever recorded.
	// "bar" is a normal scalar param that should still appear.
	group := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:      "GET",
				URL:         "https://api.example.com/items?bar=1",
				QueryParams: map[string][]string{"foo": {}, "bar": {"1"}},
				Response:    crawl.ObservedResponse{StatusCode: 200},
			},
			IsAPI: true,
		},
	}
	key := endpointKey{path: "/items", method: "get"}

	// Must not panic.
	op := buildOperation(key, group, false)

	// "foo" must be absent — no observed values means we cannot document it.
	for _, paramRef := range op.Parameters {
		if paramRef.Value != nil && paramRef.Value.Name == "foo" {
			t.Errorf("parameter 'foo' with empty values should be omitted, but was emitted")
		}
	}

	// "bar" must still be present.
	found := false
	for _, paramRef := range op.Parameters {
		if paramRef.Value != nil && paramRef.Value.Name == "bar" {
			found = true
		}
	}
	if !found {
		t.Error("parameter 'bar' with a valid value should be emitted")
	}
}

// TestBuildOperation_ScalarQueryParam is a regression test: a scalar query param
// should produce a non-array parameter with no Style or Explode set.
func TestBuildOperation_ScalarQueryParam(t *testing.T) {
	group := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:      "GET",
				URL:         "https://api.example.com/items?page=1",
				QueryParams: map[string][]string{"page": {"1"}},
				Response:    crawl.ObservedResponse{StatusCode: 200},
			},
			IsAPI: true,
		},
	}
	key := endpointKey{path: "/items", method: "get"}
	op := buildOperation(key, group, false)

	require.Len(t, op.Parameters, 1)
	param := op.Parameters[0].Value
	require.NotNil(t, param)
	require.NotNil(t, param.Schema)
	require.NotNil(t, param.Schema.Value)
	require.NotNil(t, param.Schema.Value.Type)

	assert.Equal(t, "integer", param.Schema.Value.Type.Slice()[0], "type should be integer for scalar")
	assert.Equal(t, "", param.Style, "scalar param should have no style")
	assert.Nil(t, param.Explode, "scalar param should have nil Explode")
	assert.Nil(t, param.Schema.Value.Items, "scalar param should have no items")
}

// TestBuildOperation_MultiValueQueryParam_AllInts tests that an array param with
// all-integer values produces type:array with items type:integer and style/explode set.
func TestBuildOperation_MultiValueQueryParam_AllInts(t *testing.T) {
	group := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:      "GET",
				URL:         "https://api.example.com/items?ids=1&ids=2&ids=3",
				QueryParams: map[string][]string{"ids": {"1", "2", "3"}},
				Response:    crawl.ObservedResponse{StatusCode: 200},
			},
			IsAPI: true,
		},
	}
	key := endpointKey{path: "/items", method: "get"}
	op := buildOperation(key, group, false)

	require.Len(t, op.Parameters, 1)
	param := op.Parameters[0].Value
	require.NotNil(t, param)
	require.NotNil(t, param.Schema)
	require.NotNil(t, param.Schema.Value)
	require.NotNil(t, param.Schema.Value.Type)

	assert.Equal(t, "array", param.Schema.Value.Type.Slice()[0], "type should be array")
	require.NotNil(t, param.Schema.Value.Items, "items must be set for array param")
	require.NotNil(t, param.Schema.Value.Items.Value)
	require.NotNil(t, param.Schema.Value.Items.Value.Type)
	assert.Equal(t, "integer", param.Schema.Value.Items.Value.Type.Slice()[0], "items type should be integer")
	assert.Equal(t, "form", param.Style, "style should be form")
	require.NotNil(t, param.Explode)
	assert.True(t, *param.Explode, "explode should be true")
}

// TestBuildOperation_MultiValueQueryParam_Mixed tests that a mixed-type array
// falls back to items type:string.
func TestBuildOperation_MultiValueQueryParam_Mixed(t *testing.T) {
	group := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:      "GET",
				URL:         "https://api.example.com/items?tag=a&tag=1",
				QueryParams: map[string][]string{"tag": {"a", "1"}},
				Response:    crawl.ObservedResponse{StatusCode: 200},
			},
			IsAPI: true,
		},
	}
	key := endpointKey{path: "/items", method: "get"}
	op := buildOperation(key, group, false)

	require.Len(t, op.Parameters, 1)
	param := op.Parameters[0].Value
	require.NotNil(t, param.Schema.Value.Items)
	assert.Equal(t, "string", param.Schema.Value.Items.Value.Type.Slice()[0], "mixed values should produce items type:string")
}

// TestBuildOperation_MultiValueQueryParam_AllBool tests all-boolean array values.
func TestBuildOperation_MultiValueQueryParam_AllBool(t *testing.T) {
	group := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:      "GET",
				URL:         "https://api.example.com/flags?flag=true&flag=false",
				QueryParams: map[string][]string{"flag": {"true", "false"}},
				Response:    crawl.ObservedResponse{StatusCode: 200},
			},
			IsAPI: true,
		},
	}
	key := endpointKey{path: "/flags", method: "get"}
	op := buildOperation(key, group, false)

	require.Len(t, op.Parameters, 1)
	param := op.Parameters[0].Value
	require.NotNil(t, param.Schema.Value.Items)
	assert.Equal(t, "boolean", param.Schema.Value.Items.Value.Type.Slice()[0], "all-bool values should produce items type:boolean")
}

// TestInferQueryParamItemsType tests the items type inference function directly.
func TestInferQueryParamItemsType(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		want   string
	}{
		{name: "empty slice", values: []string{}, want: "string"},
		{name: "all integers", values: []string{"1", "2", "3"}, want: "integer"},
		{name: "all floats", values: []string{"1.5", "2.5"}, want: "number"},
		{name: "all booleans", values: []string{"true", "false"}, want: "boolean"},
		{name: "mixed string and int", values: []string{"a", "1"}, want: "string"},
		{name: "single string", values: []string{"hello"}, want: "string"},
		{name: "integer is also float, int wins", values: []string{"1", "2"}, want: "integer"},
		{name: "single negative integer", values: []string{"-1"}, want: "integer"},
		{name: "single zero", values: []string{"0"}, want: "integer"},
		{name: "single negative float", values: []string{"-0.5"}, want: "number"},
		{name: "single scientific notation", values: []string{"1e10"}, want: "number"},
		{name: "single empty string", values: []string{""}, want: "string"},
		{name: "single mixed alphanumeric", values: []string{"abc123"}, want: "string"},
		{name: "single uppercase boolean-like", values: []string{"True"}, want: "string"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := inferQueryParamItemsType(tt.values)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestBuildOperation_ScalarQueryParam_OrderIndependence(t *testing.T) {
	// Two observations of the same scalar param: int first, then float.
	// Pre-fix: scalar branch took values[0] = "1" → emitted integer.
	// Post-fix: inferQueryParamItemsType walks all values → emits number.
	group := []classify.ClassifiedRequest{
		{ObservedRequest: crawl.ObservedRequest{
			Method: "GET", URL: "https://x.test/items?limit=1",
			QueryParams: map[string][]string{"limit": {"1"}},
		}},
		{ObservedRequest: crawl.ObservedRequest{
			Method: "GET", URL: "https://x.test/items?limit=1.5",
			QueryParams: map[string][]string{"limit": {"1.5"}},
		}},
	}
	op := buildOperation(endpointKey{path: "/items", method: "get"}, group, false)
	require.NotNil(t, op)
	require.Len(t, op.Parameters, 1)
	p := op.Parameters[0].Value
	require.NotNil(t, p)
	require.NotNil(t, p.Schema)
	require.NotNil(t, p.Schema.Value)
	require.NotNil(t, p.Schema.Value.Type)
	assert.Equal(t, []string{"number"}, p.Schema.Value.Type.Slice(),
		"scalar param type must be inferred from ALL observed values, not just the first")
	// Confirm scalar emission (not array): no Style/Explode set
	assert.Empty(t, p.Style, "scalar param should not set Style")
	assert.Nil(t, p.Explode, "scalar param should not set Explode")
}

func TestBuildOperation_PostDedupScalarNotOverWidened(t *testing.T) {
	// Regression: when classify.Deduplicate merges two scalar observations
	// of the same endpoint into one ClassifiedRequest, buildOperation must
	// still emit the param as scalar (not array). The pre-fix bug was that
	// the merged QueryParams slice had len > 1, tripping multiValueSeen.
	// The fix uses MultiValueQueryKeys (populated by RunClassifiers BEFORE
	// dedup) to record per-observation truth.
	//
	// Simulate post-dedup state: one ClassifiedRequest with merged values
	// AND an empty MultiValueQueryKeys map (no key was multi-value in any
	// contributing observation).
	group := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:      "GET",
				URL:         "https://x.test/items?page=1",
				QueryParams: map[string][]string{"page": {"1", "2"}},
			},
			MultiValueQueryKeys: map[string]bool{}, // empty: page was scalar in both contributing obs
		},
	}
	op := buildOperation(endpointKey{path: "/items", method: "get"}, group, false)
	require.NotNil(t, op)
	require.Len(t, op.Parameters, 1)
	p := op.Parameters[0].Value
	require.NotNil(t, p.Schema)
	require.NotNil(t, p.Schema.Value)
	require.NotNil(t, p.Schema.Value.Type)
	assert.Equal(t, []string{"integer"}, p.Schema.Value.Type.Slice(),
		"scalar param surviving dedup union must NOT be over-widened to array")
	assert.Empty(t, p.Style, "scalar must not set Style")
	assert.Nil(t, p.Explode, "scalar must not set Explode")
	assert.Nil(t, p.Schema.Value.Items, "scalar must not have Items")
}

func TestBuildOperation_PostDedupArrayStillDetected(t *testing.T) {
	// Companion regression: when a key WAS multi-value in a contributing
	// observation, MultiValueQueryKeys carries that truth through dedup,
	// and buildOperation must emit the param as array.
	group := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:      "GET",
				URL:         "https://x.test/items?tag=a&tag=b",
				QueryParams: map[string][]string{"tag": {"a", "b"}},
			},
			MultiValueQueryKeys: map[string]bool{"tag": true},
		},
	}
	op := buildOperation(endpointKey{path: "/items", method: "get"}, group, false)
	require.NotNil(t, op)
	require.Len(t, op.Parameters, 1)
	p := op.Parameters[0].Value
	require.NotNil(t, p.Schema)
	require.NotNil(t, p.Schema.Value)
	require.NotNil(t, p.Schema.Value.Type)
	assert.Equal(t, []string{"array"}, p.Schema.Value.Type.Slice(),
		"key with MultiValueQueryKeys=true must emit as array")
	assert.Equal(t, "form", p.Style)
	require.NotNil(t, p.Explode)
	assert.True(t, *p.Explode)
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

// TestMergeJSONBodies_SkipBranches verifies that mergeJSONBodies correctly skips
// nil/empty bodies and bodies that fail JSON inference, while still merging valid ones.
func TestMergeJSONBodies_SkipBranches(t *testing.T) {
	t.Run("skips empty body", func(t *testing.T) {
		bodies := [][]byte{nil, []byte(`{"a":1}`)}
		merged := mergeJSONBodies(bodies)
		require.NotNil(t, merged, "expected non-nil result when one body is valid")
		require.NotNil(t, merged.Value)
		require.NotNil(t, merged.Value.Properties)
		assert.Contains(t, merged.Value.Properties, "a", "valid body's property 'a' should be present")
	})

	t.Run("skips body that fails inference", func(t *testing.T) {
		bodies := [][]byte{[]byte("not valid json"), []byte(`{"a":1}`)}
		merged := mergeJSONBodies(bodies)
		require.NotNil(t, merged, "expected non-nil result when one body is valid")
		require.NotNil(t, merged.Value)
		require.NotNil(t, merged.Value.Properties)
		assert.Contains(t, merged.Value.Properties, "a", "valid body's property 'a' should be present")
		assert.Len(t, merged.Value.Properties, 1, "only the valid body should contribute properties")
	})
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
