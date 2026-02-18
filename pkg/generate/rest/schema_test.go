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
	"testing"
)

func TestInferSchema_BasicTypes(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		expectedType string
	}{
		{
			name:         "string type",
			input:        `"hello"`,
			expectedType: "string",
		},
		{
			name:         "integer type",
			input:        `42`,
			expectedType: "integer",
		},
		{
			name:         "number type",
			input:        `3.14`,
			expectedType: "number",
		},
		{
			name:         "boolean true",
			input:        `true`,
			expectedType: "boolean",
		},
		{
			name:         "boolean false",
			input:        `false`,
			expectedType: "boolean",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := InferSchema([]byte(tt.input))
			if result == nil {
				t.Fatalf("InferSchema returned nil for %q", tt.input)
			}
			if result.Value == nil {
				t.Fatalf("InferSchema returned SchemaRef with nil Value for %q", tt.input)
			}
			if len(result.Value.Type.Slice()) == 0 {
				t.Fatalf("InferSchema returned empty Type slice for %q", tt.input)
			}
			if result.Value.Type.Slice()[0] != tt.expectedType {
				t.Errorf("InferSchema(%q).Type = %q, want %q", tt.input, result.Value.Type.Slice()[0], tt.expectedType)
			}
		})
	}
}

func TestInferSchema_Array(t *testing.T) {
	tests := []struct {
		name             string
		input            string
		expectedItemType string
	}{
		{
			name:             "array of strings",
			input:            `["hello", "world"]`,
			expectedItemType: "string",
		},
		{
			name:             "array of integers",
			input:            `[1, 2, 3]`,
			expectedItemType: "integer",
		},
		{
			name:             "empty array",
			input:            `[]`,
			expectedItemType: "", // empty array has no item type
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := InferSchema([]byte(tt.input))
			if result == nil {
				t.Fatalf("InferSchema returned nil for %q", tt.input)
			}
			if result.Value.Type.Slice()[0] != "array" {
				t.Errorf("InferSchema(%q).Type = %q, want %q", tt.input, result.Value.Type.Slice()[0], "array")
			}
			if tt.expectedItemType != "" {
				if result.Value.Items == nil || result.Value.Items.Value == nil {
					t.Fatalf("InferSchema(%q) returned nil Items", tt.input)
				}
				if result.Value.Items.Value.Type.Slice()[0] != tt.expectedItemType {
					t.Errorf("InferSchema(%q).Items.Type = %q, want %q", tt.input, result.Value.Items.Value.Type.Slice()[0], tt.expectedItemType)
				}
			}
		})
	}
}

func TestInferSchema_Object(t *testing.T) {
	input := `{"name": "John", "age": 30, "active": true}`
	result := InferSchema([]byte(input))

	if result == nil {
		t.Fatalf("InferSchema returned nil")
	}
	if result.Value.Type.Slice()[0] != "object" {
		t.Errorf("Type = %q, want %q", result.Value.Type.Slice()[0], "object")
	}
	if result.Value.Properties == nil {
		t.Fatalf("Properties is nil")
	}
	if len(result.Value.Properties) != 3 {
		t.Errorf("Properties length = %d, want 3", len(result.Value.Properties))
	}

	// Check name property
	if nameSchema := result.Value.Properties["name"]; nameSchema == nil || nameSchema.Value.Type.Slice()[0] != "string" {
		t.Errorf("name property type incorrect")
	}

	// Check age property
	if ageSchema := result.Value.Properties["age"]; ageSchema == nil || ageSchema.Value.Type.Slice()[0] != "integer" {
		t.Errorf("age property type incorrect")
	}

	// Check active property
	if activeSchema := result.Value.Properties["active"]; activeSchema == nil || activeSchema.Value.Type.Slice()[0] != "boolean" {
		t.Errorf("active property type incorrect")
	}
}

func TestInferSchema_NestedObject(t *testing.T) {
	input := `{"user": {"name": "John", "age": 30}}`
	result := InferSchema([]byte(input))

	if result == nil {
		t.Fatalf("InferSchema returned nil")
	}
	if result.Value.Type.Slice()[0] != "object" {
		t.Errorf("Type = %q, want %q", result.Value.Type.Slice()[0], "object")
	}

	userSchema := result.Value.Properties["user"]
	if userSchema == nil || userSchema.Value == nil {
		t.Fatalf("user property is nil")
	}
	if userSchema.Value.Type.Slice()[0] != "object" {
		t.Errorf("user property type = %q, want %q", userSchema.Value.Type.Slice()[0], "object")
	}
	if len(userSchema.Value.Properties) != 2 {
		t.Errorf("user properties length = %d, want 2", len(userSchema.Value.Properties))
	}
}

func TestInferSchema_NullValue(t *testing.T) {
	input := `{"field": null}`
	result := InferSchema([]byte(input))

	if result == nil {
		t.Fatalf("InferSchema returned nil")
	}
	if result.Value.Type.Slice()[0] != "object" {
		t.Errorf("Type = %q, want %q", result.Value.Type.Slice()[0], "object")
	}

	fieldSchema := result.Value.Properties["field"]
	if fieldSchema == nil || fieldSchema.Value == nil {
		t.Fatalf("field property is nil")
	}

	// OpenAPI 3.0 doesn't support type: "null"
	// Instead, nullable: true should be set
	if fieldSchema.Value.Nullable != true {
		t.Errorf("field property Nullable = %v, want true", fieldSchema.Value.Nullable)
	}

	// Type should be absent or empty, not "null"
	if fieldSchema.Value.Type != nil && len(fieldSchema.Value.Type.Slice()) > 0 {
		typeStr := fieldSchema.Value.Type.Slice()[0]
		if typeStr == "null" {
			t.Errorf("field property Type = %q, OpenAPI 3.0 doesn't support type 'null', should use Nullable: true instead", typeStr)
		}
	}
}

// TestInferSchema_DeeplyNestedObject tests recursion depth limit (Issue 1)
func TestInferSchema_DeeplyNestedObject(t *testing.T) {
	// Create a deeply nested JSON structure (depth of 25)
	json := `{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":{"i":{"j":{"k":{"l":{"m":{"n":{"o":{"p":{"q":{"r":{"s":{"t":{"u":{"v":{"w":{"x":{"y":"value"}}}}}}}}}}}}}}}}}}}}}}}}}`

	result := InferSchema([]byte(json))
	if result == nil {
		t.Fatal("InferSchema returned nil for deeply nested JSON")
	}

	// Should not cause stack overflow and should return a schema
	// At max depth (20), it should return a generic object schema without further recursion
	if result.Value.Type.Slice()[0] != "object" {
		t.Errorf("Type = %q, want %q", result.Value.Type.Slice()[0], "object")
	}
}

// TestInferSchema_LargeBodySize tests input size guard (Issue 2)
func TestInferSchema_LargeBodySize(t *testing.T) {
	// Create a body larger than 10MB limit
	largeJSON := make([]byte, 11*1024*1024) // 11MB
	for i := range largeJSON {
		largeJSON[i] = 'a'
	}

	result := InferSchema(largeJSON)
	if result != nil {
		t.Error("InferSchema should return nil for bodies exceeding 10MB limit")
	}
}

// TestInferSchema_EdgeCaseIntegers tests integer detection edge case (Issue 3)
func TestInferSchema_EdgeCaseIntegers(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		expectedType string
		description  string
	}{
		{
			name:         "max int64",
			input:        `9223372036854775807`,
			expectedType: "integer",
			description:  "max int64 value should be detected as integer",
		},
		{
			name:         "min int64",
			input:        `-9223372036854775808`,
			expectedType: "integer",
			description:  "min int64 value should be detected as integer",
		},
		{
			name:         "beyond int64 range",
			input:        `100000000000000000000`, // 1e20, clearly beyond int64 range
			expectedType: "number",
			description:  "values beyond int64 range fall back to number",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := InferSchema([]byte(tt.input))
			if result == nil {
				t.Fatalf("InferSchema returned nil for %q", tt.input)
			}
			if result.Value.Type.Slice()[0] != tt.expectedType {
				t.Errorf("InferSchema(%q).Type = %q, want %q (%s)", tt.input, result.Value.Type.Slice()[0], tt.expectedType, tt.description)
			}
		})
	}
}
