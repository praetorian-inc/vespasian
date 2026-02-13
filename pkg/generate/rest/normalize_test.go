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

func TestNormalizePath_UUID(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "uuid in path",
			input:    "/users/550e8400-e29b-41d4-a716-446655440000",
			expected: "/users/{id}",
		},
		{
			name:     "multiple uuids",
			input:    "/users/550e8400-e29b-41d4-a716-446655440000/posts/650e8400-e29b-41d4-a716-446655440000",
			expected: "/users/{id}/posts/{id}",
		},
		{
			name:     "no uuid",
			input:    "/users/list",
			expected: "/users/list",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizePath(tt.input)
			if result != tt.expected {
				t.Errorf("NormalizePath(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestNormalizePath_NumericID(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "numeric id",
			input:    "/users/42",
			expected: "/users/{id}",
		},
		{
			name:     "multiple numeric ids",
			input:    "/users/42/posts/5",
			expected: "/users/{id}/posts/{id}",
		},
		{
			name:     "mixed with text",
			input:    "/users/42/profile",
			expected: "/users/{id}/profile",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizePath(tt.input)
			if result != tt.expected {
				t.Errorf("NormalizePath(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestNormalizePath_LiteralPreservation(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "preserve /me",
			input:    "/users/me",
			expected: "/users/me",
		},
		{
			name:     "preserve /current",
			input:    "/users/current",
			expected: "/users/current",
		},
		{
			name:     "preserve /self",
			input:    "/users/self",
			expected: "/users/self",
		},
		{
			name:     "preserve /list",
			input:    "/users/list",
			expected: "/users/list",
		},
		{
			name:     "preserve /search",
			input:    "/api/search",
			expected: "/api/search",
		},
		{
			name:     "preserve /new",
			input:    "/posts/new",
			expected: "/posts/new",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizePath(tt.input)
			if result != tt.expected {
				t.Errorf("NormalizePath(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestNormalizePathWithNames_ContextAwareNaming(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "single user ID",
			input:    "/users/42",
			expected: "/users/{userId}",
		},
		{
			name:     "nested IDs - posts and comments",
			input:    "/posts/5/comments/7",
			expected: "/posts/{postId}/comments/{commentId}",
		},
		{
			name:     "uuid user ID",
			input:    "/users/550e8400-e29b-41d4-a716-446655440000",
			expected: "/users/{userId}",
		},
		{
			name:     "nested uuid IDs",
			input:    "/users/550e8400-e29b-41d4-a716-446655440000/posts/650e8400-e29b-41d4-a716-446655440000",
			expected: "/users/{userId}/posts/{postId}",
		},
		{
			name:     "categories with ies ending",
			input:    "/categories/123",
			expected: "/categories/{categoryId}",
		},
		{
			name:     "addresses with sses ending",
			input:    "/addresses/456",
			expected: "/addresses/{addressId}",
		},
		{
			name:     "literal path preserved",
			input:    "/users/me",
			expected: "/users/me",
		},
		{
			name:     "mixed literal and ID",
			input:    "/users/42/profile",
			expected: "/users/{userId}/profile",
		},
		{
			name:     "no ID segments",
			input:    "/api/search",
			expected: "/api/search",
		},
		{
			name:     "data without trailing s",
			input:    "/data/789",
			expected: "/data/{dataId}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizePathWithNames(tt.input)
			if result != tt.expected {
				t.Errorf("NormalizePathWithNames(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestSingularize(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "users to user",
			input:    "users",
			expected: "user",
		},
		{
			name:     "categories to category",
			input:    "categories",
			expected: "category",
		},
		{
			name:     "addresses to address",
			input:    "addresses",
			expected: "address",
		},
		{
			name:     "posts to post",
			input:    "posts",
			expected: "post",
		},
		{
			name:     "data unchanged",
			input:    "data",
			expected: "data",
		},
		{
			name:     "class unchanged",
			input:    "class",
			expected: "class",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := singularize(tt.input)
			if result != tt.expected {
				t.Errorf("singularize(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestNormalizePathWithNames_ConsecutiveIDs(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "consecutive numeric IDs with no context",
			input:    "/12345/66777",
			expected: "/{id}/{id2}",
		},
		{
			name:     "consecutive IDs with one resource prefix",
			input:    "/api/12345/66777",
			expected: "/api/{apiId}/{apiId2}",
		},
		{
			name:     "mixed context with consecutive IDs",
			input:    "/users/42/posts/5/99",
			expected: "/users/{userId}/posts/{postId}/{postId2}",
		},
		{
			name:     "uuid then numeric with no context",
			input:    "/550e8400-e29b-41d4-a716-446655440000/12345",
			expected: "/{id}/{id2}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizePathWithNames(tt.input)
			if result != tt.expected {
				t.Errorf("NormalizePathWithNames(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}
