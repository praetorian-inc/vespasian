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
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

var (
	// uuidRegex matches UUIDs in paths (8-4-4-4-12 format)
	uuidRegex = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	// numericRegex matches purely numeric segments
	numericRegex = regexp.MustCompile(`^[0-9]+$`)
)

// NormalizePath normalizes a URL path for OpenAPI specification.
// It replaces UUIDs and numeric segments with {id} placeholders.
// Kept for backward compatibility.
func NormalizePath(path string) string {
	// Split path into segments
	segments := strings.Split(path, "/")

	for i, segment := range segments {
		// Skip empty segments
		if segment == "" {
			continue
		}

		// Replace UUIDs with {id}
		if uuidRegex.MatchString(segment) {
			segments[i] = "{id}"
			continue
		}

		// Replace numeric IDs with {id}
		if numericRegex.MatchString(segment) {
			segments[i] = "{id}"
		}
	}

	return strings.Join(segments, "/")
}

// NormalizePathWithNames normalizes a URL path with context-aware parameter names.
// It replaces UUIDs and numeric segments with named placeholders based on preceding path segments.
// Examples:
//   - /users/42 -> /users/{userId}
//   - /posts/5/comments/7 -> /posts/{postId}/comments/{commentId}
//   - /categories/123 -> /categories/{categoryId}
func NormalizePathWithNames(path string) string {
	segments := strings.Split(path, "/")

	for i, segment := range segments {
		// Skip empty segments
		if segment == "" {
			continue
		}

		// Check if this segment is an ID (UUID or numeric)
		isID := uuidRegex.MatchString(segment) || numericRegex.MatchString(segment)
		if !isID {
			continue
		}

		// Find parameter name from context (previous non-empty, non-parameterized segment)
		paramName := "id" // default fallback
		for j := i - 1; j >= 0; j-- {
			if segments[j] != "" && !strings.HasPrefix(segments[j], "{") {
				paramName = paramNameFromContext(segments[j])
				break
			}
		}

		segments[i] = "{" + paramName + "}"
	}

	// Deduplicate parameter names: {id}, {id2}, {id3}, etc.
	seen := make(map[string]int)
	for i, segment := range segments {
		if strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}") {
			name := segment[1 : len(segment)-1]
			seen[name]++
			if seen[name] > 1 {
				segments[i] = "{" + name + strconv.Itoa(seen[name]) + "}"
			}
		}
	}

	return strings.Join(segments, "/")
}

// sanitizeParamName removes characters that are not safe for OpenAPI parameter names.
// Allows alphanumeric characters, underscores, hyphens, and dots.
func sanitizeParamName(name string) string {
	var b strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' {
			b.WriteRune(r)
		}
	}
	result := b.String()
	if result == "" {
		return "id"
	}
	return result
}

// paramNameFromContext derives a parameter name from a path segment.
// Examples:
//   - "users" -> "userId"
//   - "categories" -> "categoryId"
//   - "addresses" -> "addressId"
//   - "data" -> "dataId" (no trailing 's')
func paramNameFromContext(segment string) string {
	singular := singularize(segment)
	raw := singular + "Id"
	sanitized := sanitizeParamName(raw)
	if sanitized != raw {
		fmt.Fprintf(os.Stderr, "warning: path segment %q produced unsafe parameter name %q, sanitized to %q\n", segment, raw, sanitized)
	}
	return sanitized
}

// singularize converts a plural word to singular (naive implementation).
// Rules:
//   - "ies" -> "y" (categories -> category)
//   - "sses" -> "ss" (addresses -> address)
//   - "s" -> "" (users -> user)
//   - otherwise -> return as-is (data -> data)
func singularize(word string) string {
	if strings.HasSuffix(word, "ies") {
		return strings.TrimSuffix(word, "ies") + "y"
	}
	if strings.HasSuffix(word, "sses") {
		return strings.TrimSuffix(word, "sses") + "ss"
	}
	if strings.HasSuffix(word, "s") && !strings.HasSuffix(word, "ss") {
		return strings.TrimSuffix(word, "s")
	}
	return word
}
