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
	"sort"
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

func TestNormalizePath_DynamicSegmentExpansion(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "mongodb objectid",
			input:    "/articles/507f1f77bcf86cd799439011",
			expected: "/articles/{id}",
		},
		{
			name:     "short hex hash 8 chars",
			input:    "/commits/a1b2c3d4",
			expected: "/commits/{id}",
		},
		{
			name:     "short hex hash 12 chars",
			input:    "/commits/abcdef012345",
			expected: "/commits/{id}",
		},
		{
			name:     "base64url token",
			input:    "/tokens/eyJhbGciOiJIUzI1NiJ9X-_test",
			expected: "/tokens/{id}",
		},
		{
			name:     "base64 with mixed case and digits",
			input:    "/sessions/AbCdEfGhIj1234567890",
			expected: "/sessions/{id}",
		},
		{
			name:     "no false positive on simple slug",
			input:    "/articles/my-blog-post",
			expected: "/articles/my-blog-post",
		},
		{
			name:     "no false positive on dictionary word",
			input:    "/users/profile",
			expected: "/users/profile",
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

func TestNormalizePathWithNames_NewKinds(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "mongodb objectid contextual name",
			input:    "/articles/507f1f77bcf86cd799439011",
			expected: "/articles/{articleId}",
		},
		{
			name:     "short hex hash contextual name",
			input:    "/commits/a1b2c3d4",
			expected: "/commits/{commitId}",
		},
		{
			name:     "short hex hash 6 chars",
			input:    "/blobs/abc123",
			expected: "/blobs/{blobId}",
		},
		{
			name:     "base64url token uses Token suffix",
			input:    "/sessions/AbCdEfGhIj1234567890XY",
			expected: "/sessions/{sessionToken}",
		},
		{
			name:     "base64 with padding uses Token suffix",
			input:    "/api/keys/ZXhhbXBsZS10b2tlbi1kYXRh",
			expected: "/api/keys/{keyToken}",
		},
		{
			name:     "ObjectID embedded among literals",
			input:    "/v1/users/507f1f77bcf86cd799439011/avatar",
			expected: "/v1/users/{userId}/avatar",
		},
		{
			name:     "literal preserved despite shape similar to short hex",
			input:    "/users/list",
			expected: "/users/list",
		},
		{
			name:     "literal me preserved",
			input:    "/users/me/profile",
			expected: "/users/me/profile",
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

func TestNormalizePathWithNames_NoFalsePositiveOnHexWords(t *testing.T) {
	// Pure-lowercase English words composed entirely of [a-f] characters
	// have the right length to match the short-hex regex but are not
	// hashes. classifyParamSegment must reject them (isShortHexHash
	// requires at least one digit or uppercase letter).
	cases := []struct {
		name string
		path string
	}{
		{"facade is six lowercase hex chars", "/commits/facade"},
		{"decade is six lowercase hex chars", "/users/decade"},
		{"defaced is seven lowercase hex chars", "/items/defaced"},
		{"beaded is six lowercase hex chars", "/state/beaded"},
		{"deface is six lowercase hex chars", "/actions/deface"},
		{"accede is six lowercase hex chars", "/votes/accede"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := NormalizePathWithNames(c.path); got != c.path {
				t.Errorf("NormalizePathWithNames(%q) = %q, want unchanged literal", c.path, got)
			}
			if got := NormalizePath(c.path); got != c.path {
				t.Errorf("NormalizePath(%q) = %q, want unchanged literal", c.path, got)
			}
		})
	}
}

func TestNormalizePathWithNames_NoFalsePositiveOnDictionaryWords(t *testing.T) {
	// Dictionary words and slugs must not be parameterized by the single-path
	// pass — only the observation-based pass may promote them to parameters.
	cases := []struct {
		name string
		path string
	}{
		{"articles slug", "/articles/my-blog-post"},
		{"users profile", "/users/profile"},
		{"common english word", "/items/recommendation"},
		{"slug with digits", "/articles/2024-year-in-review"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := NormalizePathWithNames(c.path); got != c.path {
				t.Errorf("NormalizePathWithNames(%q) = %q, want unchanged literal", c.path, got)
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

func TestNormalizePathsWithNames_SlugObservation(t *testing.T) {
	paths := []string{
		"/articles/my-first-post",
		"/articles/my-second-post",
		"/articles/yet-another-post",
	}
	got := NormalizePathsWithNames(paths)

	// All three slug-style observations should collapse to a single
	// parameterized path because the position varies across observations.
	want := map[string]string{
		"/articles/my-first-post":    "/articles/{articleSlug}",
		"/articles/my-second-post":   "/articles/{articleSlug}",
		"/articles/yet-another-post": "/articles/{articleSlug}",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("path %q normalized to %q, want %q", k, got[k], v)
		}
	}
}

func TestNormalizePathsWithNames_LiteralNotPromotedAcrossPositions(t *testing.T) {
	paths := []string{
		"/users/me/profile",
		"/users/jane/profile",
		"/users/bob/profile",
	}
	got := NormalizePathsWithNames(paths)

	// `me` is a known literal and must not be parameterized even though
	// `jane` and `bob` vary at the same position. The two non-literal
	// observations promote that position to a slug; the `me` observation
	// stays literal.
	if got["/users/me/profile"] != "/users/me/profile" {
		t.Errorf("literal `me` was rewritten: got %q", got["/users/me/profile"])
	}
	if got["/users/jane/profile"] != "/users/{userSlug}/profile" {
		t.Errorf("varying segment not parameterized: got %q", got["/users/jane/profile"])
	}
	if got["/users/bob/profile"] != "/users/{userSlug}/profile" {
		t.Errorf("varying segment not parameterized: got %q", got["/users/bob/profile"])
	}
}

func TestNormalizePathsWithNames_RootResourceNeverPromoted(t *testing.T) {
	// Different first-segment resource types must not collapse into a single
	// slug parameter just because they vary at the same position index.
	paths := []string{
		"/users",
		"/posts",
		"/articles",
		"/sessions",
	}
	got := NormalizePathsWithNames(paths)
	for _, p := range paths {
		if got[p] != p {
			t.Errorf("root resource %q was promoted: got %q", p, got[p])
		}
	}
}

func TestNormalizePathsWithNames_ResourceTypeBehindPathPrefixNeverPromoted(t *testing.T) {
	// /api/<resource> and /v1/<resource> are common API shapes. The first
	// resource segment after a known scaffold (api, rest, v1, v2, ...) must
	// not be promoted to a slug parameter, because the only preceding
	// "literal context" is the scaffold itself — which is not a resource.
	groups := [][]string{
		{"/api/users", "/api/posts", "/api/articles"},
		{"/v1/users", "/v1/posts", "/v1/articles"},
		{"/v2/products", "/v2/orders", "/v2/customers"},
		{"/api/v1/users", "/api/v1/posts", "/api/v1/articles"},
		{"/rest/users", "/rest/posts"},
	}
	for _, paths := range groups {
		got := NormalizePathsWithNames(paths)
		for _, p := range paths {
			if got[p] != p {
				t.Errorf("scaffold-prefixed resource %q was promoted: got %q", p, got[p])
			}
		}
	}
}

func TestNormalizePathsWithNames_PromotesAfterPathPrefix(t *testing.T) {
	// The segment AFTER the resource type — even when a scaffold prefix is
	// present — should still be promoted when it varies. /api/users/<id> is
	// a parameter; the bug fix for scaffold protection must not over-correct.
	paths := []string{
		"/api/users/alice",
		"/api/users/bob",
		"/api/users/carol",
	}
	got := NormalizePathsWithNames(paths)
	for _, p := range paths {
		if got[p] != "/api/users/{userSlug}" {
			t.Errorf("path %q normalized to %q, want /api/users/{userSlug}", p, got[p])
		}
	}
}

func TestNormalizePathsWithNames_MultiVaryingPositionsWithOverlap(t *testing.T) {
	// When observations overlap (the same owner appears with multiple repos
	// AND the same repo name appears with multiple owners), strict
	// prefix+suffix bucketing has anchors at both positions and the
	// fixed-point iteration promotes both.
	paths := []string{
		"/repos/alice/proj1",
		"/repos/alice/proj2",
		"/repos/bob/proj1",
		"/repos/bob/proj2",
	}
	got := NormalizePathsWithNames(paths)
	for _, p := range paths {
		want := "/repos/{repoSlug}/{repoSlug2}"
		if got[p] != want {
			t.Errorf("path %q normalized to %q, want %q", p, got[p], want)
		}
	}
}

func TestNormalizePathsWithNames_DiagonalObservationsLimitation(t *testing.T) {
	// Pure-diagonal observations — every (owner, repo) pair unique, no
	// overlapping prefix/suffix — cannot be promoted by strict bucketing.
	// Each position's bucket is a singleton, so no variation is observable.
	// This test documents the current behavior; users with this shape need
	// to wait for additional observations to anchor the inference.
	paths := []string{
		"/repos/alice/proj1",
		"/repos/bob/proj2",
		"/repos/carol/proj3",
	}
	got := NormalizePathsWithNames(paths)
	for _, p := range paths {
		if got[p] != p {
			t.Errorf("diagonal-only observation %q unexpectedly promoted to %q (algorithm limitation expected)", p, got[p])
		}
	}
}

func TestNormalizePathsWithNames_SinglePathNoSlug(t *testing.T) {
	// One observation cannot demonstrate variation, so the literal segment
	// must be preserved.
	paths := []string{"/articles/my-only-post"}
	got := NormalizePathsWithNames(paths)
	if got["/articles/my-only-post"] != "/articles/my-only-post" {
		t.Errorf("single observation parameterized: %v", got)
	}
}

func TestNormalizePathsWithNames_RegressionUUIDAndNumeric(t *testing.T) {
	paths := []string{
		"/users/42",
		"/users/43",
		"/users/550e8400-e29b-41d4-a716-446655440000",
		"/posts/1",
		"/posts/2",
	}
	got := NormalizePathsWithNames(paths)
	want := map[string]string{
		"/users/42": "/users/{userId}",
		"/users/43": "/users/{userId}",
		"/users/550e8400-e29b-41d4-a716-446655440000": "/users/{userId}",
		"/posts/1": "/posts/{postId}",
		"/posts/2": "/posts/{postId}",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("path %q normalized to %q, want %q", k, got[k], v)
		}
	}
}

func TestNormalizePathsWithNames_MixedKinds(t *testing.T) {
	paths := []string{
		"/articles/my-first-post",
		"/articles/507f1f77bcf86cd799439011", // ObjectID
		"/articles/another-post",
	}
	got := NormalizePathsWithNames(paths)
	want := map[string]string{
		"/articles/my-first-post":            "/articles/{articleSlug}",
		"/articles/507f1f77bcf86cd799439011": "/articles/{articleId}",
		"/articles/another-post":             "/articles/{articleSlug}",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("path %q normalized to %q, want %q", k, got[k], v)
		}
	}
}

func TestNormalizePathsWithNames_DifferentShapesNotConflated(t *testing.T) {
	// Same position index but different prefix/suffix shapes. The two slug
	// positions are independent, so each must be evaluated within its own
	// shape bucket.
	paths := []string{
		"/articles/foo",
		"/articles/bar",
		"/users/me",
		"/users/baz",
	}
	got := NormalizePathsWithNames(paths)

	// /articles position has two distinct values -> slug.
	if got["/articles/foo"] != "/articles/{articleSlug}" {
		t.Errorf("articles/foo got %q", got["/articles/foo"])
	}
	if got["/articles/bar"] != "/articles/{articleSlug}" {
		t.Errorf("articles/bar got %q", got["/articles/bar"])
	}
	// /users position has only one non-literal value (`baz`); `me` is excluded
	// from observation. With only one varying value, no promotion.
	if got["/users/me"] != "/users/me" {
		t.Errorf("users/me literal lost: %q", got["/users/me"])
	}
	if got["/users/baz"] != "/users/baz" {
		t.Errorf("users/baz prematurely promoted: %q", got["/users/baz"])
	}
}

func TestNormalizePathsWithNames_EmptyAndDuplicateInputs(t *testing.T) {
	if got := NormalizePathsWithNames(nil); len(got) != 0 {
		t.Errorf("NormalizePathsWithNames(nil) = %v, want empty map", got)
	}

	dupPaths := []string{"/users/42", "/users/42", "/users/43"}
	got := NormalizePathsWithNames(dupPaths)
	if len(got) != 2 {
		// Sort for stable error output
		keys := make([]string, 0, len(got))
		for k := range got {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		t.Errorf("expected 2 distinct keys, got %d: %v", len(got), keys)
	}
	if got["/users/42"] != "/users/{userId}" {
		t.Errorf("got %q for /users/42", got["/users/42"])
	}
}

func TestParamNameFromKind_NoContextFallbacks(t *testing.T) {
	cases := []struct {
		kind paramKind
		want string
	}{
		{kindUUID, "id"},
		{kindObjectID, "id"},
		{kindNumeric, "id"},
		{kindShortHex, "id"},
		{kindBase64, "token"},
		{kindSlug, "slug"},
	}
	for _, c := range cases {
		if got := paramNameFromKind("", c.kind); got != c.want {
			t.Errorf("paramNameFromKind(\"\", %v) = %q, want %q", c.kind, got, c.want)
		}
	}
}

func TestIsBase64Token(t *testing.T) {
	cases := []struct {
		segment string
		want    bool
	}{
		{"AbCdEfGhIj1234567890", true},               // mixed case + digits, length 20
		{"ZXhhbXBsZS10b2tlbi1kYXRh", true},           // base64-looking
		{"my-very-long-blog-post-title-here", false}, // pure-lower slug
		{"abcdef0123456789", false},                  // all hex/lower-digit, no upper -> not base64
		{"short", false},                             // too short
		{"AbCdEfGhIj++==", false},                    // length 14, below threshold
		{"Aa1Bb2Cc3Dd4Ee5Ff6", true},                 // mixed case + digits, length >= 16
		{"AaaaaaaaaaaaaaaaaaaaB", false},             // missing digit -> reject
		{"012345678901234567890123", false},          // pure digits handled by numeric kind, base64 alone false (no upper/lower)
	}
	for _, c := range cases {
		if got := isBase64Token(c.segment); got != c.want {
			t.Errorf("isBase64Token(%q) = %v, want %v", c.segment, got, c.want)
		}
	}
}
