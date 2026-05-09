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
			// Positive coverage for the uppercase A-F discriminator branch
			// of isShortHexHash. Uppercase hex like "ABCDEF" is a real
			// short-SHA shape; without this case the uppercase clause has
			// no positive test.
			name:     "uppercase short hex hash",
			input:    "/commits/ABCDEF",
			expected: "/commits/{commitId}",
		},
		{
			name:     "mixed-case short hex hash",
			input:    "/commits/AbCdEf12",
			expected: "/commits/{commitId}",
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
	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d: %#v", len(got), len(want), got)
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
		{"/apis/users", "/apis/posts", "/apis/articles"},
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

func TestNormalizePathsWithNames_VersionPrefixBoundary(t *testing.T) {
	// versionPrefixRegex is `^v[1-9][0-9]*$` (round-3 tightening). v0, v01,
	// v001 are NOT scaffold prefixes — `/v0/users/<varying>` therefore has
	// non-scaffold literal context (`v0`) and the observation pass DOES
	// promote the trailing varying segment, while v1/v2 (real prefixes)
	// still suppress promotion of the immediately-following resource segment.
	t.Run("v0 is not a scaffold so users segment is observable", func(t *testing.T) {
		paths := []string{"/v0/users/alice", "/v0/users/bob", "/v0/users/carol"}
		got := NormalizePathsWithNames(paths)
		for _, p := range paths {
			if got[p] != "/v0/users/{userSlug}" {
				t.Errorf("path %q normalized to %q, want /v0/users/{userSlug}", p, got[p])
			}
		}
	})
	t.Run("v01 with leading zero is not a scaffold", func(t *testing.T) {
		paths := []string{"/v01/users/alice", "/v01/users/bob", "/v01/users/carol"}
		got := NormalizePathsWithNames(paths)
		for _, p := range paths {
			if got[p] != "/v01/users/{userSlug}" {
				t.Errorf("path %q normalized to %q, want /v01/users/{userSlug}", p, got[p])
			}
		}
	})
	t.Run("v001 with multiple leading zeros is not a scaffold", func(t *testing.T) {
		paths := []string{"/v001/items/foo", "/v001/items/bar", "/v001/items/baz"}
		got := NormalizePathsWithNames(paths)
		for _, p := range paths {
			if got[p] != "/v001/items/{itemSlug}" {
				t.Errorf("path %q normalized to %q, want /v001/items/{itemSlug}", p, got[p])
			}
		}
	})
	t.Run("v1 IS a scaffold so users stays literal", func(t *testing.T) {
		// Sanity check that v1 still behaves as a scaffold (covered also by
		// ResourceTypeBehindPathPrefixNeverPromoted, but worth a direct
		// contrast against the v0 case to make the boundary explicit).
		paths := []string{"/v1/users", "/v1/posts", "/v1/articles"}
		got := NormalizePathsWithNames(paths)
		for _, p := range paths {
			if got[p] != p {
				t.Errorf("v1 scaffold path %q was promoted: got %q", p, got[p])
			}
		}
	})
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

func TestNormalizePathsWithNames_MixedKindsUnifyAcrossAllRegexKinds(t *testing.T) {
	// unifyMixedKindsAtSamePosition uses the same `hasOther` map for every
	// non-slug kind, so a position holding slug + UUID + ObjectID + ShortHex
	// + numeric must fully collapse onto kindSlug. This guards against a
	// future refactor that special-cases one kind (e.g., only collapsing
	// kindObjectID) and silently leaves other regex kinds emitting their
	// own templates alongside the slug.
	paths := []string{
		"/articles/my-first-post",                        // observation-promoted slug
		"/articles/my-second-post",                       // observation-promoted slug (anchors variation)
		"/articles/550e8400-e29b-41d4-a716-446655440000", // UUID
		"/articles/507f1f77bcf86cd799439011",             // ObjectID (24 hex)
		"/articles/AbCdEf12",                             // short hex (uppercase + digit)
		"/articles/42",                                   // numeric
	}
	got := NormalizePathsWithNames(paths)
	const want = "/articles/{articleSlug}"
	for _, p := range paths {
		if got[p] != want {
			t.Errorf("path %q normalized to %q, want %q", p, got[p], want)
		}
	}
}

func TestNormalizePathsWithNames_SlugOnlyNoOpUnification(t *testing.T) {
	// When every observation at a shape position is already kindSlug (no
	// regex-classified peer), unifyMixedKindsAtSamePosition's `!hasOther`
	// branch fires and the function does nothing. Output is identical to
	// the post-promotion state. This locks in that the unification pass is
	// inert when there is nothing to unify.
	paths := []string{
		"/items/foo-1",
		"/items/bar-2",
		"/items/baz-3",
	}
	got := NormalizePathsWithNames(paths)
	for _, p := range paths {
		if got[p] != "/items/{itemSlug}" {
			t.Errorf("path %q normalized to %q, want /items/{itemSlug}", p, got[p])
		}
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
	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d: %#v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("path %q normalized to %q, want %q", k, got[k], v)
		}
	}
}

func TestNormalizePathsWithNames_MixedKinds(t *testing.T) {
	// When an observation-promoted slug coexists at the same path position
	// with a regex-classified kind (here, an ObjectID), the post-process
	// unification collapses them onto kindSlug so a single OpenAPI path
	// template emerges. Without this, downstream tooling would see two
	// distinct templates (/articles/{articleSlug} and /articles/{articleId})
	// for the same parameterized endpoint.
	paths := []string{
		"/articles/my-first-post",
		"/articles/507f1f77bcf86cd799439011", // ObjectID
		"/articles/another-post",
	}
	got := NormalizePathsWithNames(paths)
	want := map[string]string{
		"/articles/my-first-post":            "/articles/{articleSlug}",
		"/articles/507f1f77bcf86cd799439011": "/articles/{articleSlug}",
		"/articles/another-post":             "/articles/{articleSlug}",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d: %#v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("path %q normalized to %q, want %q", k, got[k], v)
		}
	}
}

func TestNormalizePathsWithNames_MixedKindsWithoutSlugObservation(t *testing.T) {
	// When no slug observation is promoted (single observation of a slug
	// shape), the regex-classified kind keeps its template; the literal
	// stays literal. Unification only runs when a slug actually exists at
	// the shape position.
	paths := []string{
		"/articles/my-only-post",             // 1 literal observation, not promoted
		"/articles/507f1f77bcf86cd799439011", // ObjectID, regex-classified
	}
	got := NormalizePathsWithNames(paths)
	want := map[string]string{
		"/articles/my-only-post":             "/articles/my-only-post",
		"/articles/507f1f77bcf86cd799439011": "/articles/{articleId}",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d: %#v", len(got), len(want), got)
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
	if got["/users/43"] != "/users/{userId}" {
		t.Errorf("got %q for /users/43", got["/users/43"])
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

func TestParamNameFromKind_WithContext(t *testing.T) {
	// Direct table-driven coverage for the contextual path of
	// paramNameFromKind: singularize(prev) + suffixForKind(kind). This
	// isolates the suffix selection from path splitting, so a regression
	// that maps kindBase64 to "Slug" or kindSlug to "Token" fails here
	// instead of in a far-removed full-path test.
	cases := []struct {
		name string
		prev string
		kind paramKind
		want string
	}{
		{"users + UUID", "users", kindUUID, "userId"},
		{"users + ObjectID", "users", kindObjectID, "userId"},
		{"users + numeric", "users", kindNumeric, "userId"},
		{"users + shortHex", "users", kindShortHex, "userId"},
		{"sessions + base64", "sessions", kindBase64, "sessionToken"},
		{"articles + slug", "articles", kindSlug, "articleSlug"},
		{"categories + slug", "categories", kindSlug, "categorySlug"},
		{"addresses + UUID", "addresses", kindUUID, "addressId"},
		{"data + UUID (no plural)", "data", kindUUID, "dataId"},
		{"hyphen-context + slug", "my-resource", kindSlug, "myResourceSlug"},
		{"dot-context + slug", "v2.foo", kindSlug, "v2FooSlug"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := paramNameFromKind(c.prev, c.kind); got != c.want {
				t.Errorf("paramNameFromKind(%q, %v) = %q, want %q", c.prev, c.kind, got, c.want)
			}
		})
	}
}

func TestSanitizeParamName_HyphenAndDotConversion(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain alphanumeric unchanged", "userId", "userId"},
		{"underscore preserved", "user_id", "user_id"},
		{"hyphen becomes camelCase", "my-service", "myService"},
		{"dot becomes camelCase", "v2.foo.bar", "v2FooBar"},
		{"trailing hyphen swallowed", "user-", "user"},
		{"leading hyphen swallowed", "-user", "User"},
		{"unsafe characters dropped", "us%er!", "user"},
		{"empty input becomes id", "", "id"},
		{"only-unsafe becomes id", "!?", "id"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sanitizeParamName(c.in); got != c.want {
				t.Errorf("sanitizeParamName(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestNormalizePathsWithNames_DeepPathsAcrossPositions(t *testing.T) {
	// Depth-5 smoke test: owner (position 2), project (position 3), and the
	// trailing numeric segment (position 5) all parameterize. Owner and
	// project are slug-shaped and vary across observations with enough
	// overlap that strict bucketing in a single round identifies both as
	// varying; the trailing numeric is regex-classified as kindNumeric and
	// renders with the `Id` suffix. This test exercises multi-position
	// promotion plus the slug+numeric rendering through deep paths — it
	// does NOT prove the fixed-point property (see
	// TestNormalizePathsWithNames_FixedPointIterationRequired for that).
	paths := []string{
		"/repos/alice/proj1/issues/1",
		"/repos/alice/proj1/issues/2",
		"/repos/alice/proj2/issues/1",
		"/repos/bob/proj1/issues/1",
		"/repos/bob/proj2/issues/2",
	}
	got := NormalizePathsWithNames(paths)
	const want = "/repos/{repoSlug}/{repoSlug2}/issues/{issueId}"
	for _, p := range paths {
		if got[p] != want {
			t.Errorf("path %q normalized to %q, want %q", p, got[p], want)
		}
	}
}

func TestNormalizePathsWithNames_FixedPointIterationRequired(t *testing.T) {
	// This fixture genuinely requires more than one promotion round.
	//
	// In round 1, only the alice/proj-a + bob/proj-a pair shares a suffix
	// (proj-a) so position 2 promotes only at those two paths; the alice
	// and bob "loners" (alice/proj-b and bob/proj-c) sit in singleton
	// suffix-buckets at position 2 and are NOT promoted in round 1.
	// Position 3 shares the prefix /repos/alice between alice/proj-a and
	// alice/proj-b (and /repos/bob between bob/proj-a and bob/proj-c) so
	// position 3 promotes for all four paths in round 1.
	//
	// After round 1, position 2 of alice/proj-b and bob/proj-c is still
	// kindLiteral but their position-3 segments are now kindSlug. The
	// suffix shape collapses to "/{}" — which matches the suffix shape of
	// alice/proj-a and bob/proj-a (also "/{}" after round-1 promotion).
	// In round 2, alice/proj-b's position 2 bucket joins bob/proj-c's
	// position 2 bucket via the shared "/{}" suffix shape. The bucket
	// gains both alice and bob → varying → promote.
	//
	// A capped-iteration implementation (single round) would leave
	// alice/proj-b at /repos/alice/{repoSlug} and bob/proj-c at
	// /repos/bob/{repoSlug} — three distinct paths instead of one.
	paths := []string{
		"/repos/alice/proj-a",
		"/repos/alice/proj-b",
		"/repos/bob/proj-a",
		"/repos/bob/proj-c",
	}
	got := NormalizePathsWithNames(paths)
	const want = "/repos/{repoSlug}/{repoSlug2}"
	for _, p := range paths {
		if got[p] != want {
			t.Errorf("path %q normalized to %q, want %q", p, got[p], want)
		}
	}
}

func TestNormalizePathsWithNames_IntraRoundAdjacentPositionPromotion(t *testing.T) {
	// Pin down the exact failure mode of the pre-fix in-place algorithm:
	// two positions in the SAME path promoted in the SAME round via
	// different bucket keys. With four overlapping observations, round 1
	// finds varying buckets at BOTH position 2 (prefix=/x, suffix=/y/{b|c})
	// and position 4 (prefix=/x/{a|d}/y, suffix=) of every path. The
	// atomic two-pass strategy in promoteVaryingPositions promotes both
	// in the same call. An in-place implementation would mutate position 2
	// first, change the shape used to compute position 4's posKey, and
	// silently skip position 4's promotion in this round.
	paths := []string{
		"/x/a/y/b",
		"/x/a/y/c", // anchors position 4's /x/a/y prefix bucket
		"/x/d/y/b", // anchors position 2's /y/b suffix bucket
		"/x/d/y/c", // anchors position 2's /y/c suffix bucket and position 4's /x/d/y prefix bucket
	}
	got := NormalizePathsWithNames(paths)
	const want = "/x/{xSlug}/y/{ySlug}"
	if len(got) != len(paths) {
		t.Fatalf("got %d entries, want %d: %#v", len(got), len(paths), got)
	}
	for _, p := range paths {
		if got[p] != want {
			t.Errorf("path %q normalized to %q, want %q", p, got[p], want)
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
		{"ABCDEF0123456789XY", false},                // all-uppercase + digits, no lowercase -> false (documented trade-off; rare in URL paths, accepted asymmetry vs isShortHexHash)
	}
	for _, c := range cases {
		if got := isBase64Token(c.segment); got != c.want {
			t.Errorf("isBase64Token(%q) = %v, want %v", c.segment, got, c.want)
		}
	}
}
