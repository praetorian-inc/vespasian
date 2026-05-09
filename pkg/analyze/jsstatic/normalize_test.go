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

package jsstatic

import (
	"testing"
)

func TestNormalizeEXPRPath_NamedSegments(t *testing.T) {
	got, err := NormalizeEXPRPath("/users/EXPR/posts/EXPR", []string{"userId", "postId"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "/users/{userId}/posts/{postId}"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestNormalizeEXPRPath_UnnamedFallback(t *testing.T) {
	got, err := NormalizeEXPRPath("/items/EXPR", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "/items/{param}"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestNormalizeEXPRPath_QueryAndFragmentPreserved(t *testing.T) {
	got, err := NormalizeEXPRPath("/x/EXPR?a=1#b", []string{"id"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "/x/{id}?a=1#b"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestNormalizeEXPRPath_NoEXPR(t *testing.T) {
	got, err := NormalizeEXPRPath("/abc", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "/abc"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestNormalizeEXPRPath_AbsoluteURL(t *testing.T) {
	got, err := NormalizeEXPRPath("https://h/api/EXPR", []string{"id"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "https://h/api/{id}"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestNormalizeEXPRPath_MultipleUnnamed(t *testing.T) {
	got, err := NormalizeEXPRPath("/a/EXPR/b/EXPR", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "/a/{param}/b/{param1}"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestNormalizeEXPRPath_TokensFewerThanEXPR(t *testing.T) {
	got, err := NormalizeEXPRPath("/a/EXPR/b/EXPR", []string{"id"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "/a/{id}/b/{param}"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
