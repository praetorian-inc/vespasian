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
	got := NormalizeEXPRPath("/users/EXPR/posts/EXPR", []string{"userId", "postId"})
	want := "/users/{userId}/posts/{postId}"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestNormalizeEXPRPath_UnnamedFallback(t *testing.T) {
	got := NormalizeEXPRPath("/items/EXPR", nil)
	want := "/items/{param}"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestNormalizeEXPRPath_QueryAndFragmentPreserved(t *testing.T) {
	got := NormalizeEXPRPath("/x/EXPR?a=1#b", []string{"id"})
	want := "/x/{id}?a=1#b"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestNormalizeEXPRPath_NoEXPR(t *testing.T) {
	got := NormalizeEXPRPath("/abc", nil)
	want := "/abc"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestNormalizeEXPRPath_AbsoluteURL(t *testing.T) {
	got := NormalizeEXPRPath("https://h/api/EXPR", []string{"id"})
	want := "https://h/api/{id}"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestNormalizeEXPRPath_MultipleUnnamed(t *testing.T) {
	got := NormalizeEXPRPath("/a/EXPR/b/EXPR", nil)
	want := "/a/{param}/b/{param1}"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestNormalizeEXPRPath_TokensFewerThanEXPR(t *testing.T) {
	got := NormalizeEXPRPath("/a/EXPR/b/EXPR", []string{"id"})
	want := "/a/{id}/b/{param}"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
