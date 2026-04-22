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

package crawl

import "testing"

func TestResolveURL_Absolute(t *testing.T) {
	got, err := resolveURL("https://example.com/page", "https://example.com/other")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "https://example.com/other" {
		t.Errorf("got %q, want %q", got, "https://example.com/other")
	}
}

func TestResolveURL_Relative(t *testing.T) {
	got, err := resolveURL("https://example.com/dir/page", "other")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "https://example.com/dir/other" {
		t.Errorf("got %q, want %q", got, "https://example.com/dir/other")
	}
}

func TestResolveURL_RootRelative(t *testing.T) {
	got, err := resolveURL("https://example.com/dir/page", "/api/users")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "https://example.com/api/users" {
		t.Errorf("got %q, want %q", got, "https://example.com/api/users")
	}
}

func TestResolveURL_ProtocolRelative(t *testing.T) {
	got, err := resolveURL("https://example.com/page", "//cdn.example.com/asset.js")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "https://cdn.example.com/asset.js" {
		t.Errorf("got %q, want %q", got, "https://cdn.example.com/asset.js")
	}
}

func TestResolveURL_StripsFragment(t *testing.T) {
	got, err := resolveURL("https://example.com/page", "/other#section")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "https://example.com/other" {
		t.Errorf("got %q, want %q", got, "https://example.com/other")
	}
}

func TestResolveURL_JavascriptScheme(t *testing.T) {
	_, err := resolveURL("https://example.com/page", "javascript:void(0)")
	if err == nil {
		t.Error("expected error for javascript: URL")
	}
}

func TestResolveURL_MailtoScheme(t *testing.T) {
	_, err := resolveURL("https://example.com/page", "mailto:test@example.com")
	if err == nil {
		t.Error("expected error for mailto: URL")
	}
}

func TestResolveURL_DataScheme(t *testing.T) {
	_, err := resolveURL("https://example.com/page", "data:text/html,<h1>hi</h1>")
	if err == nil {
		t.Error("expected error for data: URL")
	}
}

func TestResolveURL_Empty(t *testing.T) {
	_, err := resolveURL("https://example.com/page", "")
	if err == nil {
		t.Error("expected error for empty reference")
	}
}

func TestResolveURL_WhitespaceRef(t *testing.T) {
	_, err := resolveURL("https://example.com/page", "   ")
	if err == nil {
		t.Error("expected error for whitespace-only reference")
	}
}

func TestResolveURL_FTPScheme(t *testing.T) {
	_, err := resolveURL("https://example.com/page", "ftp://files.example.com/data")
	if err == nil {
		t.Error("expected error for ftp: URL")
	}
}

func TestResolveURL_PreservesQuery(t *testing.T) {
	got, err := resolveURL("https://example.com/page", "/search?q=test&page=1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "https://example.com/search?q=test&page=1" {
		t.Errorf("got %q, want %q", got, "https://example.com/search?q=test&page=1")
	}
}

func TestResolveURL_TelScheme(t *testing.T) {
	_, err := resolveURL("https://example.com/page", "tel:+1234567890")
	if err == nil {
		t.Error("expected error for tel: URL")
	}
}
