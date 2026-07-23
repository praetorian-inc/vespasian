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

package mediatype

import "testing"

func TestBase(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "empty input",
			input: "",
			want:  "",
		},
		{
			name:  "plain type no params",
			input: "application/json",
			want:  "application/json",
		},
		{
			name:  "charset suffix stripped",
			input: "application/json; charset=utf-8",
			want:  "application/json",
		},
		{
			name:  "boundary suffix stripped",
			input: "text/html; boundary=xyz",
			want:  "text/html",
		},
		{
			name:  "case insensitive",
			input: "Application/JSON",
			want:  "application/json",
		},
		{
			name:  "leading and trailing whitespace",
			input: "  application/json  ",
			want:  "application/json",
		},
		{
			name:  "whitespace before semicolon",
			input: "application/json ; charset=utf-8",
			want:  "application/json",
		},
		{
			name:  "multipart form data with boundary",
			input: "multipart/form-data; boundary=----WebKitFormBoundary",
			want:  "multipart/form-data",
		},
		{
			name:  "urlencoded",
			input: "application/x-www-form-urlencoded",
			want:  "application/x-www-form-urlencoded",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Base(tt.input)
			if got != tt.want {
				t.Errorf("Base(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestHeader(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		lookup  string
		want    string
	}{
		{
			name:    "exact lowercase match (browser-captured)",
			headers: map[string]string{"content-type": "application/json"},
			lookup:  "content-type",
			want:    "application/json",
		},
		{
			name:    "case-insensitive fallback (Burp/HAR title-case)",
			headers: map[string]string{"Content-Type": "application/json"},
			lookup:  "content-type",
			want:    "application/json",
		},
		{
			name:    "absent header returns empty",
			headers: map[string]string{"Accept": "*/*"},
			lookup:  "content-type",
			want:    "",
		},
		{
			name:    "nil map returns empty",
			headers: nil,
			lookup:  "content-type",
			want:    "",
		},
		{
			name:    "exact match wins over cased variant",
			headers: map[string]string{"content-type": "exact", "Content-Type": "cased"},
			lookup:  "content-type",
			want:    "exact",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Header(tt.headers, tt.lookup)
			if got != tt.want {
				t.Errorf("Header(%v, %q) = %q, want %q", tt.headers, tt.lookup, got, tt.want)
			}
		})
	}
}

// TestHeaderCollisionDeterministic pins the deterministic case-insensitive
// fallback: when only differently-cased variants of the looked-up name exist
// (no exact match), the same key must be chosen on every call regardless of Go
// map iteration order. Without the lexicographic tie-break this returned an
// arbitrary value run-to-run. The lookup name here ("CONTENT-TYPE") matches
// neither stored key exactly, so both go through the fallback path.
func TestHeaderCollisionDeterministic(t *testing.T) {
	headers := map[string]string{"Content-Type": "title", "content-type": "lower"}
	// "Content-Type" < "content-type" byte-wise (uppercase precedes lowercase),
	// so the title-cased value is the stable choice.
	const want = "title"
	for i := 0; i < 100; i++ {
		if got := Header(headers, "CONTENT-TYPE"); got != want {
			t.Fatalf("iteration %d: Header = %q, want %q (must be deterministic)", i, got, want)
		}
	}
}
