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

package importer

import (
	"reflect"
	"testing"
)

func TestExtractQueryParams(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want map[string]string
	}{
		{
			name: "single parameter",
			url:  "https://example.com/api?page=1",
			want: map[string]string{"page": "1"},
		},
		{
			name: "multiple parameters",
			url:  "https://example.com/api?page=1&limit=10&sort=desc",
			want: map[string]string{
				"page":  "1",
				"limit": "10",
				"sort":  "desc",
			},
		},
		{
			name: "parameter with special characters",
			url:  "https://example.com/search?q=hello+world&filter=type%3Dpost",
			want: map[string]string{
				"q":      "hello world",
				"filter": "type=post",
			},
		},
		{
			name: "duplicate keys (takes first value)",
			url:  "https://example.com/api?tag=go&tag=rust",
			want: map[string]string{"tag": "go"},
		},
		{
			name: "no query parameters",
			url:  "https://example.com/api",
			want: nil,
		},
		{
			name: "empty query string",
			url:  "https://example.com/api?",
			want: nil,
		},
		{
			name: "parameter with empty value",
			url:  "https://example.com/api?key=",
			want: map[string]string{"key": ""},
		},
		{
			name: "parameter without value",
			url:  "https://example.com/api?flag",
			want: map[string]string{"flag": ""},
		},
		{
			name: "invalid URL",
			url:  "not a valid url",
			want: nil,
		},
		{
			name: "fragment after query",
			url:  "https://example.com/api?page=1#section",
			want: map[string]string{"page": "1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractQueryParams(tt.url)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extractQueryParams(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}
