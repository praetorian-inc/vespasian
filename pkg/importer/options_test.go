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
	"io"
	"strings"
	"testing"

	"github.com/praetorian-inc/vespasian/pkg/crawl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMatchesScope(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		scope    string
		expected bool
	}{
		{
			name:     "exact match",
			url:      "https://example.com/api",
			scope:    "example.com",
			expected: true,
		},
		{
			name:     "wildcard subdomain match",
			url:      "https://api.example.com/v1",
			scope:    "*.example.com",
			expected: true,
		},
		{
			name:     "wildcard matches root domain",
			url:      "https://example.com/api",
			scope:    "*.example.com",
			expected: true,
		},
		{
			name:     "wildcard no match",
			url:      "https://other.com/api",
			scope:    "*.example.com",
			expected: false,
		},
		{
			name:     "exact no match",
			url:      "https://other.com/api",
			scope:    "example.com",
			expected: false,
		},
		{
			name:     "subdomain no exact match",
			url:      "https://api.example.com/v1",
			scope:    "example.com",
			expected: false,
		},
		{
			name:     "empty scope matches all",
			url:      "https://anything.com/api",
			scope:    "",
			expected: true,
		},
		{
			name:     "invalid url",
			url:      "not-a-url",
			scope:    "example.com",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchesScope(tt.url, tt.scope)
			assert.Equal(t, tt.expected, result)
		})
	}
}

type mockImporter struct {
	requests []crawl.ObservedRequest
}

func (m *mockImporter) Name() string {
	return "mock"
}

func (m *mockImporter) Import(r io.Reader) ([]crawl.ObservedRequest, error) {
	return m.requests, nil
}

func TestImportWithOptions(t *testing.T) {
	requests := []crawl.ObservedRequest{
		{
			Method: "GET",
			URL:    "https://example.com/api",
			Source: "mock",
		},
		{
			Method: "GET",
			URL:    "https://other.com/api",
			Source: "mock",
		},
		{
			Method: "GET",
			URL:    "https://api.example.com/v1",
			Source: "mock",
		},
	}

	tests := []struct {
		name     string
		opts     ImportOptions
		expected int
	}{
		{
			name:     "no scope filters all",
			opts:     ImportOptions{},
			expected: 3,
		},
		{
			name: "exact scope match",
			opts: ImportOptions{
				Scope: "example.com",
			},
			expected: 1,
		},
		{
			name: "wildcard scope match",
			opts: ImportOptions{
				Scope: "*.example.com",
			},
			expected: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockImporter{requests: requests}
			result, err := ImportWithOptions(mock, strings.NewReader(""), tt.opts)
			require.NoError(t, err)
			assert.Len(t, result, tt.expected)
		})
	}
}
