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

import (
	"os"
	"testing"
)

func TestExtractBearerToken(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		want    string
	}{
		{
			name:    "standard bearer token",
			headers: map[string]string{"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.test"},
			want:    "eyJhbGciOiJIUzI1NiJ9.test",
		},
		{
			name:    "case-insensitive header name",
			headers: map[string]string{"authorization": "Bearer my-token-123"},
			want:    "my-token-123",
		},
		{
			name:    "mixed case header name",
			headers: map[string]string{"AUTHORIZATION": "Bearer TOKEN"},
			want:    "TOKEN",
		},
		{
			name:    "no authorization header",
			headers: map[string]string{"Content-Type": "application/json"},
			want:    "",
		},
		{
			name:    "empty headers",
			headers: map[string]string{},
			want:    "",
		},
		{
			name:    "nil headers",
			headers: nil,
			want:    "",
		},
		{
			name:    "basic auth (not bearer)",
			headers: map[string]string{"Authorization": "Basic dXNlcjpwYXNz"},
			want:    "",
		},
		{
			name:    "bearer with extra whitespace",
			headers: map[string]string{"Authorization": "  Bearer   spaced-token"},
			want:    "  spaced-token",
		},
		{
			name: "bearer among multiple headers",
			headers: map[string]string{
				"Content-Type":  "application/json",
				"Authorization": "Bearer multi-header-token",
				"User-Agent":    "vespasian/1.0",
			},
			want: "multi-header-token",
		},
		{
			name:    "empty bearer value",
			headers: map[string]string{"Authorization": "Bearer "},
			want:    "",
		},
		{
			name:    "just Bearer keyword",
			headers: map[string]string{"Authorization": "Bearer"},
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractBearerToken(tt.headers)
			if got != tt.want {
				t.Errorf("extractBearerToken() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCommonAuthKeys(t *testing.T) {
	// Verify that commonAuthKeys is non-empty and contains expected keys.
	if len(commonAuthKeys) == 0 {
		t.Fatal("commonAuthKeys should not be empty")
	}

	expected := map[string]bool{
		"auth":         true,
		"token":        true,
		"access_token": true,
		"jwt":          true,
	}
	found := make(map[string]bool)
	for _, key := range commonAuthKeys {
		found[key] = true
	}
	for key := range expected {
		if !found[key] {
			t.Errorf("commonAuthKeys missing expected key %q", key)
		}
	}
}

// TestPreSeedBrowserAuth_CreatesDataDir verifies that preSeedBrowserAuth
// creates a Chrome data directory and returns a valid path.
// This test requires Chrome to be installed and launches a headless instance.
func TestPreSeedBrowserAuth_CreatesDataDir(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	dataDir, err := preSeedBrowserAuth("http://example.com", "test-token-123")
	if err != nil {
		t.Fatalf("preSeedBrowserAuth() error: %v", err)
	}
	defer os.RemoveAll(dataDir)

	// Verify the directory exists.
	info, err := os.Stat(dataDir)
	if err != nil {
		t.Fatalf("data dir stat error: %v", err)
	}
	if !info.IsDir() {
		t.Errorf("data dir is not a directory: %s", dataDir)
	}
}

// TestPreSeedBrowserAuth_InvalidURL verifies that an invalid URL returns an error.
func TestPreSeedBrowserAuth_InvalidURL(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser test in short mode")
	}

	_, err := preSeedBrowserAuth("://invalid", "test-token")
	if err == nil {
		t.Error("expected error for invalid URL, got nil")
	}
}
