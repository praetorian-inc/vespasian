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

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"valid https", "https://example.com", false},
		{"valid http", "http://example.com", false},
		{"valid with path", "https://example.com/api/v1", false},
		{"valid with port", "https://example.com:8080", false},
		{"missing scheme", "example.com", true},
		{"missing host", "https://", true},
		{"empty string", "", true},
		{"ftp scheme", "ftp://example.com", true},
		{"just path", "/api/v1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateURL(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateURL(%q) error = %v, wantErr %v", tt.url, err, tt.wantErr)
			}
		})
	}
}

func TestParseHeaders(t *testing.T) {
	tests := []struct {
		name    string
		headers []string
		wantLen int
		wantErr bool
	}{
		{"nil headers", nil, 0, false},
		{"empty headers", []string{}, 0, false},
		{"single header", []string{"Authorization: Bearer token"}, 1, false},
		{"multiple headers", []string{"Authorization: Bearer token", "Content-Type: application/json"}, 2, false},
		{"header with extra colons", []string{"Authorization: Bearer: token: extra"}, 1, false},
		{"invalid header no colon", []string{"InvalidHeader"}, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseHeaders(tt.headers)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseHeaders() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(result) != tt.wantLen {
				t.Errorf("parseHeaders() got %d headers, want %d", len(result), tt.wantLen)
			}
		})
	}

	// Verify specific header values
	t.Run("header values", func(t *testing.T) {
		result, err := parseHeaders([]string{"Authorization: Bearer token123"})
		if err != nil {
			t.Fatal(err)
		}
		if got := result["Authorization"]; got != "Bearer token123" {
			t.Errorf("got %q, want %q", got, "Bearer token123")
		}
	})

	// Verify trimming
	t.Run("header trimming", func(t *testing.T) {
		result, err := parseHeaders([]string{"  Key  :  Value  "})
		if err != nil {
			t.Fatal(err)
		}
		if got := result["Key"]; got != "Value" {
			t.Errorf("got %q, want %q", got, "Value")
		}
	})
}

func TestOpenOutput(t *testing.T) {
	t.Run("stdout when empty", func(t *testing.T) {
		w, cleanup, err := openOutput("")
		if err != nil {
			t.Fatal(err)
		}
		defer cleanup()
		if w != os.Stdout {
			t.Error("expected os.Stdout for empty path")
		}
	})

	t.Run("file when path given", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "test-output.json")
		w, cleanup, err := openOutput(path)
		if err != nil {
			t.Fatal(err)
		}
		defer cleanup()
		if w == os.Stdout {
			t.Error("expected file writer, got os.Stdout")
		}
		// Verify file was created
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Error("output file was not created")
		}
	})

	t.Run("error on bad path", func(t *testing.T) {
		_, _, err := openOutput("/nonexistent/directory/file.json")
		if err == nil {
			t.Error("expected error for nonexistent directory")
		}
	})
}

func TestClassifiersForType(t *testing.T) {
	tests := []struct {
		name    string
		apiType string
		wantLen int
	}{
		{"rest returns classifier", "rest", 1},
		{"unknown returns nil", "unknown", 0},
		{"graphql returns nil", "graphql", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			classifiers := classifiersForType(tt.apiType)
			if len(classifiers) != tt.wantLen {
				t.Errorf("classifiersForType(%q) got %d classifiers, want %d", tt.apiType, len(classifiers), tt.wantLen)
			}
		})
	}
}

func TestVersionCmd(t *testing.T) {
	cmd := &VersionCmd{}
	if err := cmd.Run(); err != nil {
		t.Errorf("VersionCmd.Run() error = %v", err)
	}
}

func TestCrawlCmdInvalidURL(t *testing.T) {
	cmd := &CrawlCmd{URL: "not-a-url"}
	err := cmd.Run()
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestCrawlCmdInvalidHeader(t *testing.T) {
	cmd := &CrawlCmd{
		URL:    "https://example.com",
		Header: []string{"no-colon-header"},
	}
	err := cmd.Run()
	if err == nil {
		t.Error("expected error for invalid header")
	}
}

func TestImportCmdMissingFile(t *testing.T) {
	cmd := &ImportCmd{
		Format: "burp",
		File:   "/nonexistent/file.xml",
	}
	err := cmd.Run()
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestGenerateCmdMissingCapture(t *testing.T) {
	cmd := &GenerateCmd{
		APIType: "rest",
		Capture: "/nonexistent/capture.json",
	}
	err := cmd.Run()
	if err == nil {
		t.Error("expected error for missing capture file")
	}
}

func TestScanCmdInvalidURL(t *testing.T) {
	cmd := &ScanCmd{URL: "not-a-url"}
	err := cmd.Run()
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}
