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
	"io"
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

func TestParseHeaders_Valid(t *testing.T) {
	tests := []struct {
		name    string
		input   []string
		want    map[string]string
		wantErr bool
	}{
		{
			name:  "single header",
			input: []string{"Content-Type: application/json"},
			want: map[string]string{
				"Content-Type": "application/json",
			},
			wantErr: false,
		},
		{
			name: "multiple headers",
			input: []string{
				"Content-Type: application/json",
				"Authorization: Bearer token123",
				"User-Agent: vespasian/1.0",
			},
			want: map[string]string{
				"Content-Type":  "application/json",
				"Authorization": "Bearer token123",
				"User-Agent":    "vespasian/1.0",
			},
			wantErr: false,
		},
		{
			name:    "empty slice",
			input:   []string{},
			want:    map[string]string{},
			wantErr: false,
		},
		{
			name:  "header with spaces around colon",
			input: []string{"Content-Type   :   application/json"},
			want: map[string]string{
				"Content-Type": "application/json",
			},
			wantErr: false,
		},
		{
			name:  "header with multiple colons in value",
			input: []string{"X-Custom: value:with:colons"},
			want: map[string]string{
				"X-Custom": "value:with:colons",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseHeaders(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseHeaders() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if len(got) != len(tt.want) {
				t.Errorf("parseHeaders() got %d headers, want %d", len(got), len(tt.want))
				return
			}

			for key, wantValue := range tt.want {
				gotValue, ok := got[key]
				if !ok {
					t.Errorf("parseHeaders() missing key %q", key)
				}
				if gotValue != wantValue {
					t.Errorf("parseHeaders()[%q] = %q, want %q", key, gotValue, wantValue)
				}
			}
		})
	}
}

func TestParseHeaders_CRLFInjection(t *testing.T) {
	tests := []struct {
		name  string
		input []string
	}{
		{
			name:  "CRLF in header name",
			input: []string{"Content\r\nType: application/json"},
		},
		{
			name:  "CRLF in header value",
			input: []string{"Content-Type: application/json\r\nX-Injected: malicious"},
		},
		{
			name:  "CR in header name",
			input: []string{"Content\rType: application/json"},
		},
		{
			name:  "LF in header value",
			input: []string{"Content-Type: application/json\nmalicious"},
		},
		{
			name:  "multiple CRLF in value",
			input: []string{"X-Custom: normal\r\n\r\ninjected"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseHeaders(tt.input)
			if err == nil {
				t.Error("parseHeaders() expected error for CRLF injection, got nil")
			}
		})
	}
}

func TestParseHeaders_InvalidFormat(t *testing.T) {
	tests := []struct {
		name  string
		input []string
	}{
		{
			name:  "missing colon",
			input: []string{"Content-Type application/json"},
		},
		{
			name:  "empty string",
			input: []string{""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseHeaders(tt.input)
			if err == nil {
				t.Error("parseHeaders() expected error for invalid format, got nil")
			}
		})
	}
}

// TestParseHeaders_EdgeCases tests edge cases that are technically valid.
func TestParseHeaders_EdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		input   []string
		wantKey string
		wantVal string
		wantErr bool
	}{
		{
			name:    "colon at end (empty value)",
			input:   []string{"Key:"},
			wantKey: "Key",
			wantVal: "",
			wantErr: false,
		},
		{
			name:    "colon at start (empty key)",
			input:   []string{": value"},
			wantErr: true,
		},
		{
			name:    "only colon",
			input:   []string{":"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseHeaders(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseHeaders() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(got) != 1 {
					t.Errorf("parseHeaders() returned %d headers, want 1", len(got))
					return
				}
				if got[tt.wantKey] != tt.wantVal {
					t.Errorf("parseHeaders()[%q] = %q, want %q", tt.wantKey, got[tt.wantKey], tt.wantVal)
				}
			}
		})
	}
}

func TestParseHeaders_Empty(t *testing.T) {
	got, err := parseHeaders([]string{})
	if err != nil {
		t.Errorf("parseHeaders() error = %v, want nil", err)
	}

	if len(got) != 0 {
		t.Errorf("parseHeaders() returned %d headers, want 0", len(got))
	}
}

func TestWriteOutput(t *testing.T) {
	t.Run("stdout when empty", func(t *testing.T) {
		err := writeOutput("", func(_ io.Writer) error {
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("file when path given", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "test-output.json")
		err := writeOutput(path, func(w io.Writer) error {
			_, writeErr := w.Write([]byte("test"))
			return writeErr
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, statErr := os.Stat(path); os.IsNotExist(statErr) {
			t.Error("output file was not created")
		}
	})

	t.Run("error on bad path", func(t *testing.T) {
		err := writeOutput("/nonexistent/directory/file.json", func(_ io.Writer) error {
			return nil
		})
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
