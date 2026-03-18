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
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/praetorian-inc/vespasian/pkg/crawl"
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
		{
			name:  "null byte in header value",
			input: []string{"X-Custom: before\x00after"},
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

// TestParseHeaders_RFC7230InvalidNames tests that header names with characters
// outside the RFC 7230 token production are rejected.
func TestParseHeaders_RFC7230InvalidNames(t *testing.T) {
	tests := []struct {
		name  string
		input []string
	}{
		{
			name:  "space in header name",
			input: []string{"Content Type: application/json"},
		},
		{
			name:  "parenthesis in header name",
			input: []string{"Content(Type): application/json"},
		},
		{
			name:  "slash in header name",
			input: []string{"Content/Type: application/json"},
		},
		{
			name:  "equals in header name",
			input: []string{"Content=Type: application/json"},
		},
		{
			name:  "at sign in header name",
			input: []string{"Content@Type: application/json"},
		},
		{
			name:  "bracket in header name",
			input: []string{"Content[Type]: application/json"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseHeaders(tt.input)
			if err == nil {
				t.Error("parseHeaders() expected error for invalid header name, got nil")
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
		{"graphql returns classifier", "graphql", 1},
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
		URL: "https://example.com",
		CrawlOptions: CrawlOptions{
			Header: []string{"no-colon-header"},
		},
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

// TestGenerateSpec tests the generateSpec pipeline with table-driven cases.
func TestGenerateSpec(t *testing.T) {
	requests := []crawl.ObservedRequest{
		{
			Method: "GET",
			URL:    "https://example.com/api/users",
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "application/json",
			},
		},
	}

	tests := []struct {
		name        string
		apiType     string
		probe       bool
		deduplicate bool
		verbose     bool
		wantErrStr  string
		wantErr     bool
	}{
		{
			name:        "rest with valid requests, probe disabled",
			apiType:     "rest",
			probe:       false,
			deduplicate: true,
			wantErr:     false,
		},
		{
			name:       "unknown api type",
			apiType:    "unknown",
			probe:      false,
			wantErr:    true,
			wantErrStr: "unsupported API type",
		},
		{
			name:        "probe enabled with real implementations",
			apiType:     "rest",
			probe:       true,
			deduplicate: true,
			wantErr:     false,
		},
		{
			name:        "verbose logging",
			apiType:     "rest",
			probe:       false,
			deduplicate: true,
			verbose:     true,
			wantErr:     false,
		},
		{
			name:        "rest without deduplication",
			apiType:     "rest",
			probe:       false,
			deduplicate: false,
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := generateSpec(context.Background(), requests, generateSpecOptions{
				APIType:     tt.apiType,
				Confidence:  0.5,
				Probe:       tt.probe,
				Deduplicate: tt.deduplicate,
				Verbose:     tt.verbose,
			})
			if tt.wantErr {
				if err == nil {
					t.Fatalf("generateSpec() expected error containing %q, got nil", tt.wantErrStr)
				}
				if !strings.Contains(err.Error(), tt.wantErrStr) {
					t.Errorf("generateSpec() error = %q, want error containing %q", err.Error(), tt.wantErrStr)
				}
			} else if err != nil {
				t.Errorf("generateSpec() unexpected error: %v", err)
			}
		})
	}
}

// TestGenerateSpec_EmptyRequests verifies generateSpec handles empty request slices.
// With real implementations, empty requests produce no classified endpoints,
// so the generator returns nil spec with no error.
func TestGenerateSpec_EmptyRequests(t *testing.T) {

	spec, err := generateSpec(context.Background(), []crawl.ObservedRequest{}, generateSpecOptions{
		APIType:     "rest",
		Confidence:  0.5,
		Deduplicate: true,
	})
	if err != nil {
		t.Fatalf("generateSpec() unexpected error: %v", err)
	}
	// Empty input produces nil or empty spec — no endpoints found.
	if len(spec) > 0 {
		t.Logf("generateSpec() returned %d bytes for empty input", len(spec))
	}
}

// TestGenerateCmdRun_ValidCapture writes a valid capture file and runs GenerateCmd.
func TestGenerateCmdRun_ValidCapture(t *testing.T) {
	requests := []crawl.ObservedRequest{
		{
			Method: "GET",
			URL:    "https://example.com/api/users",
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "application/json",
			},
		},
	}

	// Write capture data to a temp file.
	capturePath := filepath.Join(t.TempDir(), "capture.json")
	f, err := os.Create(capturePath)
	if err != nil {
		t.Fatalf("failed to create temp capture file: %v", err)
	}
	if writeErr := crawl.WriteCapture(f, requests); writeErr != nil {
		_ = f.Close()
		t.Fatalf("failed to write capture: %v", writeErr)
	}
	_ = f.Close()

	cmd := &GenerateCmd{
		APIType:     "rest",
		Capture:     capturePath,
		Probe:       false,
		Deduplicate: true,
	}
	err = cmd.Run()
	if err != nil {
		t.Errorf("GenerateCmd.Run() unexpected error: %v", err)
	}
}

// TestImportCmdRun_ValidFile creates a temp file and runs ImportCmd with burp format.
// The real burp importer expects valid Burp Suite XML with <items> root element.
func TestImportCmdRun_ValidFile(t *testing.T) {
	// Write invalid Burp XML — real importer rejects <burp> root (expects <items>).
	tmpFile := filepath.Join(t.TempDir(), "burp-export.xml")
	if writeErr := os.WriteFile(tmpFile, []byte("<burp></burp>"), 0600); writeErr != nil {
		t.Fatalf("failed to write temp file: %v", writeErr)
	}

	cmd := &ImportCmd{
		Format: "burp",
		File:   tmpFile,
	}
	err := cmd.Run()
	if err == nil {
		t.Fatal("ImportCmd.Run() expected error for invalid Burp XML, got nil")
	}
	// Real burp importer rejects wrong root element.
	if !strings.Contains(err.Error(), "import failed") {
		t.Errorf("ImportCmd.Run() error = %q, want error containing \"import failed\"", err.Error())
	}
}

// TestScanCmdInvalidHeader verifies that ScanCmd rejects invalid header format.
func TestScanCmdInvalidHeader(t *testing.T) {
	cmd := &ScanCmd{
		URL: "https://example.com",
		CrawlOptions: CrawlOptions{
			Header: []string{"no-colon-header"},
		},
	}
	err := cmd.Run()
	if err == nil {
		t.Error("expected error for invalid header")
	}
}

// TestCrawlOptions_Embedded verifies that CrawlOptions fields are promoted into CrawlCmd and ScanCmd.
func TestCrawlOptions_Embedded(t *testing.T) {
	// Verify CrawlCmd can access embedded CrawlOptions fields directly.
	c := &CrawlCmd{
		URL: "https://example.com",
		CrawlOptions: CrawlOptions{
			Depth:    5,
			MaxPages: 50,
			Verbose:  true,
		},
	}
	if c.Depth != 5 {
		t.Errorf("CrawlCmd.Depth = %d, want 5", c.Depth)
	}
	if c.MaxPages != 50 {
		t.Errorf("CrawlCmd.MaxPages = %d, want 50", c.MaxPages)
	}
	if !c.Verbose {
		t.Error("CrawlCmd.Verbose = false, want true")
	}

	// Verify ScanCmd can access embedded CrawlOptions fields directly.
	s := &ScanCmd{
		URL: "https://example.com",
		CrawlOptions: CrawlOptions{
			Depth:    10,
			Headless: true,
		},
	}
	if s.Depth != 10 {
		t.Errorf("ScanCmd.Depth = %d, want 10", s.Depth)
	}
	if !s.Headless {
		t.Error("ScanCmd.Headless = false, want true")
	}
}

// TestDangerousAllowPrivate_GenerateSpec tests generateSpec with allowPrivate=true.
func TestDangerousAllowPrivate_GenerateSpec(t *testing.T) {
	requests := []crawl.ObservedRequest{
		{
			Method: "GET",
			URL:    "https://example.com/api/users",
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "application/json",
			},
		},
	}

	tests := []struct {
		name    string
		probe   bool
		wantErr bool
	}{
		{
			name:    "allowPrivate with probe disabled",
			probe:   false,
			wantErr: false,
		},
		{
			name:    "allowPrivate with probe enabled",
			probe:   true,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := generateSpec(context.Background(), requests, generateSpecOptions{
				APIType:      "rest",
				Confidence:   0.5,
				Probe:        tt.probe,
				Deduplicate:  true,
				AllowPrivate: true,
			})
			if (err != nil) != tt.wantErr {
				t.Errorf("generateSpec() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestDangerousAllowPrivate_GenerateCmd verifies GenerateCmd accepts DangerousAllowPrivate
// and completes without error when probing with the flag enabled.
func TestDangerousAllowPrivate_GenerateCmd(t *testing.T) {
	requests := []crawl.ObservedRequest{
		{
			Method: "GET",
			URL:    "https://example.com/api/users",
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "application/json",
			},
		},
	}

	capturePath := filepath.Join(t.TempDir(), "capture.json")
	f, err := os.Create(capturePath)
	if err != nil {
		t.Fatalf("failed to create temp capture file: %v", err)
	}
	if writeErr := crawl.WriteCapture(f, requests); writeErr != nil {
		_ = f.Close()
		t.Fatalf("failed to write capture: %v", writeErr)
	}
	_ = f.Close()

	cmd := &GenerateCmd{
		APIType:               "rest",
		Capture:               capturePath,
		Probe:                 true,
		DangerousAllowPrivate: true,
	}
	if err := cmd.Run(); err != nil {
		t.Errorf("GenerateCmd.Run() with DangerousAllowPrivate unexpected error: %v", err)
	}
}

// TestDangerousAllowPrivate_ScanCmd verifies ScanCmd accepts the DangerousAllowPrivate field.
// Intentionally shallow: Run() requires a live browser and network, so this only confirms the
// kong struct wiring is correct. The flag's runtime behavior is covered by TestGenerateSpec_*
// and TestDangerousAllowPrivate_PrivateIPProbe.
func TestDangerousAllowPrivate_ScanCmd(t *testing.T) {
	cmd := &ScanCmd{
		URL:                   "https://example.com",
		DangerousAllowPrivate: true,
		CrawlOptions: CrawlOptions{
			Depth:    3,
			MaxPages: 100,
		},
	}
	if !cmd.DangerousAllowPrivate {
		t.Error("ScanCmd.DangerousAllowPrivate = false, want true")
	}
	if cmd.URL != "https://example.com" {
		t.Errorf("ScanCmd.URL = %q, want %q", cmd.URL, "https://example.com")
	}
}

// TestDangerousAllowPrivate_SameOutputForPublicURLs verifies that allowPrivate=true
// and allowPrivate=false produce identical specs when all targets are public.
func TestDangerousAllowPrivate_SameOutputForPublicURLs(t *testing.T) {
	requests := []crawl.ObservedRequest{
		{
			Method: "GET",
			URL:    "https://example.com/api/users",
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "application/json",
			},
		},
	}

	specWithout, err := generateSpec(context.Background(), requests, generateSpecOptions{
		APIType:     "rest",
		Confidence:  0.5,
		Probe:       true,
		Deduplicate: true,
	})
	if err != nil {
		t.Fatalf("generateSpec(allowPrivate=false) unexpected error: %v", err)
	}

	specWith, err := generateSpec(context.Background(), requests, generateSpecOptions{
		APIType:      "rest",
		Confidence:   0.5,
		Probe:        true,
		Deduplicate:  true,
		AllowPrivate: true,
	})
	if err != nil {
		t.Fatalf("generateSpec(allowPrivate=true) unexpected error: %v", err)
	}

	if string(specWithout) != string(specWith) {
		t.Errorf("specs differ for public URLs:\n  allowPrivate=false: %d bytes\n  allowPrivate=true:  %d bytes",
			len(specWithout), len(specWith))
	}
}

// TestDangerousAllowPrivate_PrivateIPProbe verifies that generateSpec with
// allowPrivate=true can actually probe a loopback httptest server. Without the
// flag, the SSRF protection (both URLValidator and ssrfSafeDialContext) would
// block the connection to 127.0.0.1.
func TestDangerousAllowPrivate_PrivateIPProbe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "OPTIONS" {
			w.Header().Set("Allow", "GET, POST, OPTIONS")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	requests := []crawl.ObservedRequest{
		{
			Method: "GET",
			URL:    srv.URL + "/api/users",
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "application/json",
			},
		},
	}

	// With allowPrivate=true, probes should reach the loopback server.
	spec, err := generateSpec(context.Background(), requests, generateSpecOptions{
		APIType:      "rest",
		Confidence:   0.5,
		Probe:        true,
		Deduplicate:  true,
		AllowPrivate: true,
	})
	if err != nil {
		t.Fatalf("generateSpec(allowPrivate=true, probe=true) on loopback: %v", err)
	}
	if len(spec) == 0 {
		t.Error("generateSpec returned empty spec for loopback server with allowPrivate=true")
	}

	// Without allowPrivate, probes to loopback should be blocked by SSRF protection.
	// generateSpec still succeeds (probe errors are non-fatal), but we verify it
	// doesn't crash.
	_, err = generateSpec(context.Background(), requests, generateSpecOptions{
		APIType:     "rest",
		Confidence:  0.5,
		Probe:       true,
		Deduplicate: true,
	})
	if err != nil {
		t.Fatalf("generateSpec(allowPrivate=false, probe=true) on loopback: %v", err)
	}
}

// TestDangerousAllowPrivate_WarningOnlyWhenProbing verifies the SSRF warning
// is only printed when both allowPrivate and probe are true.
func TestDangerousAllowPrivate_WarningOnlyWhenProbing(t *testing.T) {
	requests := []crawl.ObservedRequest{
		{
			Method: "GET",
			URL:    "https://example.com/api/users",
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "application/json",
			},
		},
	}

	// Capture stderr
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	_, _ = generateSpec(context.Background(), requests, generateSpecOptions{
		APIType:      "rest",
		Confidence:   0.5,
		Probe:        false,
		AllowPrivate: true,
	})

	w.Close()
	var buf bytes.Buffer
	io.Copy(&buf, r)
	os.Stderr = oldStderr

	if strings.Contains(buf.String(), "WARNING") {
		t.Error("SSRF warning should not be printed when probe is disabled")
	}
}

// TestDoCrawl_ProxyIgnoredWithoutHeadless verifies that doCrawl warns and clears
// the proxy option when headless mode is disabled.
func TestDoCrawl_ProxyIgnoredWithoutHeadless(t *testing.T) {
	var buf bytes.Buffer
	opts := crawl.CrawlerOptions{
		Headless: false,
		Proxy:    "http://127.0.0.1:8080",
	}
	// doCrawl will warn and clear proxy before creating the crawler.
	// It will then fail on the actual crawl (no valid URL), but we only
	// care about the warning message.
	_, _ = doCrawl(context.Background(), &buf, "https://example.com", opts)
	if !strings.Contains(buf.String(), "warning: --proxy is only supported with headless browser mode") {
		t.Errorf("expected proxy warning on stderr, got %q", buf.String())
	}
}

// TestDoCrawl_ProxyPortlessWarning verifies that doCrawl warns when the proxy
// address has no explicit port.
func TestDoCrawl_ProxyPortlessWarning(t *testing.T) {
	var buf bytes.Buffer
	opts := crawl.CrawlerOptions{
		Headless: true,
		Proxy:    "http://proxy.local",
	}
	// doCrawl will warn about the missing port, then fail on the actual crawl.
	// We only care about the warning message.
	_, _ = doCrawl(context.Background(), &buf, "https://example.com", opts)
	if !strings.Contains(buf.String(), "has no explicit port") {
		t.Errorf("expected port-less warning on stderr, got %q", buf.String())
	}
}

// TestCrawlOptions_Proxy verifies that the --proxy flag is accessible on both
// CrawlCmd and ScanCmd via the embedded CrawlOptions.
func TestCrawlOptions_Proxy(t *testing.T) {
	proxy := "http://127.0.0.1:8080"

	c := &CrawlCmd{
		URL: "https://example.com",
		CrawlOptions: CrawlOptions{
			Proxy: proxy,
		},
	}
	if c.Proxy != proxy {
		t.Errorf("CrawlCmd.Proxy = %q, want %q", c.Proxy, proxy)
	}

	s := &ScanCmd{
		URL: "https://example.com",
		CrawlOptions: CrawlOptions{
			Proxy: proxy,
		},
	}
	if s.Proxy != proxy {
		t.Errorf("ScanCmd.Proxy = %q, want %q", s.Proxy, proxy)
	}
}

// TestVersionVariable verifies the version variable is accessible and has a default.
func TestVersionVariable(t *testing.T) {
	if version == "" {
		t.Error("version variable should not be empty")
	}
	// Default value is "dev" unless set via ldflags.
	t.Logf("version = %q", version)
}

// TestOnForceExit_WritesMessageAndExits verifies that the force-exit logic
// writes the expected message to stderr and calls exitFn with code 1.
func TestOnForceExit_WritesMessageAndExits(t *testing.T) {
	var stderr bytes.Buffer
	var exitCode int

	onForceExit(&stderr, nil, func(code int) { exitCode = code })

	if exitCode != 1 {
		t.Errorf("exitFn called with code %d, want 1", exitCode)
	}
	if !strings.Contains(stderr.String(), "forcing immediate exit") {
		t.Errorf("stderr = %q, want message containing 'forcing immediate exit'", stderr.String())
	}
}

// TestOnForceExit_CallsCleanupBeforeExit verifies that the cleanup function
// is called before the exit message and exitFn.
func TestOnForceExit_CallsCleanupBeforeExit(t *testing.T) {
	var stderr bytes.Buffer
	var order []string

	cleanup := func() { order = append(order, "cleanup") }
	exitFn := func(code int) { order = append(order, "exit") }

	onForceExit(&stderr, cleanup, exitFn)

	if len(order) != 2 || order[0] != "cleanup" || order[1] != "exit" {
		t.Errorf("call order = %v, want [cleanup exit]", order)
	}
}

// TestOnForceExit_NilCleanup verifies that nil cleanup does not panic.
func TestOnForceExit_NilCleanup(t *testing.T) {
	var stderr bytes.Buffer
	called := false

	onForceExit(&stderr, nil, func(code int) { called = true })

	if !called {
		t.Error("exitFn was not called")
	}
}

// TestOnForceExit_CleanupPanicRecovery verifies that if cleanup() panics,
// exitFn is still called and the panic value is logged.
func TestOnForceExit_CleanupPanicRecovery(t *testing.T) {
	var stderr bytes.Buffer
	var exitCode int

	cleanup := func() { panic("cleanup exploded") }

	onForceExit(&stderr, cleanup, func(code int) { exitCode = code })

	if exitCode != 1 {
		t.Errorf("exitFn called with code %d, want 1", exitCode)
	}
	output := stderr.String()
	if !strings.Contains(output, "cleanup panicked: cleanup exploded") {
		t.Errorf("stderr = %q, want message containing panic value", output)
	}
	if !strings.Contains(output, "forcing immediate exit") {
		t.Errorf("stderr = %q, want message containing 'forcing immediate exit'", output)
	}
}

// TestDoCrawl_GracefulShutdownReturnsPartialResults exercises the real doCrawl
// function with a pre-canceled context against a live httptest server. The
// crawler returns context.Canceled with partial results, and doCrawl should
// convert that to (results, nil) with a "returning N partial results" message.
func TestDoCrawl_GracefulShutdownReturnsPartialResults(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body><a href="/page2">link</a></body></html>`)
	}))
	defer srv.Close()

	// Cancel context before calling doCrawl — triggers signal path in Crawl(),
	// which returns (partial, context.Canceled). doCrawl should return (partial, nil).
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var stderr bytes.Buffer
	opts := crawl.CrawlerOptions{
		Depth:    1,
		MaxPages: 100,
		Timeout:  30 * time.Second,
		Headless: false,
	}

	results, err := doCrawl(ctx, &stderr, srv.URL, opts)
	if err != nil {
		t.Fatalf("doCrawl() returned error %v, want nil (graceful shutdown)", err)
	}
	// The crawler may or may not collect results before context fires.
	// The key assertion: doCrawl did NOT return an error, proving the
	// graceful-shutdown condition (lines 127-129 of main.go) activated.
	if !strings.Contains(stderr.String(), "interrupt received") && !strings.Contains(stderr.String(), "returning") {
		t.Errorf("stderr = %q, want interrupt or partial-results message", stderr.String())
	}
	t.Logf("doCrawl returned %d partial results", len(results))
}

// TestDoCrawl_DeadlineExceededReturnsPartialResults exercises doCrawl with a
// context that hits its deadline. The crawler returns context.DeadlineExceeded
// with partial results, and doCrawl should convert that to (results, nil).
func TestDoCrawl_DeadlineExceededReturnsPartialResults(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body><a href="/page2">link</a></body></html>`)
	}))
	defer srv.Close()

	// Use a very short deadline so the crawl times out quickly.
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	// Let the deadline expire before calling doCrawl.
	time.Sleep(5 * time.Millisecond)

	var stderr bytes.Buffer
	opts := crawl.CrawlerOptions{
		Depth:    1,
		MaxPages: 100,
		Timeout:  30 * time.Second,
		Headless: false,
	}

	results, err := doCrawl(ctx, &stderr, srv.URL, opts)
	if err != nil {
		t.Fatalf("doCrawl() returned error %v, want nil (graceful shutdown on deadline)", err)
	}
	t.Logf("doCrawl returned %d partial results on DeadlineExceeded", len(results))
}

// TestSetupBrowserAndSignals_InvalidHeaderReturnsError verifies that invalid
// headers are rejected before launching Chrome.
func TestSetupBrowserAndSignals_InvalidHeaderReturnsError(t *testing.T) {
	_, err := setupBrowserAndSignals(
		[]string{"bad header"},
		CrawlOptions{Headless: false},
		crawl.CrawlerOptions{Depth: 1},
	)
	if err == nil {
		t.Fatal("setupBrowserAndSignals() expected error for invalid header, got nil")
	}
	if !strings.Contains(err.Error(), "invalid header") {
		t.Errorf("setupBrowserAndSignals() error = %q, want 'invalid header'", err.Error())
	}
}

func TestGenerateRequestID(t *testing.T) {
	t.Run("produces 32-char hex string", func(t *testing.T) {
		id, err := generateRequestID()
		if err != nil {
			t.Fatalf("generateRequestID() error = %v", err)
		}
		if len(id) != 32 {
			t.Errorf("generateRequestID() length = %d, want 32", len(id))
		}
		if _, err := hex.DecodeString(id); err != nil {
			t.Errorf("generateRequestID() returned non-hex string: %q", id)
		}
	})

	t.Run("produces unique values", func(t *testing.T) {
		ids := make(map[string]bool)
		for i := 0; i < 100; i++ {
			id, err := generateRequestID()
			if err != nil {
				t.Fatalf("generateRequestID() error = %v", err)
			}
			if ids[id] {
				t.Fatalf("generateRequestID() produced duplicate ID: %q", id)
			}
			ids[id] = true
		}
	})
}

func TestInjectRequestID(t *testing.T) {
	t.Run("default injects header", func(t *testing.T) {
		headers := map[string]string{}
		id, err := injectRequestID(headers, false)
		if err != nil {
			t.Fatal(err)
		}
		if len(id) != 32 {
			t.Errorf("request ID length = %d, want 32", len(id))
		}
		if headers[RequestIDHeader] != id {
			t.Errorf("header value = %q, want %q", headers[RequestIDHeader], id)
		}
	})

	t.Run("disabled skips injection", func(t *testing.T) {
		headers := map[string]string{}
		id, err := injectRequestID(headers, true)
		if err != nil {
			t.Fatal(err)
		}
		if id != "" {
			t.Errorf("expected empty ID when disabled, got %q", id)
		}
		if _, ok := headers[RequestIDHeader]; ok {
			t.Error("expected no header when disabled")
		}
	})

	t.Run("user-supplied value is preserved", func(t *testing.T) {
		headers := map[string]string{RequestIDHeader: "my-custom-id"}
		id, err := injectRequestID(headers, false)
		if err != nil {
			t.Fatal(err)
		}
		if id != "" {
			t.Errorf("expected empty ID when user-supplied, got %q", id)
		}
		if headers[RequestIDHeader] != "my-custom-id" {
			t.Errorf("user value overwritten: got %q", headers[RequestIDHeader])
		}
	})

	t.Run("user-supplied value with different casing is preserved", func(t *testing.T) {
		headers := map[string]string{"x-vespasian-request-id": "lowercase-id"}
		id, err := injectRequestID(headers, false)
		if err != nil {
			t.Fatal(err)
		}
		if id != "" {
			t.Errorf("expected empty ID when user-supplied, got %q", id)
		}
		// Should not inject canonical header when lowercase variant exists
		if _, exists := headers[RequestIDHeader]; exists {
			t.Error("should not inject canonical header when lowercase variant exists")
		}
		if headers["x-vespasian-request-id"] != "lowercase-id" {
			t.Errorf("user value overwritten: got %q", headers["x-vespasian-request-id"])
		}
	})
}

// TestSetupBrowserAndSignals_InjectsRequestID verifies that setupBrowserAndSignals
// injects the request ID header by default and returns it in the result.
func TestSetupBrowserAndSignals_InjectsRequestID(t *testing.T) {
	bs, err := setupBrowserAndSignals(
		nil,
		CrawlOptions{Headless: false},
		crawl.CrawlerOptions{Depth: 1},
	)
	if err != nil {
		t.Fatalf("setupBrowserAndSignals() error = %v", err)
	}
	defer bs.cleanup()

	if len(bs.requestID) != 32 {
		t.Errorf("requestID length = %d, want 32", len(bs.requestID))
	}
	if bs.opts.Headers[RequestIDHeader] != bs.requestID {
		t.Errorf("header = %q, want %q", bs.opts.Headers[RequestIDHeader], bs.requestID)
	}
}

// TestSetupBrowserAndSignals_NoRequestIDDisablesInjection verifies that
// NoRequestID=true prevents the header from being injected.
func TestSetupBrowserAndSignals_NoRequestIDDisablesInjection(t *testing.T) {
	bs, err := setupBrowserAndSignals(
		nil,
		CrawlOptions{Headless: false, NoRequestID: true},
		crawl.CrawlerOptions{Depth: 1},
	)
	if err != nil {
		t.Fatalf("setupBrowserAndSignals() error = %v", err)
	}
	defer bs.cleanup()

	if bs.requestID != "" {
		t.Errorf("requestID = %q, want empty", bs.requestID)
	}
	if _, ok := bs.opts.Headers[RequestIDHeader]; ok {
		t.Error("header should not be present when NoRequestID is true")
	}
}

// TestSetupBrowserAndSignals_UserSuppliedRequestIDPreserved verifies that a
// user-supplied X-Vespasian-Request-Id via -H takes precedence.
func TestSetupBrowserAndSignals_UserSuppliedRequestIDPreserved(t *testing.T) {
	bs, err := setupBrowserAndSignals(
		[]string{"X-Vespasian-Request-Id: user-value"},
		CrawlOptions{Headless: false},
		crawl.CrawlerOptions{Depth: 1},
	)
	if err != nil {
		t.Fatalf("setupBrowserAndSignals() error = %v", err)
	}
	defer bs.cleanup()

	if bs.requestID != "" {
		t.Errorf("requestID = %q, want empty (user-supplied)", bs.requestID)
	}
	if bs.opts.Headers[RequestIDHeader] != "user-value" {
		t.Errorf("header = %q, want %q", bs.opts.Headers[RequestIDHeader], "user-value")
	}
}

// TestDetectAPIType verifies that detectAPIType correctly identifies SOAP/WSDL
// traffic and falls back to REST for non-SOAP traffic.
func TestDetectAPIType(t *testing.T) {
	tests := []struct {
		name      string
		requests  []crawl.ObservedRequest
		threshold float64
		want      string
	}{
		{
			name:      "empty requests defaults to rest",
			requests:  nil,
			threshold: 0.5,
			want:      apiTypeREST,
		},
		{
			name: "REST JSON requests returns rest",
			requests: []crawl.ObservedRequest{
				{
					Method: "GET",
					URL:    "https://example.com/api/users",
					Headers: map[string]string{
						"Content-Type": "application/json",
					},
					Response: crawl.ObservedResponse{
						StatusCode:  200,
						ContentType: "application/json",
					},
				},
			},
			threshold: 0.5,
			want:      apiTypeREST,
		},
		{
			name: "SOAP request with SOAPAction header returns wsdl",
			requests: []crawl.ObservedRequest{
				{
					Method: "POST",
					URL:    "https://example.com/service",
					Headers: map[string]string{
						"Content-Type": "text/xml",
						"SOAPAction":   "http://example.com/GetUser",
					},
					Body: []byte(`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body/></soap:Envelope>`),
				},
			},
			threshold: 0.5,
			want:      apiTypeWSDL,
		},
		{
			name: "WSDL URL query param returns wsdl",
			requests: []crawl.ObservedRequest{
				{
					Method: "GET",
					URL:    "https://example.com/service?wsdl",
					Headers: map[string]string{
						"Content-Type": "text/xml",
					},
				},
			},
			threshold: 0.5,
			want:      apiTypeWSDL,
		},
		{
			name: "SOAP envelope in body returns wsdl",
			requests: []crawl.ObservedRequest{
				{
					Method: "POST",
					URL:    "https://example.com/service",
					Headers: map[string]string{
						"Content-Type": "text/xml",
					},
					Body: []byte(`<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><GetUser/></soap:Body></soap:Envelope>`),
				},
			},
			threshold: 0.5,
			want:      apiTypeWSDL,
		},
		{
			name: "majority SOAP traffic returns wsdl",
			requests: []crawl.ObservedRequest{
				{
					Method: "POST",
					URL:    "https://example.com/service",
					Headers: map[string]string{
						"Content-Type": "text/xml",
						"SOAPAction":   "http://example.com/GetUser",
					},
					Body: []byte(`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body/></soap:Envelope>`),
				},
				{
					Method: "POST",
					URL:    "https://example.com/service",
					Headers: map[string]string{
						"Content-Type": "text/xml",
						"SOAPAction":   "http://example.com/ListUsers",
					},
					Body: []byte(`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body/></soap:Envelope>`),
				},
			},
			threshold: 0.5,
			want:      apiTypeWSDL,
		},
		{
			name: "minority SOAP in mostly REST traffic returns rest",
			requests: []crawl.ObservedRequest{
				{
					Method: "GET",
					URL:    "https://example.com/api/users",
					Headers: map[string]string{
						"Accept": "application/json",
					},
					Response: crawl.ObservedResponse{
						StatusCode:  200,
						ContentType: "application/json",
						Body:        []byte(`[{"id":1}]`),
					},
				},
				{
					Method: "GET",
					URL:    "https://example.com/api/posts",
					Headers: map[string]string{
						"Accept": "application/json",
					},
					Response: crawl.ObservedResponse{
						StatusCode:  200,
						ContentType: "application/json",
						Body:        []byte(`[{"id":1}]`),
					},
				},
				{
					Method: "GET",
					URL:    "https://example.com/health",
					Headers: map[string]string{
						"Accept": "application/json",
					},
					Response: crawl.ObservedResponse{
						StatusCode:  200,
						ContentType: "text/xml",
					},
				},
			},
			threshold: 0.5,
			want:      apiTypeREST,
		},
		{
			name: "SOAP below threshold returns rest",
			requests: []crawl.ObservedRequest{
				{
					Method: "POST",
					URL:    "https://example.com/service",
					Headers: map[string]string{
						"Content-Type": "text/xml",
					},
					// This test verifies threshold gating: a weak WSDL signal
				// (content-type only, no SOAPAction/envelope) produces a
				// confidence around 0.85. Setting threshold=0.90 ensures
				// detection is rejected. If WSDLClassifier scoring changes,
				// this test may need threshold adjustment.
				},
			},
			threshold: 0.90,
			want:      apiTypeREST,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectAPIType(tt.requests, tt.threshold)
			if got != tt.want {
				t.Errorf("detectAPIType() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestGenerateSpec_WSDLType verifies that generateSpec works end-to-end with
// WSDL-classified traffic (the pipeline that was broken before the fix).
func TestGenerateSpec_WSDLType(t *testing.T) {
	requests := []crawl.ObservedRequest{
		{
			Method: "POST",
			URL:    "https://example.com/service",
			Headers: map[string]string{
				"Content-Type": "text/xml",
				"SOAPAction":   "http://example.com/GetUser",
			},
			Body: []byte(`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><GetUser xmlns="http://example.com/"/></soap:Body></soap:Envelope>`),
		},
	}

	spec, err := generateSpec(context.Background(), requests, generateSpecOptions{
		APIType:     apiTypeWSDL,
		Confidence:  0.5,
		Probe:       false,
		Deduplicate: true,
	})
	if err != nil {
		t.Fatalf("generateSpec(wsdl) unexpected error: %v", err)
	}
	if len(spec) == 0 {
		t.Fatal("generateSpec(wsdl) returned empty spec for SOAP traffic")
	}
	// Verify the output is WSDL, not REST/OpenAPI
	specStr := string(spec)
	if strings.Contains(specStr, "openapi") {
		t.Errorf("generateSpec(wsdl) produced OpenAPI spec instead of WSDL:\n%s", specStr)
	}
	if !strings.Contains(specStr, "definitions") {
		t.Errorf("generateSpec(wsdl) output missing WSDL definitions element:\n%s", specStr)
	}
}

// TestScanPipeline_WSDLDetection is an integration test verifying the full
// scan pipeline detects WSDL traffic and routes to the WSDL generator.
// This is the core regression test for LAB-1392.
func TestScanPipeline_WSDLDetection(t *testing.T) {
	// Simulate what happens inside ScanCmd.Run(): capture traffic, detect type,
	// generate spec — but without the actual crawl (which needs a live server).
	soapRequests := []crawl.ObservedRequest{
		{
			Method: "POST",
			URL:    "https://example.com/dvwsuserservice",
			Headers: map[string]string{
				"Content-Type": "text/xml; charset=utf-8",
				"SOAPAction":   "http://example.com/GetUser",
			},
			Body: []byte(`<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><GetUser xmlns="http://example.com/"/></soap:Body></soap:Envelope>`),
		},
	}

	// Step 1: Detect API type (this is the new logic)
	apiType := detectAPIType(soapRequests, 0.5)
	if apiType != apiTypeWSDL {
		t.Fatalf("detectAPIType() = %q for SOAP traffic, want %q", apiType, apiTypeWSDL)
	}

	// Step 2: Generate spec with detected type
	spec, err := generateSpec(context.Background(), soapRequests, generateSpecOptions{
		APIType:     apiType,
		Confidence:  0.5,
		Probe:       false,
		Deduplicate: true,
	})
	if err != nil {
		t.Fatalf("generateSpec(%s) error: %v", apiType, err)
	}
	if len(spec) == 0 {
		t.Fatal("scan pipeline produced empty output for SOAP traffic")
	}

	// Step 3: Verify output is WSDL, not REST/OpenAPI
	specStr := string(spec)
	if strings.Contains(specStr, "openapi") {
		t.Error("scan pipeline produced OpenAPI spec for SOAP traffic — should be WSDL")
	}
	if !strings.Contains(specStr, "definitions") {
		t.Error("scan pipeline output missing WSDL definitions element")
	}
}

// TestDetectAPIType_ExplicitOverride verifies that when --api-type is set
// explicitly (not "auto"), the scan command skips auto-detection and uses
// the user-provided type directly.
func TestDetectAPIType_ExplicitOverride(t *testing.T) {
	// SOAP traffic that would be auto-detected as WSDL
	soapRequests := []crawl.ObservedRequest{
		{
			Method: "POST",
			URL:    "https://example.com/service",
			Headers: map[string]string{
				"Content-Type": "text/xml",
				"SOAPAction":   "http://example.com/GetUser",
			},
			Body: []byte(`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body/></soap:Envelope>`),
		},
	}

	// With auto, should detect WSDL
	autoType := detectAPIType(soapRequests, 0.5)
	if autoType != apiTypeWSDL {
		t.Fatalf("auto detection = %q, want %q", autoType, apiTypeWSDL)
	}

	// With explicit REST override, generateSpec should produce REST output
	// (even though the traffic is SOAP — user explicitly chose REST)
	spec, err := generateSpec(context.Background(), soapRequests, generateSpecOptions{
		APIType:     apiTypeREST,
		Confidence:  0.5,
		Probe:       false,
		Deduplicate: true,
	})
	if err != nil {
		t.Fatalf("generateSpec(rest override) error: %v", err)
	}
	// REST classifier won't match SOAP traffic, so spec should be empty/nil
	if len(spec) > 0 && strings.Contains(string(spec), "definitions") {
		t.Error("explicit REST override produced WSDL output")
	}
}

// TestGenerateSpec_WSDLFromResponseBody verifies that the WSDL generator can
// extract operations from response bodies when request bodies are empty — the
// typical pattern for crawl-captured SOAP traffic.
func TestGenerateSpec_WSDLFromResponseBody(t *testing.T) {
	// Simulate crawl-captured traffic: the crawler observed a response to a
	// SOAP endpoint but didn't replay the request, so Body is empty.
	// The response body contains a SOAP envelope with an operation element.
	requests := []crawl.ObservedRequest{
		{
			Method: "GET",
			URL:    "https://example.com/dvwsuserservice",
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "text/xml",
				Body: []byte(`<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUserResponse xmlns="http://example.com/">
      <User><Name>Alice</Name></User>
    </GetUserResponse>
  </soap:Body>
</soap:Envelope>`),
			},
		},
	}

	spec, err := generateSpec(context.Background(), requests, generateSpecOptions{
		APIType:     apiTypeWSDL,
		Confidence:  0.5,
		Probe:       false,
		Deduplicate: true,
	})
	if err != nil {
		t.Fatalf("generateSpec(wsdl, response-body traffic) unexpected error: %v", err)
	}
	if len(spec) == 0 {
		t.Fatal("generateSpec(wsdl, response-body traffic) returned empty spec")
	}
	specStr := string(spec)
	if !strings.Contains(specStr, "definitions") {
		t.Errorf("output missing WSDL definitions element:\n%s", specStr)
	}
	if !strings.Contains(specStr, "GetUser") {
		t.Errorf("output missing inferred GetUser operation (stripped Response suffix):\n%s", specStr)
	}
}

// TestGenerateSpec_WSDLFromCrawledWSDLDocument verifies that when a ?wsdl URL
// is crawled and the response body is a valid WSDL document, the generator
// returns it directly (Phase 1) without needing to infer operations.
func TestGenerateSpec_WSDLFromCrawledWSDLDocument(t *testing.T) {
	validWSDL := []byte(`<?xml version="1.0"?>
<definitions name="TestService"
  xmlns="http://schemas.xmlsoap.org/wsdl/"
  xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
  xmlns:tns="http://example.com/"
  targetNamespace="http://example.com/">
  <message name="GetUserRequest"><part name="parameters" element="tns:GetUser"/></message>
  <message name="GetUserResponse"><part name="parameters" element="tns:GetUserResponse"/></message>
  <portType name="TestServicePortType">
    <operation name="GetUser">
      <input message="tns:GetUserRequest"/>
      <output message="tns:GetUserResponse"/>
    </operation>
  </portType>
</definitions>`)

	requests := []crawl.ObservedRequest{
		{
			Method: "GET",
			URL:    "https://example.com/dvwsuserservice?wsdl",
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "text/xml",
				Body:        validWSDL,
			},
		},
	}

	spec, err := generateSpec(context.Background(), requests, generateSpecOptions{
		APIType:     apiTypeWSDL,
		Confidence:  0.5,
		Probe:       false,
		Deduplicate: true,
	})
	if err != nil {
		t.Fatalf("generateSpec(wsdl, crawled ?wsdl doc) unexpected error: %v", err)
	}
	if len(spec) == 0 {
		t.Fatal("generateSpec(wsdl, crawled ?wsdl doc) returned empty spec")
	}
	// Should return the original WSDL document via Phase 1
	if !strings.Contains(string(spec), "TestService") {
		t.Errorf("expected original WSDL document to be returned, got:\n%s", string(spec))
	}
}

// TestScanPipeline_RealisticCrawlTraffic is a regression test for LAB-1392
// using traffic patterns that match real crawl output (empty request bodies,
// content-type only signals, SOAP response envelopes).
func TestScanPipeline_RealisticCrawlTraffic(t *testing.T) {
	// Realistic: crawler GETs a SOAP endpoint, observes text/xml response
	// with a SOAP envelope, but request body is empty.
	crawlTraffic := []crawl.ObservedRequest{
		{
			Method: "GET",
			URL:    "https://example.com/dvwsuserservice",
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "text/xml; charset=utf-8",
				Body: []byte(`<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><GetUserResponse xmlns="http://example.com/"><User><Name>Alice</Name></User></GetUserResponse></soap:Body></soap:Envelope>`),
			},
		},
	}

	// Step 1: Auto-detect should identify WSDL
	apiType := detectAPIType(crawlTraffic, 0.5)
	if apiType != apiTypeWSDL {
		t.Fatalf("detectAPIType() = %q, want %q", apiType, apiTypeWSDL)
	}

	// Step 2: Generate should produce WSDL output
	spec, err := generateSpec(context.Background(), crawlTraffic, generateSpecOptions{
		APIType:     apiType,
		Confidence:  0.5,
		Probe:       false,
		Deduplicate: true,
	})
	if err != nil {
		t.Fatalf("generateSpec(%s) error: %v", apiType, err)
	}
	if len(spec) == 0 {
		t.Fatal("scan pipeline produced empty output for realistic crawl SOAP traffic")
	}
	specStr := string(spec)
	if !strings.Contains(specStr, "definitions") {
		t.Error("output missing WSDL definitions element")
	}
	if !strings.Contains(specStr, "GetUser") {
		t.Error("output missing inferred GetUser operation from response body")
	}
}

// TestGenerateSpec_WSDLEmptyBodyNoResponse verifies that InferWSDL returns
// a clear error when request bodies are empty AND response bodies have no
// SOAP envelope — documenting the known limitation.
func TestGenerateSpec_WSDLEmptyBodyNoResponse(t *testing.T) {
	// Minimal SOAP signal: content-type only, no request body, no SOAP
	// envelope in response. This is the case the reviewer flagged.
	requests := []crawl.ObservedRequest{
		{
			Method: "GET",
			URL:    "https://example.com/service",
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "text/xml",
				Body:        []byte(`<html><body>Not a SOAP response</body></html>`),
			},
		},
	}

	_, err := generateSpec(context.Background(), requests, generateSpecOptions{
		APIType:     apiTypeWSDL,
		Confidence:  0.5,
		Probe:       false,
		Deduplicate: true,
	})
	if err == nil {
		t.Error("expected error for empty-body WSDL traffic with no SOAP response, got nil")
	}
}

// TestProbeWSDLDocument_ValidWSDL verifies that probeWSDLDocument fetches and
// validates a WSDL document from a ?wsdl endpoint.
func TestProbeWSDLDocument_ValidWSDL(t *testing.T) {
	validWSDL := `<?xml version="1.0"?>
<definitions name="Calculator"
  xmlns="http://schemas.xmlsoap.org/wsdl/"
  xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
  xmlns:tns="http://example.com/"
  targetNamespace="http://example.com/">
  <message name="AddRequest"><part name="parameters" element="tns:Add"/></message>
  <message name="AddResponse"><part name="parameters" element="tns:AddResponse"/></message>
  <portType name="CalculatorPortType">
    <operation name="Add">
      <input message="tns:AddRequest"/>
      <output message="tns:AddResponse"/>
    </operation>
  </portType>
</definitions>`

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery == "wsdl" {
			w.Header().Set("Content-Type", "text/xml")
			w.Write([]byte(validWSDL))
			return
		}
		// Base URL returns HTML (like real SOAP services)
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>Service Description</body></html>"))
	}))
	defer ts.Close()

	doc := probeWSDLDocument(ts.URL+"/calculator.asmx", true, false)
	if doc == nil {
		t.Fatal("probeWSDLDocument returned nil for valid WSDL endpoint")
	}
	if !strings.Contains(string(doc), "Calculator") {
		t.Errorf("expected WSDL document with Calculator service, got:\n%s", string(doc))
	}
}

// TestProbeWSDLDocument_NoWSDL verifies that probeWSDLDocument returns nil
// when the endpoint doesn't serve WSDL.
func TestProbeWSDLDocument_NoWSDL(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>Not a SOAP service</body></html>"))
	}))
	defer ts.Close()

	doc := probeWSDLDocument(ts.URL, true, false)
	if doc != nil {
		t.Errorf("probeWSDLDocument should return nil for non-WSDL endpoint, got %d bytes", len(doc))
	}
}

// TestProbeWSDLDocument_404 verifies that probeWSDLDocument returns nil
// when the ?wsdl endpoint returns an error status.
func TestProbeWSDLDocument_404(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	doc := probeWSDLDocument(ts.URL, true, false)
	if doc != nil {
		t.Error("probeWSDLDocument should return nil for 404 response")
	}
}

// TestScanPipeline_WSDLDiscoveryProbe is an end-to-end test verifying that
// the scan pipeline discovers a WSDL document via active probing even when
// crawl traffic contains no SOAP signals (the real-world scenario for LAB-1392).
func TestScanPipeline_WSDLDiscoveryProbe(t *testing.T) {
	validWSDL := `<?xml version="1.0"?>
<definitions name="Calculator"
  xmlns="http://schemas.xmlsoap.org/wsdl/"
  xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
  xmlns:tns="http://example.com/"
  targetNamespace="http://example.com/">
  <message name="AddRequest"><part name="parameters" element="tns:Add"/></message>
  <message name="AddResponse"><part name="parameters" element="tns:AddResponse"/></message>
  <portType name="CalculatorPortType">
    <operation name="Add">
      <input message="tns:AddRequest"/>
      <output message="tns:AddResponse"/>
    </operation>
  </portType>
</definitions>`

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery == "wsdl" {
			w.Header().Set("Content-Type", "text/xml")
			w.Write([]byte(validWSDL))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>Service</body></html>"))
	}))
	defer ts.Close()

	// Simulate crawl output: browser visited the HTML page, no SOAP signals
	crawlTraffic := []crawl.ObservedRequest{
		{
			Method: "GET",
			URL:    ts.URL + "/calculator.asmx",
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "text/html",
				Body:        []byte("<html><body>Service</body></html>"),
			},
		},
	}

	// Passive detection sees no WSDL — but active probe finds it
	passiveType := detectAPIType(crawlTraffic, 0.5)
	if passiveType != apiTypeREST {
		t.Fatalf("passive detection should return REST for HTML, got %q", passiveType)
	}

	// Active probe discovers the WSDL document
	wsdlDoc := probeWSDLDocument(ts.URL+"/calculator.asmx", true, false)
	if wsdlDoc == nil {
		t.Fatal("probeWSDLDocument should find the WSDL document")
	}

	// Inject synthetic request (same as ScanCmd.Run does)
	crawlTraffic = append(crawlTraffic, crawl.ObservedRequest{
		Method: "GET",
		URL:    ts.URL + "/calculator.asmx?wsdl",
		Response: crawl.ObservedResponse{
			StatusCode:  200,
			ContentType: "text/xml",
			Body:        wsdlDoc,
		},
	})

	// Generate WSDL spec
	spec, err := generateSpec(context.Background(), crawlTraffic, generateSpecOptions{
		APIType:     apiTypeWSDL,
		Confidence:  0.5,
		Probe:       false,
		Deduplicate: true,
	})
	if err != nil {
		t.Fatalf("generateSpec error: %v", err)
	}
	if len(spec) == 0 {
		t.Fatal("pipeline produced empty output")
	}
	if !strings.Contains(string(spec), "Calculator") {
		t.Errorf("expected WSDL with Calculator service, got:\n%s", string(spec))
	}
}

// TestAPITypeDisplayName verifies display name mapping for verbose output.
func TestAPITypeDisplayName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{apiTypeREST, "REST"},
		{apiTypeWSDL, "WSDL"},
		{apiTypeGraphQL, "GraphQL"},
		{"unknown", "unknown"},
	}
	for _, tt := range tests {
		got := apiTypeDisplayName(tt.input)
		if got != tt.want {
			t.Errorf("apiTypeDisplayName(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
