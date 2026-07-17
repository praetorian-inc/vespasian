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
	"sync/atomic"
	"testing"
	"time"

	"github.com/alecthomas/kong"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/praetorian-inc/vespasian/internal/pipeline"
	"github.com/praetorian-inc/vespasian/pkg/analyze"
	"github.com/praetorian-inc/vespasian/pkg/crawl"
)

// jsonGetRequest builds a minimal GET ObservedRequest for the given URL with a
// JSON response.
func jsonGetRequest(url string) crawl.ObservedRequest {
	return crawl.ObservedRequest{
		Method:  "GET",
		URL:     url,
		Headers: map[string]string{"Content-Type": "application/json"},
		Response: crawl.ObservedResponse{
			StatusCode:  200,
			ContentType: "application/json",
		},
	}
}

// siblingSlugRequests returns two sibling REST requests whose only varying
// path segment looks like a content slug. Default normalization keeps both
// paths; --merge-slugs collapses them to /api/posts/{postSlug}.
func siblingSlugRequests() []crawl.ObservedRequest {
	return []crawl.ObservedRequest{
		jsonGetRequest("https://example.com/api/posts/hello-world"),
		jsonGetRequest("https://example.com/api/posts/my-trip"),
	}
}

// TestGenerateSpec_SlugThresholdValidation covers the CLI-boundary guard in
// pipeline.ClassifyProbeGenerate: --slug-threshold < 2 is rejected when merging is on, and
// ignored when merging is off.
func TestGenerateSpec_SlugThresholdValidation(t *testing.T) {
	requests := siblingSlugRequests()

	_, err := pipeline.ClassifyProbeGenerate(context.Background(), requests, pipeline.Options{
		APIType:       "rest",
		Confidence:    0.5,
		Probe:         false,
		Deduplicate:   true,
		MergeSlugs:    true,
		SlugThreshold: 1,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "--slug-threshold must be >= 2")

	off, err := pipeline.ClassifyProbeGenerate(context.Background(), requests, pipeline.Options{
		APIType:       "rest",
		Confidence:    0.5,
		Probe:         false,
		Deduplicate:   true,
		MergeSlugs:    false,
		SlugThreshold: 1,
	})
	require.NoError(t, err)
	// threshold=1 is ignored when merging is off: both siblings survive, no collapse.
	offStr := string(off)
	require.Contains(t, offStr, "/api/posts/hello-world")
	require.Contains(t, offStr, "/api/posts/my-trip")
	require.NotContains(t, offStr, "{postSlug}")
}

// TestGenerateSpec_MergeSlugsWiring proves the --merge-slugs flag flows
// cmd -> pipeline.ClassifyProbeGenerate -> GetWithOptions -> generator and changes the output.
func TestGenerateSpec_MergeSlugsWiring(t *testing.T) {
	// Include numeric-ID siblings to prove regex ID normalization is always
	// on, independent of --merge-slugs, through the full CLI wiring.
	requests := append(siblingSlugRequests(),
		jsonGetRequest("https://example.com/api/users/42"),
		jsonGetRequest("https://example.com/api/users/99"),
	)

	// SlugThreshold intentionally omitted: it is ignored when MergeSlugs is false.
	off, err := pipeline.ClassifyProbeGenerate(context.Background(), requests, pipeline.Options{
		APIType:     "rest",
		Confidence:  0.5,
		Probe:       false,
		Deduplicate: true,
		MergeSlugs:  false,
	})
	require.NoError(t, err)
	offStr := string(off)
	require.Contains(t, offStr, "/api/posts/hello-world")
	require.Contains(t, offStr, "/api/posts/my-trip")
	require.NotContains(t, offStr, "{postSlug}")
	require.Contains(t, offStr, "/api/users/{userId}")

	on, err := pipeline.ClassifyProbeGenerate(context.Background(), requests, pipeline.Options{
		APIType:       "rest",
		Confidence:    0.5,
		Probe:         false,
		Deduplicate:   true,
		MergeSlugs:    true,
		SlugThreshold: 2,
	})
	require.NoError(t, err)
	onStr := string(on)
	require.Contains(t, onStr, "/api/posts/{postSlug}")
	require.NotContains(t, onStr, "/api/posts/hello-world")
	require.NotContains(t, onStr, "/api/posts/my-trip")
	require.Contains(t, onStr, "/api/users/{userId}")
}

// TestValidateSlugThreshold covers the wsdl/graphql exemption and the
// apiType x mergeSlugs x threshold matrix for the slug-threshold guard.
func TestValidateSlugThreshold(t *testing.T) {
	tests := []struct {
		name          string
		apiType       string
		mergeSlugs    bool
		slugThreshold int
		wantErr       bool
	}{
		{"rest merge threshold 1 rejected", pipeline.APITypeREST, true, 1, true},
		{"rest merge threshold 0 rejected", pipeline.APITypeREST, true, 0, true},
		{"rest merge threshold 2 ok", pipeline.APITypeREST, true, 2, false},
		{"rest merge off threshold 1 ignored", pipeline.APITypeREST, false, 1, false},
		{"auto merge threshold 1 rejected (avoids wasted crawl)", pipeline.APITypeAuto, true, 1, true},
		{"wsdl merge threshold 1 exempt", pipeline.APITypeWSDL, true, 1, false},
		{"graphql merge threshold 1 exempt", pipeline.APITypeGraphQL, true, 1, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSlugThreshold(tt.apiType, tt.mergeSlugs, tt.slugThreshold)
			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), "--slug-threshold must be >= 2")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestGenerateCmdRun_RejectsSlugThresholdBeforeFileIO proves the slug-threshold
// guard fires before the capture file is opened: the missing file never
// produces an open error because validation rejects the flag first.
func TestGenerateCmdRun_RejectsSlugThresholdBeforeFileIO(t *testing.T) {
	cmd := &GenerateCmd{
		APIType:     pipeline.APITypeREST,
		Capture:     filepath.Join(t.TempDir(), "does-not-exist.json"),
		SlugOptions: SlugOptions{MergeSlugs: true, SlugThreshold: 1},
	}
	err := cmd.Run()
	require.Error(t, err)
	// Early-validation contract: fail on the flag before touching the (missing) file.
	require.Contains(t, err.Error(), "--slug-threshold must be >= 2")
	require.NotContains(t, err.Error(), "open capture file")
}

// TestScanCmdRun_RejectsSlugThresholdBeforeCrawl proves the slug-threshold
// guard fires before any browser/crawl. A malformed header would make
// setupBrowserAndSignals (which runs AFTER the guard, before the crawl) fail
// with a distinct "invalid header" error; asserting the error is EXACTLY the
// slug error proves the guard short-circuited first. If the early guard were
// removed, the header error would surface instead. No network/Chrome needed.
func TestScanCmdRun_RejectsSlugThresholdBeforeCrawl(t *testing.T) {
	cmd := &ScanCmd{
		URL:          "https://example.com",
		APIType:      pipeline.APITypeAuto,
		CrawlOptions: CrawlOptions{Header: []string{"no-colon-header"}},
		SlugOptions:  SlugOptions{MergeSlugs: true, SlugThreshold: 1},
	}
	err := cmd.Run()
	require.EqualError(t, err, "--slug-threshold must be >= 2")
}

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
			classifiers := pipeline.ClassifiersForType(tt.apiType)
			if len(classifiers) != tt.wantLen {
				t.Errorf("pipeline.ClassifiersForType(%q) got %d classifiers, want %d", tt.apiType, len(classifiers), tt.wantLen)
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
			_, err := pipeline.ClassifyProbeGenerate(context.Background(), requests, pipeline.Options{
				APIType:     tt.apiType,
				Confidence:  0.5,
				Probe:       tt.probe,
				Deduplicate: tt.deduplicate,
				Status:      statusWriter(tt.verbose),
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

	spec, err := pipeline.ClassifyProbeGenerate(context.Background(), []crawl.ObservedRequest{}, pipeline.Options{
		APIType:     "rest",
		Confidence:  0.5,
		Deduplicate: true,
	})
	if err != nil {
		t.Fatalf("pipeline.ClassifyProbeGenerate() unexpected error: %v", err)
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
	f, err := os.Create(capturePath) //nolint:gosec // G304: test file
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

// TestSlugOptions_Embedded verifies GenerateCmd and ScanCmd expose the embedded
// SlugOptions fields directly, the promotion their Run() methods rely on to
// forward c.MergeSlugs / c.SlugThreshold into generateSpec.
func TestSlugOptions_Embedded(t *testing.T) {
	g := &GenerateCmd{SlugOptions: SlugOptions{MergeSlugs: true, SlugThreshold: 4}}
	require.True(t, g.MergeSlugs)
	require.Equal(t, 4, g.SlugThreshold)

	s := &ScanCmd{SlugOptions: SlugOptions{MergeSlugs: true, SlugThreshold: 7}}
	require.True(t, s.MergeSlugs)
	require.Equal(t, 7, s.SlugThreshold)
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
			_, err := pipeline.ClassifyProbeGenerate(context.Background(), requests, pipeline.Options{
				APIType:      "rest",
				Confidence:   0.5,
				Probe:        tt.probe,
				Deduplicate:  true,
				AllowPrivate: true,
			})
			if (err != nil) != tt.wantErr {
				t.Errorf("pipeline.ClassifyProbeGenerate() error = %v, wantErr %v", err, tt.wantErr)
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
	f, err := os.Create(capturePath) //nolint:gosec // G304: test file
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
		Output:                filepath.Join(t.TempDir(), "spec.json"),
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

// TestGRPCInsecureSkipVerify_Embedded pins that GenerateCmd and ScanCmd both
// expose the GRPCInsecureSkipVerify kong field, catching a field removal or
// rename on either struct. It does NOT exercise Run() and cannot catch a
// dropped assignment of the field into pipeline.Options inside Run() (see
// main.go:541 and main.go:669) — that semantic wiring is covered by
// internal/pipeline's TestClassifyProbeGenerate_GRPCInsecureSkipVerify.
func TestGRPCInsecureSkipVerify_Embedded(t *testing.T) {
	g := &GenerateCmd{GRPCInsecureSkipVerify: true}
	require.True(t, g.GRPCInsecureSkipVerify)

	gDefault := &GenerateCmd{}
	require.False(t, gDefault.GRPCInsecureSkipVerify)

	s := &ScanCmd{GRPCInsecureSkipVerify: true}
	require.True(t, s.GRPCInsecureSkipVerify)

	sDefault := &ScanCmd{}
	require.False(t, sDefault.GRPCInsecureSkipVerify)
}

// TestGRPCInsecureSkipVerify_GenerateCmd is a smoke test proving
// GenerateCmd.Run() accepts GRPCInsecureSkipVerify without erroring on a
// non-gRPC (REST) capture. It does NOT prove the flag is forwarded into
// pipeline.Options inside Run() — a REST capture never reaches the gRPC
// probe path that consumes it, and pipeline.Options is built inline with no
// inspectable seam. That semantic behavior is covered by internal/pipeline's
// TestClassifyProbeGenerate_GRPCInsecureSkipVerify. Probe stays false (see
// below) since this test never exercises the gRPC probe path anyway.
func TestGRPCInsecureSkipVerify_GenerateCmd(t *testing.T) {
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
	f, err := os.Create(capturePath) //nolint:gosec // G304: test file
	if err != nil {
		t.Fatalf("failed to create temp capture file: %v", err)
	}
	if writeErr := crawl.WriteCapture(f, requests); writeErr != nil {
		_ = f.Close()
		t.Fatalf("failed to write capture: %v", writeErr)
	}
	_ = f.Close()

	cmd := &GenerateCmd{
		APIType: "rest",
		Capture: capturePath,
		// Output goes to a temp file so a successful Run() doesn't write the
		// generated spec to stdout during the test.
		Output: filepath.Join(t.TempDir(), "spec.json"),
		// Probe stays false: GRPCInsecureSkipVerify is consumed only by the
		// gRPC reflection probe, which this REST capture never reaches, so
		// Probe:true would add zero coverage of the flag while making a live
		// network call to example.com. Keep this smoke test hermetic.
		Probe:                  false,
		GRPCInsecureSkipVerify: true,
	}
	if err := cmd.Run(); err != nil {
		t.Errorf("GenerateCmd.Run() with GRPCInsecureSkipVerify unexpected error: %v", err)
	}
}

// TestGRPCInsecureSkipVerify_ReachesOptions closes the AC3 boundary gap: it
// asserts that c.GRPCInsecureSkipVerify actually reaches pipeline.Options
// (via GenerateCmd.options()) and pipeline.ScanOptions (via
// ScanCmd.scanOptions()) at the CLI boundary, so a dropped assignment inside
// either method is caught — unlike TestGRPCInsecureSkipVerify_Embedded
// (field-exposure only) and TestGRPCInsecureSkipVerify_GenerateCmd (a
// hermetic Run() smoke test that never reaches pipeline.Options
// construction on a REST capture).
func TestGRPCInsecureSkipVerify_ReachesOptions(t *testing.T) {
	require.True(t, (&GenerateCmd{GRPCInsecureSkipVerify: true}).options().GRPCInsecureSkipVerify,
		"GenerateCmd flag must reach pipeline.Options")
	require.False(t, (&GenerateCmd{GRPCInsecureSkipVerify: false}).options().GRPCInsecureSkipVerify)

	require.True(t, (&ScanCmd{GRPCInsecureSkipVerify: true}).scanOptions("rest", nil).GRPCInsecureSkipVerify,
		"ScanCmd flag must reach pipeline.ScanOptions")
	require.False(t, (&ScanCmd{GRPCInsecureSkipVerify: false}).scanOptions("rest", nil).GRPCInsecureSkipVerify)
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

	specWithout, err := pipeline.ClassifyProbeGenerate(context.Background(), requests, pipeline.Options{
		APIType:     "rest",
		Confidence:  0.5,
		Probe:       true,
		Deduplicate: true,
	})
	if err != nil {
		t.Fatalf("pipeline.ClassifyProbeGenerate(allowPrivate=false) unexpected error: %v", err)
	}

	specWith, err := pipeline.ClassifyProbeGenerate(context.Background(), requests, pipeline.Options{
		APIType:      "rest",
		Confidence:   0.5,
		Probe:        true,
		Deduplicate:  true,
		AllowPrivate: true,
	})
	if err != nil {
		t.Fatalf("pipeline.ClassifyProbeGenerate(allowPrivate=true) unexpected error: %v", err)
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
	spec, err := pipeline.ClassifyProbeGenerate(context.Background(), requests, pipeline.Options{
		APIType:      "rest",
		Confidence:   0.5,
		Probe:        true,
		Deduplicate:  true,
		AllowPrivate: true,
	})
	if err != nil {
		t.Fatalf("pipeline.ClassifyProbeGenerate(allowPrivate=true, probe=true) on loopback: %v", err)
	}
	if len(spec) == 0 {
		t.Error("pipeline.ClassifyProbeGenerate returned empty spec for loopback server with allowPrivate=true")
	}

	// Without allowPrivate, probes to loopback should be blocked by SSRF protection.
	// pipeline.ClassifyProbeGenerate still succeeds (probe errors are non-fatal), but we verify it
	// doesn't crash.
	_, err = pipeline.ClassifyProbeGenerate(context.Background(), requests, pipeline.Options{
		APIType:     "rest",
		Confidence:  0.5,
		Probe:       true,
		Deduplicate: true,
	})
	if err != nil {
		t.Fatalf("pipeline.ClassifyProbeGenerate(allowPrivate=false, probe=true) on loopback: %v", err)
	}
}

// TestDangerousAllowPrivate_WarningOnlyWhenProbing verifies the SSRF warning
// is only printed when both DangerousAllowPrivate and Probe are true.
// Drives GenerateCmd.Run (the actual code path where the warning is emitted)
// and covers both branches of the conditional at main.go:525-527.
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

	t.Run("Probe=false, no warning", func(t *testing.T) {
		capturePath := filepath.Join(t.TempDir(), "capture.json")
		f, err := os.Create(capturePath) //nolint:gosec // G304: test file
		if err != nil {
			t.Fatalf("failed to create temp capture file: %v", err)
		}
		if writeErr := crawl.WriteCapture(f, requests); writeErr != nil {
			_ = f.Close()
			t.Fatalf("failed to write capture: %v", writeErr)
		}
		_ = f.Close()

		oldStderr := os.Stderr
		r, w, _ := os.Pipe()
		os.Stderr = w
		defer func() { os.Stderr = oldStderr }()

		cmd := &GenerateCmd{
			APIType:               "rest",
			Capture:               capturePath,
			Output:                filepath.Join(t.TempDir(), "spec.json"),
			Probe:                 false,
			DangerousAllowPrivate: true,
		}
		if err := cmd.Run(); err != nil {
			t.Errorf("GenerateCmd.Run() unexpected error: %v", err)
		}

		w.Close() //nolint:gosec // G104: test code
		var buf bytes.Buffer
		io.Copy(&buf, r) //nolint:gosec // G104: test code
		os.Stderr = oldStderr

		if strings.Contains(buf.String(), "WARNING") {
			t.Errorf("SSRF warning should not be printed when probe is disabled; stderr: %q", buf.String())
		}
	})

	t.Run("Probe=true, warning printed", func(t *testing.T) {
		capturePath := filepath.Join(t.TempDir(), "capture.json")
		f, err := os.Create(capturePath) //nolint:gosec // G304: test file
		if err != nil {
			t.Fatalf("failed to create temp capture file: %v", err)
		}
		if writeErr := crawl.WriteCapture(f, requests); writeErr != nil {
			_ = f.Close()
			t.Fatalf("failed to write capture: %v", writeErr)
		}
		_ = f.Close()

		oldStderr := os.Stderr
		r, w, _ := os.Pipe()
		os.Stderr = w
		defer func() { os.Stderr = oldStderr }()

		cmd := &GenerateCmd{
			APIType:               "rest",
			Capture:               capturePath,
			Output:                filepath.Join(t.TempDir(), "spec.json"),
			Probe:                 true,
			DangerousAllowPrivate: true,
		}
		if err := cmd.Run(); err != nil {
			t.Errorf("GenerateCmd.Run() unexpected error: %v", err)
		}

		w.Close() //nolint:gosec // G104: test code
		var buf bytes.Buffer
		io.Copy(&buf, r) //nolint:gosec // G104: test code
		os.Stderr = oldStderr

		if !strings.Contains(buf.String(), "WARNING") {
			t.Errorf("SSRF warning should be printed when probe is enabled; stderr: %q", buf.String())
		}
	})
}

// TestDoCrawl_ProxyHonoredWithoutHeadless verifies that on the HTTP backend
// (--headless=false) doCrawl no longer warns-and-clears --proxy AND actually
// routes the crawl through the configured proxy (LAB-4011). A loopback
// recording proxy forwards to a loopback origin; a non-zero hit count proves
// the crawl path honored --proxy rather than silently ignoring it.
func TestDoCrawl_ProxyHonoredWithoutHeadless(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><body>ok</body></html>")
	}))
	defer origin.Close()

	// Minimal recording forward proxy on loopback: counts hits and forwards the
	// (plain http) request to the origin.
	var proxied atomic.Int64
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxied.Add(1)
		outReq, err := http.NewRequestWithContext(r.Context(), r.Method, r.RequestURI, nil) //nolint:gosec // test proxy forwards the received request URI
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		resp, err := http.DefaultTransport.RoundTrip(outReq)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close() //nolint:errcheck // test cleanup
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body) //nolint:gosec // test best-effort
	}))
	defer proxy.Close()

	var buf bytes.Buffer
	opts := crawl.CrawlerOptions{
		Headless: false,
		Proxy:    proxy.URL,
		MaxPages: 1,
		Timeout:  10 * time.Second,
		// The loopback origin passes the upfront scope check; --proxy relaxes
		// only the dial-time SSRF pin, not URL scope, so AllowPrivate is needed.
		AllowPrivate: true,
	}
	_, err := doCrawl(context.Background(), &buf, origin.URL, opts)
	if err != nil {
		t.Fatalf("doCrawl error = %v", err)
	}
	if strings.Contains(buf.String(), "only supported with headless browser mode") {
		t.Errorf("stderr still carries the removed warn-and-clear message: %q", buf.String())
	}
	if proxied.Load() == 0 {
		t.Error("proxy was not used; doCrawl did not route the crawl through --proxy")
	}
}

// TestDoCrawl_InvalidProxyRejected verifies doCrawl validates --proxy via
// ValidateProxyAddr BEFORE printing it, so an invalid, credential-bearing proxy
// is rejected with an error and the credentials never reach stderr (LAB-4011).
// The credential string is assembled at runtime to avoid a hardcoded-credential
// lint false positive on a deliberate test fixture.
func TestDoCrawl_InvalidProxyRejected(t *testing.T) {
	var buf bytes.Buffer
	badProxy := "http://" + "admin:s3cret" + "@127.0.0.1" // no port + embedded creds
	opts := crawl.CrawlerOptions{
		Headless: false,
		Proxy:    badProxy,
		Timeout:  5 * time.Second,
	}
	_, err := doCrawl(context.Background(), &buf, "https://example.com", opts)
	if err == nil {
		t.Fatal("expected error for proxy with embedded credentials, got nil")
	}
	if !strings.Contains(err.Error(), "embedded credentials") {
		t.Errorf("error = %q, want containing %q", err.Error(), "embedded credentials")
	}
	// Neither the username nor the password may leak to stderr or the error
	// (the port-less warning that would have printed opts.Proxy must never run
	// for an invalid proxy). Both halves of the fixture credential are checked.
	stderr := buf.String()
	errMsg := err.Error()
	if strings.Contains(stderr, "admin") || strings.Contains(stderr, "s3cret") ||
		strings.Contains(errMsg, "admin") || strings.Contains(errMsg, "s3cret") {
		t.Errorf("credentials leaked: stderr=%q err=%v", stderr, errMsg)
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
			want:      pipeline.APITypeREST,
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
			want:      pipeline.APITypeREST,
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
			want:      pipeline.APITypeWSDL,
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
			want:      pipeline.APITypeWSDL,
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
			want:      pipeline.APITypeWSDL,
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
			want:      pipeline.APITypeWSDL,
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
			want:      pipeline.APITypeREST,
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
			want:      pipeline.APITypeREST,
		},
		{
			name: "GraphQL POST to /graphql returns graphql",
			requests: []crawl.ObservedRequest{
				{
					Method: "POST",
					URL:    "https://example.com/graphql",
					Headers: map[string]string{
						"Content-Type": "application/json",
					},
					Body: []byte(`{"query":"{ users { id name } }"}`),
					Response: crawl.ObservedResponse{
						StatusCode:  200,
						ContentType: "application/json",
						Body:        []byte(`{"data":{"users":[{"id":"1","name":"Alice"}]}}`),
					},
				},
			},
			threshold: 0.5,
			want:      pipeline.APITypeGraphQL,
		},
		{
			name: "majority GraphQL traffic returns graphql",
			requests: []crawl.ObservedRequest{
				{
					Method: "POST",
					URL:    "https://example.com/graphql",
					Headers: map[string]string{
						"Content-Type": "application/json",
					},
					Body: []byte(`{"query":"{ users { id } }"}`),
					Response: crawl.ObservedResponse{
						StatusCode:  200,
						ContentType: "application/json",
						Body:        []byte(`{"data":{"users":[]}}`),
					},
				},
				{
					Method: "POST",
					URL:    "https://example.com/graphql",
					Headers: map[string]string{
						"Content-Type": "application/json",
					},
					Body: []byte(`{"query":"mutation { createUser(name: \"Bob\") { id } }"}`),
					Response: crawl.ObservedResponse{
						StatusCode:  200,
						ContentType: "application/json",
						Body:        []byte(`{"data":{"createUser":{"id":"2"}}}`),
					},
				},
				{
					// Non-API request (HTML page) — REST classifier won't match this,
					// so GraphQL count (2) ties REST count (2) and GraphQL wins via >=.
					Method: "GET",
					URL:    "https://example.com/",
					Response: crawl.ObservedResponse{
						StatusCode:  200,
						ContentType: "text/html",
						Body:        []byte(`<html><body>Welcome</body></html>`),
					},
				},
			},
			threshold: 0.5,
			want:      pipeline.APITypeGraphQL,
		},
		{
			name: "minority GraphQL in mostly REST traffic returns rest",
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
					Method: "POST",
					URL:    "https://example.com/graphql",
					Headers: map[string]string{
						"Content-Type": "application/json",
					},
					Body: []byte(`{"query":"{ users { id } }"}`),
					Response: crawl.ObservedResponse{
						StatusCode:  200,
						ContentType: "application/json",
						Body:        []byte(`{"data":{"users":[]}}`),
					},
				},
			},
			threshold: 0.5,
			want:      pipeline.APITypeREST,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pipeline.DetectAPIType(tt.requests, tt.threshold)
			if got != tt.want {
				t.Errorf("pipeline.DetectAPIType() = %q, want %q", got, tt.want)
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

	spec, err := pipeline.ClassifyProbeGenerate(context.Background(), requests, pipeline.Options{
		APIType:     pipeline.APITypeWSDL,
		Confidence:  0.5,
		Probe:       false,
		Deduplicate: true,
	})
	if err != nil {
		t.Fatalf("pipeline.ClassifyProbeGenerate(wsdl) unexpected error: %v", err)
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
	apiType := pipeline.DetectAPIType(soapRequests, 0.5)
	if apiType != pipeline.APITypeWSDL {
		t.Fatalf("pipeline.DetectAPIType() = %q for SOAP traffic, want %q", apiType, pipeline.APITypeWSDL)
	}

	// Step 2: Generate spec with detected type
	spec, err := pipeline.ClassifyProbeGenerate(context.Background(), soapRequests, pipeline.Options{
		APIType:     apiType,
		Confidence:  0.5,
		Probe:       false,
		Deduplicate: true,
	})
	if err != nil {
		t.Fatalf("pipeline.ClassifyProbeGenerate(%s) error: %v", apiType, err)
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
	autoType := pipeline.DetectAPIType(soapRequests, 0.5)
	if autoType != pipeline.APITypeWSDL {
		t.Fatalf("auto detection = %q, want %q", autoType, pipeline.APITypeWSDL)
	}

	// With explicit REST override, pipeline.ClassifyProbeGenerate should produce REST output
	// (even though the traffic is SOAP — user explicitly chose REST)
	spec, err := pipeline.ClassifyProbeGenerate(context.Background(), soapRequests, pipeline.Options{
		APIType:     pipeline.APITypeREST,
		Confidence:  0.5,
		Probe:       false,
		Deduplicate: true,
	})
	if err != nil {
		t.Fatalf("pipeline.ClassifyProbeGenerate(rest override) error: %v", err)
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

	spec, err := pipeline.ClassifyProbeGenerate(context.Background(), requests, pipeline.Options{
		APIType:     pipeline.APITypeWSDL,
		Confidence:  0.5,
		Probe:       false,
		Deduplicate: true,
	})
	if err != nil {
		t.Fatalf("pipeline.ClassifyProbeGenerate(wsdl, response-body traffic) unexpected error: %v", err)
	}
	if len(spec) == 0 {
		t.Fatal("pipeline.ClassifyProbeGenerate(wsdl, response-body traffic) returned empty spec")
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

	spec, err := pipeline.ClassifyProbeGenerate(context.Background(), requests, pipeline.Options{
		APIType:     pipeline.APITypeWSDL,
		Confidence:  0.5,
		Probe:       false,
		Deduplicate: true,
	})
	if err != nil {
		t.Fatalf("pipeline.ClassifyProbeGenerate(wsdl, crawled ?wsdl doc) unexpected error: %v", err)
	}
	if len(spec) == 0 {
		t.Fatal("pipeline.ClassifyProbeGenerate(wsdl, crawled ?wsdl doc) returned empty spec")
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
				Body:        []byte(`<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><GetUserResponse xmlns="http://example.com/"><User><Name>Alice</Name></User></GetUserResponse></soap:Body></soap:Envelope>`),
			},
		},
	}

	// Step 1: Auto-detect should identify WSDL
	apiType := pipeline.DetectAPIType(crawlTraffic, 0.5)
	if apiType != pipeline.APITypeWSDL {
		t.Fatalf("pipeline.DetectAPIType() = %q, want %q", apiType, pipeline.APITypeWSDL)
	}

	// Step 2: Generate should produce WSDL output
	spec, err := pipeline.ClassifyProbeGenerate(context.Background(), crawlTraffic, pipeline.Options{
		APIType:     apiType,
		Confidence:  0.5,
		Probe:       false,
		Deduplicate: true,
	})
	if err != nil {
		t.Fatalf("pipeline.ClassifyProbeGenerate(%s) error: %v", apiType, err)
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

	_, err := pipeline.ClassifyProbeGenerate(context.Background(), requests, pipeline.Options{
		APIType:     pipeline.APITypeWSDL,
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
			w.Write([]byte(validWSDL)) //nolint:gosec // G104: test code
			return
		}
		// Base URL returns HTML (like real SOAP services)
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>Service Description</body></html>")) //nolint:gosec // G104: test code
	}))
	defer ts.Close()

	doc := pipeline.ProbeWSDLDocument(context.Background(), ts.URL+"/calculator.asmx", true, nil)
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
		w.Write([]byte("<html><body>Not a SOAP service</body></html>")) //nolint:gosec // G104: test code
	}))
	defer ts.Close()

	doc := pipeline.ProbeWSDLDocument(context.Background(), ts.URL, true, nil)
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

	doc := pipeline.ProbeWSDLDocument(context.Background(), ts.URL, true, nil)
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
			w.Write([]byte(validWSDL)) //nolint:gosec // G104: test code
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>Service</body></html>")) //nolint:gosec // G104: test code
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
	passiveType := pipeline.DetectAPIType(crawlTraffic, 0.5)
	if passiveType != pipeline.APITypeREST {
		t.Fatalf("passive detection should return REST for HTML, got %q", passiveType)
	}

	// Active probe discovers the WSDL document
	wsdlDoc := pipeline.ProbeWSDLDocument(context.Background(), ts.URL+"/calculator.asmx", true, nil)
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
	spec, err := pipeline.ClassifyProbeGenerate(context.Background(), crawlTraffic, pipeline.Options{
		APIType:     pipeline.APITypeWSDL,
		Confidence:  0.5,
		Probe:       false,
		Deduplicate: true,
	})
	if err != nil {
		t.Fatalf("pipeline.ClassifyProbeGenerate error: %v", err)
	}
	if len(spec) == 0 {
		t.Fatal("pipeline produced empty output")
	}
	if !strings.Contains(string(spec), "Calculator") {
		t.Errorf("expected WSDL with Calculator service, got:\n%s", string(spec))
	}
}

// TestProbeWSDLDocument_URLConstruction verifies that probeWSDLDocument
// constructs the ?wsdl query correctly regardless of whether the input URL
// has no query, an existing query string, or a trailing bare "?".
func TestProbeWSDLDocument_URLConstruction(t *testing.T) {
	tests := []struct {
		name      string
		inputPath string // path+query appended to ts.URL
		wantQuery string // expected RawQuery seen by the server
	}{
		{
			name:      "plain URL",
			inputPath: "/service",
			wantQuery: "wsdl",
		},
		{
			name:      "URL with existing query",
			inputPath: "/service?foo=bar",
			wantQuery: "wsdl",
		},
		{
			name:      "URL with trailing question mark",
			inputPath: "/service?",
			wantQuery: "wsdl",
		},
	}

	validWSDL := `<?xml version="1.0"?>
<definitions name="Test"
  xmlns="http://schemas.xmlsoap.org/wsdl/"
  xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
  xmlns:tns="http://example.com/"
  targetNamespace="http://example.com/">
</definitions>`

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotQuery string
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotQuery = r.URL.RawQuery
				if r.URL.RawQuery == "wsdl" {
					w.Header().Set("Content-Type", "text/xml")
					w.Write([]byte(validWSDL)) //nolint:gosec // G104: test code
					return
				}
				http.NotFound(w, r)
			}))
			defer ts.Close()

			pipeline.ProbeWSDLDocument(context.Background(), ts.URL+tt.inputPath, true, nil)

			if gotQuery != tt.wantQuery {
				t.Errorf("probeWSDLDocument(%q) sent query %q, want %q", tt.inputPath, gotQuery, tt.wantQuery)
			}
		})
	}
}

// TestAPITypeDisplayName verifies display name mapping for verbose output.
func TestAPITypeDisplayName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{pipeline.APITypeREST, "REST"},
		{pipeline.APITypeWSDL, "WSDL"},
		{pipeline.APITypeGraphQL, "GraphQL"},
		{pipeline.APITypeGRPC, "gRPC"},
		{"unknown", "unknown"},
	}
	for _, tt := range tests {
		got := apiTypeDisplayName(tt.input)
		if got != tt.want {
			t.Errorf("apiTypeDisplayName(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// TestMaybeReplayJSExtracted_GatesOnProbe is the regression test for CR-1
// (CodeRabbit review #4215872430). The gate's job: --probe=false must NOT
// trigger any outbound HTTP from the JS-replay step. A silent removal of
// the gate (or moving the ReplayJSExtracted call outside it) would fail
// here.
func TestMaybeReplayJSExtracted_GatesOnProbe(t *testing.T) {
	// Server records every inbound path so we can assert exactly how many
	// HTTP requests the JS-replay step made under each probe setting.
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	// Capture containing a JS bundle whose extracted paths would trigger
	// probes IF the gate is open.
	requests := []crawl.ObservedRequest{
		{
			Method: "GET",
			URL:    srv.URL + "/static/js/main.js",
			Source: "katana",
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "application/javascript",
				Body:        []byte(`var u = "/api/v1/users"; var v = "/api/v1/items";`),
			},
		},
	}

	cfg := crawl.JSReplayConfig{
		Client:       srv.Client(),
		TargetURL:    srv.URL,
		AllowPrivate: true,
	}

	t.Run("Probe=false suppresses JS replay (no outbound HTTP)", func(t *testing.T) {
		hits = 0
		got := maybeReplayJSExtracted(context.Background(), requests, false, cfg)
		if hits != 0 {
			t.Errorf("Probe=false: expected 0 server hits, got %d", hits)
		}
		if len(got) != len(requests) {
			t.Errorf("Probe=false: expected requests passed through unchanged, got len=%d want %d", len(got), len(requests))
		}
		if got[0].URL != requests[0].URL {
			t.Errorf("Probe=false: first request URL changed: got %q want %q", got[0].URL, requests[0].URL)
		}
	})

	t.Run("Probe=true triggers JS replay (outbound HTTP fires)", func(t *testing.T) {
		hits = 0
		got := maybeReplayJSExtracted(context.Background(), requests, true, cfg)
		if hits == 0 {
			t.Errorf("Probe=true: expected ≥1 server hit, got 0 — gate may have flipped wrong")
		}
		// JS-extracted probes are appended to the input slice.
		if len(got) <= len(requests) {
			t.Errorf("Probe=true: expected probed requests appended, got len=%d (input was %d)", len(got), len(requests))
		}
	})
}

// TestMaybeReplayJSExtracted_DefaultGateOpen pins the AC1 zero-flag default
// (TEST-001): when --probe and --analyze-js are both left at their kong CLI
// defaults (true), GenerateCmd.Run's JS-replay gate (c.Probe && c.AnalyzeJS)
// is open, so maybeReplayJSExtracted must forward to crawl.ReplayJSExtracted
// instead of short-circuiting. Modeled on
// TestMaybeReplayJSExtracted_GatesOnProbe (same direct-call, no-capture-file,
// no-browser shape) but derives the gate boolean from a GenerateCmd struct
// populated with the flags' documented true defaults, rather than a bare
// literal, so a future default flip would be caught here.
func TestMaybeReplayJSExtracted_DefaultGateOpen(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	requests := []crawl.ObservedRequest{
		{
			Method: "GET",
			URL:    srv.URL + "/static/js/main.js",
			Source: "katana",
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "application/javascript",
				Body:        []byte(`var u = "/api/v1/users";`),
			},
		},
	}

	cfg := crawl.JSReplayConfig{
		Client:       srv.Client(),
		TargetURL:    srv.URL,
		AllowPrivate: true,
	}

	// Zero-flag two-stage default: parse `generate` with no flags so kong
	// applies the `default:"true"` tags to --probe and --analyze-js, and derive
	// the gate from the *parsed* struct rather than hardcoded literals. This is
	// what makes the test non-tautological: a future flip of either flag's
	// default to false makes the parsed value false, the gate closed, and this
	// test fail.
	var cli struct {
		Generate GenerateCmd `cmd:"" name:"generate"`
	}
	p := kong.Must(&cli, kong.Name("vespasian"))
	_, err := p.Parse([]string{"generate", "rest", "capture.json"})
	require.NoError(t, err, "parsing generate with no flags")
	require.True(t, cli.Generate.Probe, "--probe must default to true")
	require.True(t, cli.Generate.AnalyzeJS, "--analyze-js must default to true")

	gate := cli.Generate.Probe && cli.Generate.AnalyzeJS
	require.True(t, gate, "gate boolean (c.Probe && c.AnalyzeJS) must be open when both flags are at their documented true defaults")

	got := maybeReplayJSExtracted(context.Background(), requests, gate, cfg)
	require.NotZero(t, hits, "with the default gate open, maybeReplayJSExtracted must forward to crawl.ReplayJSExtracted and fire outbound HTTP")
	require.Greater(t, len(got), len(requests), "JS-replay must append the recovered endpoint to the requests slice when the default gate is open")
}

// TestGenerateSpec_ExtractsFormParametersIntoOpenAPI verifies the end-to-end promise of the
// HTML form extraction feature: a GET response whose HTML body contains a <form action="/login"
// method="POST"> must produce a generated OpenAPI spec that includes a POST /login path.
//
// This is the integration seam: crawl.ObservedRequest → analyze.ExtractForms →
// classify.RunClassifiers → REST generator → YAML output. Unit tests in pkg/analyze/ prove
// ExtractForms produces the correct synthetic request; this test proves that synthetic request
// flows all the way through generateSpec and appears in the final spec.
//
// Note on parameter assertions: the REST generator's InferSchema is JSON-only. URL-encoded form
// bodies (e.g., "username=&password=") are not valid JSON and produce no requestBody schema.
// Accordingly, this test asserts the weakest true statement: /login with a post operation
// exists in the spec. The presence of the path proves the full pipeline ran; schema assertions
// would require a form-aware schema inference layer that is out of scope for this ticket.
func TestGenerateSpec_ExtractsFormParametersIntoOpenAPI(t *testing.T) {
	htmlBody := `<html><body><form action="/login" method="POST"><input name="username"><input name="password" type="password"></form></body></html>`

	req := crawl.ObservedRequest{
		Method: "GET",
		URL:    "https://app.example.com/login",
		Source: "browser",
		Response: crawl.ObservedResponse{
			StatusCode:  200,
			ContentType: "text/html; charset=utf-8",
			Body:        []byte(htmlBody),
		},
	}

	requests := []crawl.ObservedRequest{req}
	requests = append(requests, analyze.ExtractForms(requests)...)

	spec, err := pipeline.ClassifyProbeGenerate(context.Background(), requests, pipeline.Options{
		APIType:     "rest",
		Confidence:  0.5,
		Probe:       false,
		Deduplicate: true,
	})

	if err != nil {
		t.Fatalf("pipeline.ClassifyProbeGenerate() unexpected error: %v", err)
	}
	if len(spec) == 0 {
		t.Fatal("pipeline.ClassifyProbeGenerate() returned empty spec; expected OpenAPI YAML with /login path")
	}

	// Unmarshal into a generic map so we can navigate without importing kin-openapi.
	var parsed map[string]interface{}
	if err := yaml.Unmarshal(spec, &parsed); err != nil {
		t.Fatalf("failed to unmarshal generated spec as YAML: %v", err)
	}

	// Assert paths section exists and contains /login.
	pathsRaw, ok := parsed["paths"]
	if !ok {
		t.Fatal("spec missing 'paths' key")
	}
	paths, ok := pathsRaw.(map[string]interface{})
	if !ok {
		t.Fatalf("'paths' is not a map, got %T", pathsRaw)
	}
	loginPathRaw, ok := paths["/login"]
	if !ok {
		t.Fatalf("spec paths do not contain '/login'; paths = %v", paths)
	}

	// Assert /login has a post operation.
	loginPath, ok := loginPathRaw.(map[string]interface{})
	if !ok {
		t.Fatalf("'/login' path item is not a map, got %T", loginPathRaw)
	}
	if _, ok := loginPath["post"]; !ok {
		t.Errorf("'/login' path does not have a 'post' operation; got operations: %v", loginPath)
	}
}

// TestGenerateSpec_ExtractsGETFormParametersIntoOpenAPI verifies that a GET
// form's input fields are surfaced as query parameters in the generated OpenAPI
// spec. This exercises the analyze → deduplicate → generate pipeline:
// ExtractForms synthesizes a GET /search?q= ObservedRequest, Deduplicate merges
// its QueryParams into a co-located classified endpoint, and the REST generator
// emits those QueryParams as OpenAPI parameters[].
//
// Note on classification threshold: synthetic static:html GET form requests
// score 0 confidence with the current RESTClassifier because they carry no
// response body, no API content-type, and no non-GET method — the three rules
// that drive confidence above zero. Using Confidence: 0.0 here is intentional:
// it lets the synthetic request through the classification gate so Deduplicate
// can merge its QueryParams into the co-located live GET /search request, which
// is classified normally at 0.85. This tests the parameter-propagation path
// without requiring a classifier change in this PR; improving static:html GET
// classification is tracked as a follow-up.
func TestGenerateSpec_ExtractsGETFormParametersIntoOpenAPI(t *testing.T) {
	htmlBody := `<html><body><form action="/search"><input name="q"></form></body></html>`

	requests := []crawl.ObservedRequest{
		// Request 1: a live browser capture of GET /search returning JSON. The JSON
		// response body gives the REST classifier 0.85 confidence, ensuring this
		// endpoint lands in the spec at any reasonable threshold.
		{
			Method: "GET",
			URL:    "https://app.example.com/search",
			Source: "browser",
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "application/json",
				Body:        []byte(`{"results":[]}`),
			},
		},
		// Request 2: the HTML page that contains the search form. ExtractForms
		// synthesizes a GET /search?q= entry from this response body; Deduplicate
		// merges it into Request 1's entry, adding "q" to its QueryParams.
		{
			Method: "GET",
			URL:    "https://app.example.com/",
			Source: "browser",
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "text/html; charset=utf-8",
				Body:        []byte(htmlBody),
			},
		},
	}

	requests = append(requests, analyze.ExtractForms(requests)...)

	spec, err := pipeline.ClassifyProbeGenerate(context.Background(), requests, pipeline.Options{
		APIType:     "rest",
		Confidence:  0.0, // See function comment: synthetic GET form requests score 0 confidence.
		Probe:       false,
		Deduplicate: true,
	})

	if err != nil {
		t.Fatalf("pipeline.ClassifyProbeGenerate() unexpected error: %v", err)
	}
	if len(spec) == 0 {
		t.Fatal("pipeline.ClassifyProbeGenerate() returned empty spec; expected OpenAPI YAML with /search path")
	}

	// Unmarshal into a generic map so we can navigate without importing kin-openapi.
	var parsed map[string]interface{}
	if err := yaml.Unmarshal(spec, &parsed); err != nil {
		t.Fatalf("failed to unmarshal generated spec as YAML: %v", err)
	}

	// Assert paths section exists and contains /search.
	pathsRaw, ok := parsed["paths"]
	if !ok {
		t.Fatal("spec missing 'paths' key")
	}
	paths, ok := pathsRaw.(map[string]interface{})
	if !ok {
		t.Fatalf("'paths' is not a map, got %T", pathsRaw)
	}
	searchPathRaw, ok := paths["/search"]
	if !ok {
		t.Fatalf("spec paths do not contain '/search'; paths = %v", paths)
	}

	// Assert /search has a get operation.
	searchPath, ok := searchPathRaw.(map[string]interface{})
	if !ok {
		t.Fatalf("'/search' path item is not a map, got %T", searchPathRaw)
	}
	getOpRaw, ok := searchPath["get"]
	if !ok {
		t.Fatalf("'/search' path does not have a 'get' operation; got operations: %v", searchPath)
	}

	// Assert the get operation has a parameter named "q". This is the core
	// assertion: the "q" field from the HTML form must appear in the generated
	// spec's query parameters list, proving the full analyze → deduplicate →
	// generate pipeline correctly surfaces GET form fields.
	getOp, ok := getOpRaw.(map[string]interface{})
	if !ok {
		t.Fatalf("'/search' get operation is not a map, got %T", getOpRaw)
	}
	parametersRaw, ok := getOp["parameters"]
	if !ok {
		t.Fatalf("'/search' get operation has no 'parameters' key; operation = %v", getOp)
	}
	parameters, ok := parametersRaw.([]interface{})
	if !ok {
		t.Fatalf("'/search' get parameters is not a slice, got %T", parametersRaw)
	}
	foundQ := false
	for _, pRaw := range parameters {
		p, ok := pRaw.(map[string]interface{})
		if !ok {
			continue
		}
		if p["name"] == "q" {
			foundQ = true
			break
		}
	}
	if !foundQ {
		t.Errorf("'/search' get parameters do not contain a parameter with name 'q'; parameters = %v", parameters)
	}
}

// --- QUAL-001: synthetic-only GET form does not create a path in the spec ---

// TestGenerateSpec_SyntheticOnlyGETFormYieldsNoPath verifies that a synthetic
// GET form request alone (with no co-located live classified request) does NOT
// produce a /search path in the generated OpenAPI spec at the default confidence
// threshold. This pins the contract that synthetic static:html GET requests
// (which score 0 confidence with the current RESTClassifier) need a co-located
// live request to land in the spec — synthetic-only is not sufficient at the
// default 0.5 confidence threshold.
func TestGenerateSpec_SyntheticOnlyGETFormYieldsNoPath(t *testing.T) {
	htmlBody := `<html><body><form action="/search"><input name="q"></form></body></html>`

	// Only the HTML landing page — no live browser GET /search request.
	requests := []crawl.ObservedRequest{
		{
			Method: "GET",
			URL:    "https://app.example.com/",
			Source: "browser",
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "text/html; charset=utf-8",
				Body:        []byte(htmlBody),
			},
		},
	}
	requests = append(requests, analyze.ExtractForms(requests)...)

	// Use the default confidence threshold (0.5). Synthetic static:html GET
	// form requests score 0 confidence, so they will not pass this gate.
	spec, err := pipeline.ClassifyProbeGenerate(context.Background(), requests, pipeline.Options{
		APIType:     "rest",
		Confidence:  0.5,
		Probe:       false,
		Deduplicate: true,
	})
	if err != nil {
		t.Fatalf("pipeline.ClassifyProbeGenerate() unexpected error: %v", err)
	}

	// Spec may be empty or contain paths for high-confidence endpoints — either
	// way /search must not appear, because no live GET /search request was
	// captured.
	if len(spec) == 0 {
		return // empty spec trivially satisfies the assertion
	}

	var parsed map[string]interface{}
	if err := yaml.Unmarshal(spec, &parsed); err != nil {
		t.Fatalf("failed to unmarshal generated spec as YAML: %v", err)
	}

	pathsRaw, ok := parsed["paths"]
	if !ok {
		return // no paths section → /search definitely absent
	}
	paths, ok := pathsRaw.(map[string]interface{})
	if !ok {
		return
	}
	if _, found := paths["/search"]; found {
		t.Errorf("spec contains /search path, but it should not: synthetic-only GET form request is insufficient for path creation at default confidence; paths = %v", paths)
	}
}

// QUAL-001 regression guard: pins that ExtractForms must run BEFORE detectAPIType.
// A static-only HTML landing page whose only API signal is a <form action="/api/…"
// method="POST"> has no REST signals raw, but classifies as REST after ExtractForms
// synthesizes the POST observation. A regression that reverts the ScanCmd.Run
// reorder would silently fall through here.
func TestDetectAPIType_StaticHTMLPostFormDrivesREST(t *testing.T) {
	// A SOAP request anchors the raw set to WSDL so that rawType != pipeline.APITypeREST.
	// Without this, detectAPIType falls back to REST even with zero signals,
	// making it impossible to observe the change ExtractForms causes.
	soapAnchor := crawl.ObservedRequest{
		Method: "POST",
		URL:    "https://example.com/service",
		Headers: map[string]string{
			"SOAPAction": "http://example.com/GetUser",
		},
	}

	// Landing page: static HTML with two POST forms targeting /api/* paths.
	// Two forms ensure that after ExtractForms the synthesized restCount (2)
	// exceeds wsdlCount (1), so detectAPIType flips from WSDL to REST.
	landingPage := crawl.ObservedRequest{
		Method: "GET",
		URL:    "https://example.com/",
		Response: crawl.ObservedResponse{
			StatusCode:  200,
			ContentType: "text/html",
			Body: []byte(`<!doctype html><html><body>` +
				`<form action="/api/login" method="POST">` +
				`<input name="username">` +
				`<input name="password">` +
				`</form>` +
				`<form action="/api/register" method="POST">` +
				`<input name="email">` +
				`<input name="password">` +
				`</form>` +
				`</body></html>`),
		},
	}

	raw := []crawl.ObservedRequest{soapAnchor, landingPage}
	rawType := pipeline.DetectAPIType(raw, 0.5)

	augmented := append([]crawl.ObservedRequest{}, raw...)
	augmented = append(augmented, analyze.ExtractForms(raw)...)
	augType := pipeline.DetectAPIType(augmented, 0.5)

	if augType != pipeline.APITypeREST {
		t.Errorf("pipeline.DetectAPIType(augmented) = %q, want %q", augType, pipeline.APITypeREST)
	}
	if rawType == augType {
		t.Errorf("ExtractForms must change classification: raw=%q augmented=%q (both same — pipeline reorder isn't load-bearing)", rawType, augType)
	}
}

// TestGenerateCmdRun_JSReplayGatedOnProbe proves that GenerateCmd.Run's
// LAB-3892 JS-replay step (crawl.ReplayJSExtracted, invoked via
// maybeReplayJSExtracted) is gated on BOTH c.Probe and c.AnalyzeJS. app.js
// reconstructs its one API path only via String.prototype.concat — the path
// never appears as a quoted literal — so static JS analysis
// (pipeline.Augment, gated by --analyze-js alone) cannot recover it from the
// capture (which does not carry app.js's body at all); only the active
// JS-replay step, which fetches app.js over HTTP and reconstructs the concat
// path, can produce it. This isolates the "&& c.AnalyzeJS" half of the gate:
// with --probe=true and --analyze-js=false, the gate must stay closed even
// though probing alone is enabled.
func TestGenerateCmdRun_JSReplayGatedOnProbe(t *testing.T) {
	const appJS = `function loadOrders(uid) { return fetch("/api/users/".concat(uid, "/orders")); }`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte(appJS))
		case "/api/users/0/orders":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"orders":[]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	// Capture: a single HTML entry referencing the external app.js, mirroring
	// a real crawl. The replay step discovers and fetches app.js itself.
	requests := []crawl.ObservedRequest{
		{
			Method: "GET",
			URL:    srv.URL + "/",
			Source: "katana",
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "text/html",
				Body:        []byte(`<!DOCTYPE html><html><head><script src="app.js"></script></head></html>`),
			},
		},
	}

	capturePath := filepath.Join(t.TempDir(), "capture.json")
	f, err := os.Create(capturePath) //nolint:gosec // G304: test file
	require.NoError(t, err)
	require.NoError(t, crawl.WriteCapture(f, requests))
	require.NoError(t, f.Close())

	// runGenerate drives GenerateCmd.Run() with the given gate settings and
	// returns the generated spec read back from the Output file (not
	// stdout).
	runGenerate := func(t *testing.T, probe, analyzeJS bool) string {
		t.Helper()
		outputPath := filepath.Join(t.TempDir(), "spec.yaml")
		cmd := &GenerateCmd{
			APIType:               "rest",
			Capture:               capturePath,
			Output:                outputPath,
			Probe:                 probe,
			AnalyzeJS:             analyzeJS,
			Deduplicate:           true,
			DangerousAllowPrivate: true,
		}
		require.NoError(t, cmd.Run())
		specBytes, err := os.ReadFile(outputPath) //nolint:gosec // G304: test file
		require.NoError(t, err)
		return string(specBytes)
	}

	t.Run("probe_and_analyze_recovers", func(t *testing.T) {
		spec := runGenerate(t, true, true)
		require.Contains(t, spec, "/api/users/", "concat-reconstructed path's prefix must reach the generated spec when both --probe and --analyze-js are true")
		require.Contains(t, spec, "/orders", "concat-reconstructed path's suffix must reach the generated spec when both --probe and --analyze-js are true")
	})

	t.Run("probe_false_skips", func(t *testing.T) {
		spec := runGenerate(t, false, true)
		require.NotContains(t, spec, "/orders", "with --probe=false, JS-replay must not run and the concat-reconstructed path must be absent")
	})

	t.Run("analyze_false_skips", func(t *testing.T) {
		spec := runGenerate(t, true, false)
		require.NotContains(t, spec, "/orders", "with --analyze-js=false, JS-replay must not run (gate is c.Probe && c.AnalyzeJS) and the concat-reconstructed path must be absent")
	})
}

// TestGenerateCmdRun_TwoStageRecoversConcatEndpoints mirrors pkg/crawl's
// TestReplayJSExtracted_ConcatStyle_EndToEnd, but drives the full two-stage
// crawl->generate workflow through GenerateCmd.Run instead of calling
// crawl.ReplayJSExtracted directly. It pins LAB-3892 acceptance criterion #1:
// the two-stage crawl | generate workflow recovers SPA endpoints that exist
// only inside JS bundles as concat-style strings — both the
// String.prototype.concat form and the +-operator chain form — while a
// reconstructed concat path that 404s is filtered out of the generated spec.
func TestGenerateCmdRun_TwoStageRecoversConcatEndpoints(t *testing.T) {
	// .concat() form, +-chain form, and a concat form whose reconstructed
	// path 404s (control for the filter). None of the full paths appear as
	// quoted literals — only the concat extractor can reconstruct them.
	const appJS = `
		function loadOrders(uid)  { return fetch("/api/users/".concat(uid, "/orders")); }
		function loadReviews(pid) { var u = "/api/products/" + pid + "/reviews"; return fetch(u); }
		function loadGone(x)      { return fetch("/api/missing/".concat(x, "/gone")); }
	`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte(appJS))
		case "/api/users/0/orders":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"orders":[]}`))
		case "/api/products/0/reviews":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"reviews":[]}`))
		// /api/missing/0/gone falls through to the 404 default.
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	requests := []crawl.ObservedRequest{
		{
			Method: "GET",
			URL:    srv.URL + "/",
			Source: "katana",
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "text/html",
				Body:        []byte(`<!DOCTYPE html><html><head><script src="app.js"></script></head></html>`),
			},
		},
	}

	capturePath := filepath.Join(t.TempDir(), "capture.json")
	f, err := os.Create(capturePath) //nolint:gosec // G304: test file
	require.NoError(t, err)
	require.NoError(t, crawl.WriteCapture(f, requests))
	require.NoError(t, f.Close())

	outputPath := filepath.Join(t.TempDir(), "spec.yaml")
	cmd := &GenerateCmd{
		APIType:               "rest",
		Capture:               capturePath,
		Output:                outputPath,
		Probe:                 true,
		AnalyzeJS:             true,
		Deduplicate:           true,
		DangerousAllowPrivate: true,
	}
	require.NoError(t, cmd.Run())

	specBytes, err := os.ReadFile(outputPath) //nolint:gosec // G304: test file
	require.NoError(t, err)

	// Parse the spec structurally instead of substring-matching, so the
	// assertions are robust to whatever normalized parameter name the REST
	// generator picks (e.g. {userId} vs {id}).
	var parsed map[string]interface{}
	require.NoError(t, yaml.Unmarshal(specBytes, &parsed))

	pathsRaw, ok := parsed["paths"]
	require.True(t, ok, "spec missing 'paths' key")
	paths, ok := pathsRaw.(map[string]interface{})
	require.True(t, ok, "'paths' is not a map, got %T", pathsRaw)

	var usersOrdersFound, productsReviewsFound, missingFound bool
	for p := range paths {
		if strings.HasPrefix(p, "/api/users/") && strings.HasSuffix(p, "/orders") {
			usersOrdersFound = true
		}
		if strings.HasPrefix(p, "/api/products/") && strings.HasSuffix(p, "/reviews") {
			productsReviewsFound = true
		}
		if strings.HasPrefix(p, "/api/missing") {
			missingFound = true
		}
	}

	require.True(t, usersOrdersFound, "String.prototype.concat path /api/users/.../orders must be reconstructed, probed, kept, and appear in generated spec paths: %v", paths)
	require.True(t, productsReviewsFound, "+-chain path /api/products/.../reviews must be reconstructed, probed, kept, and appear in generated spec paths: %v", paths)
	require.False(t, missingFound, "reconstructed concat path that 404s (/api/missing/...) must be dropped from generated spec paths: %v", paths)
}

// TestGenerateCmdRun_ForwardsHeaderToJSReplay pins LAB-3892 review R1: the
// generate command's --header/-H values must be forwarded to the same-origin
// JS-replay bundle fetches and probes, mirroring scan. The test server gates
// EVERY request behind a required auth header, so app.js (whose concat-only
// endpoint exists nowhere else) can only be fetched — and the endpoint only
// recovered — when the header is supplied.
func TestGenerateCmdRun_ForwardsHeaderToJSReplay(t *testing.T) {
	const appJS = `function loadOrders(uid) { return fetch("/api/users/".concat(uid, "/orders")); }`
	const authName = "X-Auth"
	const authValue = "s3kr3t"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(authName) != authValue {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte(appJS))
		case "/api/users/0/orders":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"orders":[]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	// Capture: one HTML entry referencing the external app.js. The replay step
	// discovers and fetches app.js itself (which needs the auth header).
	requests := []crawl.ObservedRequest{
		{
			Method: "GET",
			URL:    srv.URL + "/",
			Source: "katana",
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "text/html",
				Body:        []byte(`<!DOCTYPE html><html><head><script src="app.js"></script></head></html>`),
			},
		},
	}

	capturePath := filepath.Join(t.TempDir(), "capture.json")
	f, err := os.Create(capturePath) //nolint:gosec // G304: test file
	require.NoError(t, err)
	require.NoError(t, crawl.WriteCapture(f, requests))
	require.NoError(t, f.Close())

	runGenerate := func(t *testing.T, headers []string) string {
		t.Helper()
		outputPath := filepath.Join(t.TempDir(), "spec.yaml")
		cmd := &GenerateCmd{
			APIType:               "rest",
			Capture:               capturePath,
			Output:                outputPath,
			Probe:                 true,
			AnalyzeJS:             true,
			Deduplicate:           true,
			DangerousAllowPrivate: true,
			Header:                headers,
		}
		require.NoError(t, cmd.Run())
		specBytes, err := os.ReadFile(outputPath) //nolint:gosec // G304: test file
		require.NoError(t, err)
		return string(specBytes)
	}

	t.Run("without_header_cannot_recover", func(t *testing.T) {
		spec := runGenerate(t, nil)
		require.NotContains(t, spec, "/orders",
			"without --header the auth-gated app.js is a 401, so the concat endpoint must not be recovered")
	})

	t.Run("with_header_recovers", func(t *testing.T) {
		spec := runGenerate(t, []string{authName + ": " + authValue})
		require.Contains(t, spec, "/api/users/",
			"--header must be forwarded to the same-origin app.js fetch so the concat endpoint is recovered")
		require.Contains(t, spec, "/orders",
			"--header must be forwarded to the same-origin probe so the concat endpoint reaches the spec")
	})
}

// TestGenerateCmdRun_TargetURLOverridesOrigin pins LAB-3892 review R1/R2: the
// generate command's --target-url must override the capture-derived origin that
// JS-replay probes against. The only capture entry is a JS bundle recorded at a
// bogus third-party origin (as happens with imported/mixed-origin captures), so
// the default derivation would probe the concat endpoint against the wrong,
// unreachable host. --target-url pins the reachable origin, recovering it.
func TestGenerateCmdRun_TargetURLOverridesOrigin(t *testing.T) {
	const appJS = `function loadOrders(uid) { return fetch("/api/users/".concat(uid, "/orders")); }`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/users/0/orders":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"orders":[]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	// The bundle is captured inline at a bogus origin, so replay processes its
	// body without fetching. The extracted /api/users/0/orders is RELATIVE and
	// gets probed against the derived origin — bogus by default, srv via override.
	requests := []crawl.ObservedRequest{
		{
			Method: "GET",
			URL:    "http://cdn.example.invalid/app.js",
			Source: "burp",
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "application/javascript",
				Body:        []byte(appJS),
			},
		},
	}

	capturePath := filepath.Join(t.TempDir(), "capture.json")
	f, err := os.Create(capturePath) //nolint:gosec // G304: test file
	require.NoError(t, err)
	require.NoError(t, crawl.WriteCapture(f, requests))
	require.NoError(t, f.Close())

	runGenerate := func(t *testing.T, targetURL string) string {
		t.Helper()
		outputPath := filepath.Join(t.TempDir(), "spec.yaml")
		cmd := &GenerateCmd{
			APIType:               "rest",
			Capture:               capturePath,
			Output:                outputPath,
			Probe:                 true,
			AnalyzeJS:             true,
			Deduplicate:           true,
			DangerousAllowPrivate: true,
			TargetURL:             targetURL,
		}
		require.NoError(t, cmd.Run())
		specBytes, err := os.ReadFile(outputPath) //nolint:gosec // G304: test file
		require.NoError(t, err)
		return string(specBytes)
	}

	t.Run("without_target_url_probes_wrong_origin", func(t *testing.T) {
		spec := runGenerate(t, "")
		require.NotContains(t, spec, "/orders",
			"without --target-url the endpoint is probed against the capture's bogus origin and must not be recovered")
	})

	t.Run("with_target_url_recovers", func(t *testing.T) {
		spec := runGenerate(t, srv.URL)
		require.Contains(t, spec, "/api/users/",
			"--target-url must pin the reachable origin so the concat endpoint is probed there and recovered")
		require.Contains(t, spec, "/orders",
			"--target-url must pin the reachable origin so the concat endpoint reaches the spec")
	})
}

// TestGenerateCmdRun_RejectsMalformedTargetURL pins the fail-fast guard: a
// non-empty but malformed --target-url must error rather than silently fall
// back to the capture-derived origin heuristic (which would reintroduce the
// wrong-origin footgun --target-url exists to prevent).
func TestGenerateCmdRun_RejectsMalformedTargetURL(t *testing.T) {
	requests := []crawl.ObservedRequest{
		{
			Method: "GET",
			URL:    "http://app.example.test/",
			Source: "katana",
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "text/html",
				Body:        []byte(`<!DOCTYPE html><html></html>`),
			},
		},
	}
	capturePath := filepath.Join(t.TempDir(), "capture.json")
	f, err := os.Create(capturePath) //nolint:gosec // G304: test file
	require.NoError(t, err)
	require.NoError(t, crawl.WriteCapture(f, requests))
	require.NoError(t, f.Close())

	for _, bad := range []string{"host-only-no-scheme:8080", "://missing-scheme", "not a url"} {
		t.Run(bad, func(t *testing.T) {
			cmd := &GenerateCmd{
				APIType:               "rest",
				Capture:               capturePath,
				Output:                filepath.Join(t.TempDir(), "spec.yaml"),
				Probe:                 true,
				AnalyzeJS:             true,
				Deduplicate:           true,
				DangerousAllowPrivate: true,
				TargetURL:             bad,
			}
			err := cmd.Run()
			require.Error(t, err, "malformed --target-url must be rejected, not silently ignored")
			require.Contains(t, err.Error(), "invalid --target-url")
		})
	}
}

// TestGenerateCmdRun_RejectsMalformedHeader pins the fail-fast guard: a
// malformed --header value must be rejected by parseHeaders and surfaced as
// an "invalid --header" error, not silently ignored or passed through to the
// JS-replay fetches/probes.
func TestGenerateCmdRun_RejectsMalformedHeader(t *testing.T) {
	requests := []crawl.ObservedRequest{
		{
			Method: "GET",
			URL:    "http://app.example.test/",
			Source: "katana",
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "text/html",
				Body:        []byte(`<!DOCTYPE html><html></html>`),
			},
		},
	}
	capturePath := filepath.Join(t.TempDir(), "capture.json")
	f, err := os.Create(capturePath) //nolint:gosec // G304: test file
	require.NoError(t, err)
	require.NoError(t, crawl.WriteCapture(f, requests))
	require.NoError(t, f.Close())

	for _, bad := range []string{"NoColonHeader", "", "  : emptyname"} {
		t.Run(bad, func(t *testing.T) {
			cmd := &GenerateCmd{
				APIType:               "rest",
				Capture:               capturePath,
				Output:                filepath.Join(t.TempDir(), "spec.yaml"),
				Probe:                 true,
				AnalyzeJS:             true,
				Deduplicate:           true,
				DangerousAllowPrivate: true,
				Header:                []string{bad},
			}
			err := cmd.Run()
			require.Error(t, err, "malformed --header must be rejected, not silently ignored")
			require.Contains(t, err.Error(), "invalid --header")
		})
	}
}
