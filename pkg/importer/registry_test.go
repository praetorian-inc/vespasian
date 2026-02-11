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
	"testing"
)

func TestGet(t *testing.T) {
	tests := []struct {
		name         string
		format       string
		wantErr      bool
		wantImporter string
	}{
		{
			name:         "burp format",
			format:       "burp",
			wantErr:      false,
			wantImporter: "burp",
		},
		{
			name:         "har format",
			format:       "har",
			wantErr:      false,
			wantImporter: "har",
		},
		{
			name:         "mitmproxy format",
			format:       "mitmproxy",
			wantErr:      false,
			wantImporter: "mitmproxy",
		},
		{
			name:    "unsupported format",
			format:  "unknown",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			imp, err := Get(tt.format)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Get(%q) expected error, got nil", tt.format)
				}
				return
			}

			if err != nil {
				t.Errorf("Get(%q) unexpected error: %v", tt.format, err)
				return
			}

			if imp == nil {
				t.Errorf("Get(%q) returned nil importer", tt.format)
				return
			}

			if imp.Name() != tt.wantImporter {
				t.Errorf("Get(%q).Name() = %q, want %q", tt.format, imp.Name(), tt.wantImporter)
			}
		})
	}
}

func TestSupportedFormats(t *testing.T) {
	formats := SupportedFormats()

	// Check we have expected formats
	expectedFormats := map[string]bool{
		"burp":      true,
		"har":       true,
		"mitmproxy": true,
	}

	if len(formats) != len(expectedFormats) {
		t.Errorf("SupportedFormats() returned %d formats, want %d", len(formats), len(expectedFormats))
	}

	for _, format := range formats {
		if !expectedFormats[format] {
			t.Errorf("SupportedFormats() returned unexpected format: %q", format)
		}
	}

	// Verify all expected formats are present
	for expected := range expectedFormats {
		found := false
		for _, format := range formats {
			if format == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("SupportedFormats() missing expected format: %q", expected)
		}
	}
}
