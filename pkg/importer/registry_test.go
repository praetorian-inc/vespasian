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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, imp)
			assert.Equal(t, tt.wantImporter, imp.Name())
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

	assert.Len(t, formats, len(expectedFormats))

	for _, format := range formats {
		assert.True(t, expectedFormats[format], "unexpected format: %s", format)
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
		assert.True(t, found, "missing expected format: %s", expected)
	}
}
