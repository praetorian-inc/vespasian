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
	"strings"
	"testing"
)

func TestGet(t *testing.T) {
	tests := []struct {
		name       string
		format     string
		wantName   string
		wantErr    bool
		errContain string
	}{
		{"burp", "burp", "burp", false, ""},
		{"har", "har", "har", false, ""},
		{"mitmproxy", "mitmproxy", "mitmproxy", false, ""},
		{"unsupported", "wireshark", "", true, "unsupported import format"},
		{"empty", "", "", true, "unsupported import format"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			imp, err := Get(tt.format)
			if (err != nil) != tt.wantErr {
				t.Errorf("Get(%q) error = %v, wantErr %v", tt.format, err, tt.wantErr)
				return
			}
			if tt.wantErr {
				if !strings.Contains(err.Error(), tt.errContain) {
					t.Errorf("Get(%q) error = %q, want containing %q", tt.format, err, tt.errContain)
				}
				return
			}
			if imp.Name() != tt.wantName {
				t.Errorf("Get(%q).Name() = %q, want %q", tt.format, imp.Name(), tt.wantName)
			}
		})
	}
}
