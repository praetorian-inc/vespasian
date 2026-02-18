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

package generate

import (
	"strings"
	"testing"
)

func TestGet(t *testing.T) {
	tests := []struct {
		name       string
		apiType    string
		wantType   string
		wantErr    bool
		errContain string
	}{
		{"rest", "rest", "rest", false, ""},
		{"unsupported graphql", "graphql", "", true, "unsupported API type"},
		{"empty", "", "", true, "unsupported API type"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen, err := Get(tt.apiType)
			if (err != nil) != tt.wantErr {
				t.Errorf("Get(%q) error = %v, wantErr %v", tt.apiType, err, tt.wantErr)
				return
			}
			if tt.wantErr {
				if !strings.Contains(err.Error(), tt.errContain) {
					t.Errorf("Get(%q) error = %q, want containing %q", tt.apiType, err, tt.errContain)
				}
				return
			}
			if gen.APIType() != tt.wantType {
				t.Errorf("Get(%q).APIType() = %q, want %q", tt.apiType, gen.APIType(), tt.wantType)
			}
		})
	}
}
