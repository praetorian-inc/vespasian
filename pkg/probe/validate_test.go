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

package probe

import (
	"context"
	"testing"

	"github.com/praetorian-inc/vespasian/pkg/ssrf"
)

// The full SSRF behavior is exercised by pkg/ssrf's tests. The wrapper layer
// here only needs to assert that it delegates and keeps the public API stable.

func TestValidateProbeURL_DelegatesToSSRF(t *testing.T) {
	cases := []struct {
		name   string
		url    string
		expect bool // true if delegation should report blocked
	}{
		{"public URL allowed", "https://8.8.8.8/api", false},
		{"private IP blocked", "http://127.0.0.1/api", true},
		{"link-local blocked", "http://169.254.169.254/", true},
		{"non-http scheme blocked", "ftp://example.com/", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wrapErr := ValidateProbeURL(tc.url)
			ssrfErr := ssrf.ValidateURL(tc.url)
			if (wrapErr == nil) != (ssrfErr == nil) {
				t.Errorf("wrapper/SSRF disagreement for %s: wrapper=%v ssrf=%v", tc.url, wrapErr, ssrfErr)
			}
			if (wrapErr != nil) != tc.expect {
				t.Errorf("ValidateProbeURL(%s) blocked=%v, want %v", tc.url, wrapErr != nil, tc.expect)
			}
		})
	}
}

func TestSSRFSafeDialContext_DelegatesToSSRF(t *testing.T) {
	// A loopback dial through the wrapper must fail with the same blocklist
	// behavior as ssrf.SafeDialContext.
	if _, err := SSRFSafeDialContext(context.Background(), "tcp", "127.0.0.1:1"); err == nil {
		t.Error("expected wrapper to reject loopback dial")
	}
	if _, err := ssrf.SafeDialContext(context.Background(), "tcp", "127.0.0.1:1"); err == nil {
		t.Error("expected ssrf.SafeDialContext to reject loopback dial")
	}
}
