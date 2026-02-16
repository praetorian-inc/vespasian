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
	"testing"
)

func TestValidateProbeURL_PublicURL(t *testing.T) {
	err := validateProbeURL("https://example.com/api")
	if err != nil {
		t.Errorf("expected public URL to be allowed, got error: %v", err)
	}
}

func TestValidateProbeURL_BlocksPrivateIPs(t *testing.T) {
	cases := []struct {
		name string
		url  string
	}{
		{"loopback", "http://127.0.0.1/api"},
		{"rfc1918-10", "http://10.0.0.1/api"},
		{"rfc1918-172", "http://172.16.0.1/api"},
		{"rfc1918-192", "http://192.168.1.1/api"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateProbeURL(tc.url)
			if err == nil {
				t.Errorf("expected %s to be blocked, got nil error", tc.url)
			}
		})
	}
}

func TestValidateProbeURL_BlocksLinkLocal(t *testing.T) {
	// AWS metadata endpoint
	err := validateProbeURL("http://169.254.169.254/latest/meta-data/")
	if err == nil {
		t.Error("expected link-local (AWS metadata) to be blocked, got nil error")
	}
}

func TestValidateProbeURL_BlocksNonHTTPSchemes(t *testing.T) {
	cases := []struct {
		name string
		url  string
	}{
		{"ftp", "ftp://example.com/file"},
		{"file", "file:///etc/passwd"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateProbeURL(tc.url)
			if err == nil {
				t.Errorf("expected scheme %q to be blocked, got nil error", tc.name)
			}
		})
	}
}

func TestValidateProbeURL_InvalidURL(t *testing.T) {
	err := validateProbeURL("://not-a-url")
	if err == nil {
		t.Error("expected invalid URL to return error, got nil")
	}
}

func TestValidateProbeURL_BlocksIPv6Loopback(t *testing.T) {
	err := validateProbeURL("http://[::1]/api")
	if err == nil {
		t.Error("expected IPv6 loopback to be blocked, got nil error")
	}
}
