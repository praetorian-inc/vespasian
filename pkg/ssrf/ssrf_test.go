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

package ssrf

import (
	"context"
	"net"
	"testing"
)

func TestValidateURL_PublicURL(t *testing.T) {
	if err := ValidateURL("https://example.com/api"); err != nil {
		t.Errorf("expected public URL to be allowed, got error: %v", err)
	}
}

func TestValidateURL_BlocksPrivateIPs(t *testing.T) {
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
			if err := ValidateURL(tc.url); err == nil {
				t.Errorf("expected %s to be blocked", tc.url)
			}
		})
	}
}

func TestValidateURL_BlocksLinkLocal(t *testing.T) {
	if err := ValidateURL("http://169.254.169.254/latest/meta-data/"); err == nil {
		t.Error("expected link-local (AWS metadata) to be blocked")
	}
}

func TestValidateURL_BlocksNonHTTPSchemes(t *testing.T) {
	cases := []string{"ftp://example.com/file", "file:///etc/passwd"}
	for _, raw := range cases {
		if err := ValidateURL(raw); err == nil {
			t.Errorf("expected %s to be blocked", raw)
		}
	}
}

func TestValidateURL_InvalidURL(t *testing.T) {
	if err := ValidateURL("://not-a-url"); err == nil {
		t.Error("expected invalid URL to return error")
	}
}

func TestValidateURL_BlocksIPv6Loopback(t *testing.T) {
	if err := ValidateURL("http://[::1]/api"); err == nil {
		t.Error("expected IPv6 loopback to be blocked")
	}
}

func TestValidateURL_BlocksUnspecifiedIPv4(t *testing.T) {
	if err := ValidateURL("http://0.0.0.0/api"); err == nil {
		t.Error("expected 0.0.0.0 to be blocked")
	}
}

func TestValidateURL_BlocksUnspecifiedIPv6(t *testing.T) {
	if err := ValidateURL("http://[::]/api"); err == nil {
		t.Error("expected [::] (IPv6 unspecified) to be blocked")
	}
}

func TestIsPrivateIP(t *testing.T) {
	cases := []struct {
		ip      string
		private bool
	}{
		{"127.0.0.1", true},
		{"10.5.5.5", true},
		{"192.168.0.1", true},
		{"172.16.0.1", true},
		{"169.254.169.254", true},
		{"::1", true},
		{"0.0.0.0", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
	}
	for _, tc := range cases {
		got := IsPrivateIP(net.ParseIP(tc.ip))
		if got != tc.private {
			t.Errorf("IsPrivateIP(%s) = %v, want %v", tc.ip, got, tc.private)
		}
	}
}

func TestSafeDialContext_RejectsPrivate(t *testing.T) {
	// Direct dial to a loopback host:port should fail before any TCP
	// connection is attempted.
	_, err := SafeDialContext(context.Background(), "tcp", "127.0.0.1:1")
	if err == nil {
		t.Error("expected SafeDialContext to reject loopback dial")
	}
}
