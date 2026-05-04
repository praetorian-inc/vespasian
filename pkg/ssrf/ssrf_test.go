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
	"strings"
	"testing"
)

func TestValidateURL_PublicURL(t *testing.T) {
	// Use a public IP literal (Google DNS) so the test does not depend on
	// outbound DNS or internet access — same code path as a public hostname,
	// just without the lookup.
	if err := ValidateURL("https://8.8.8.8/api"); err != nil {
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
		{"cgnat", "http://100.64.0.1/api"},
		{"this-network", "http://0.1.2.3/api"},
		{"multicast", "http://224.0.0.1/api"},
		{"reserved-class-e", "http://240.0.0.1/api"},
		{"broadcast", "http://255.255.255.255/api"},
		{"ietf-protocol", "http://192.0.0.1/api"},
		{"benchmarking", "http://198.18.0.1/api"},
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

func TestValidateURL_BlocksIPv6Reserved(t *testing.T) {
	cases := []string{
		"http://[::1]/api",            // loopback
		"http://[fe80::1]/api",        // link-local
		"http://[fc00::1]/api",        // ULA
		"http://[fd00:ec2::254]/api",  // AWS IMDSv2 IPv6
		"http://[2002:7f00::]/api",    // 6to4 wrapping 127.0.0.0
		"http://[64:ff9b::a00:1]/api", // NAT64 wrapping 10.0.0.1
	}
	for _, raw := range cases {
		if err := ValidateURL(raw); err == nil {
			t.Errorf("expected %s to be blocked", raw)
		}
	}
}

func TestValidateURL_BlocksIPv4MappedIPv6(t *testing.T) {
	// ::ffff:127.0.0.1 should be blocked because the IP is folded into IPv4.
	if err := ValidateURL("http://[::ffff:127.0.0.1]/api"); err == nil {
		t.Error("expected IPv4-mapped IPv6 loopback to be blocked")
	}
	if err := ValidateURL("http://[::ffff:10.0.0.1]/api"); err == nil {
		t.Error("expected IPv4-mapped IPv6 RFC1918 to be blocked")
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

func TestValidateURLContext_HonorsDeadline(t *testing.T) {
	// A canceled ctx must cause LookupIPAddr to fail for non-IP hostnames.
	// Use TEST-NET-2 (RFC 5737 documentation range) since we want a host
	// that requires DNS resolution; the lookup will fail-fast on the
	// canceled ctx before any actual resolver call.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := ValidateURLContext(ctx, "https://documentation.test/api")
	if err == nil {
		t.Error("expected canceled context to fail validation for non-IP host")
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
		{"100.64.0.1", true}, // CGNAT
		{"224.0.0.1", true},  // multicast
		{"240.0.0.1", true},  // class E
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

func TestIsPrivateIP_NilOrZero(t *testing.T) {
	// Fail-closed: nil/zero-length IP must be treated as private.
	if !IsPrivateIP(nil) {
		t.Error("IsPrivateIP(nil) should return true (fail-closed)")
	}
	if !IsPrivateIP(net.IP{}) {
		t.Error("IsPrivateIP(empty) should return true (fail-closed)")
	}
}

func TestSafeDialContext_RejectsPrivate(t *testing.T) {
	_, err := SafeDialContext(context.Background(), "tcp", "127.0.0.1:1")
	if err == nil {
		t.Error("expected SafeDialContext to reject IPv4 loopback dial")
	}
}

func TestSafeDialContext_RejectsIPv6Loopback(t *testing.T) {
	_, err := SafeDialContext(context.Background(), "tcp", "[::1]:1")
	if err == nil {
		t.Error("expected SafeDialContext to reject IPv6 loopback dial")
	}
}

func TestSafeDialContext_RejectsInvalidAddr(t *testing.T) {
	_, err := SafeDialContext(context.Background(), "tcp", "not-an-addr")
	if err == nil {
		t.Error("expected SafeDialContext to reject malformed address")
	}
	if !strings.Contains(err.Error(), "invalid address") {
		t.Errorf("expected 'invalid address' in error, got: %v", err)
	}
}

func TestSafeDialContext_RejectsCGNAT(t *testing.T) {
	_, err := SafeDialContext(context.Background(), "tcp", "100.64.0.1:80")
	if err == nil {
		t.Error("expected SafeDialContext to reject CGNAT 100.64.0.0/10")
	}
}
