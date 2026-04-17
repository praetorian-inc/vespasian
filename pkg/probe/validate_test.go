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

func TestValidateProbeURL_BlocksUnspecifiedIPv4(t *testing.T) {
	err := validateProbeURL("http://0.0.0.0/api")
	if err == nil {
		t.Error("expected 0.0.0.0 to be blocked, got nil error")
	}
}

func TestValidateProbeURL_BlocksUnspecifiedIPv6(t *testing.T) {
	err := validateProbeURL("http://[::]/api")
	if err == nil {
		t.Error("expected [::] (IPv6 unspecified) to be blocked, got nil error")
	}
}

// TestValidateProbeURL_Exported verifies that the exported ValidateProbeURL
// wrapper delegates to validateProbeURL correctly.
func TestValidateProbeURL_Exported(t *testing.T) {
	// A private IP must be rejected — exercises the exported wrapper.
	err := ValidateProbeURL("http://127.0.0.1/api")
	if err == nil {
		t.Error("expected loopback address to be blocked via exported ValidateProbeURL")
	}
}

// TestSSRFSafeDialContext_BlocksPrivateIP verifies that ssrfSafeDialContext
// rejects connections to private IP addresses without requiring a real TCP dial.
// A pre-canceled context is used so even DNS resolution is bounded.
func TestSSRFSafeDialContext_BlocksPrivateIP(t *testing.T) {
	ctx := context.Background()
	// 127.0.0.1 resolves immediately (no external DNS) and is a private IP,
	// so ssrfSafeDialContext should return an error before attempting to dial.
	_, err := ssrfSafeDialContext(ctx, "tcp", "127.0.0.1:80")
	if err == nil {
		t.Error("expected loopback address to be blocked by ssrfSafeDialContext")
	}
}

// TestSSRFSafeDialContext_Exported exercises the exported SSRFSafeDialContext
// wrapper to ensure it delegates to the internal implementation.
func TestSSRFSafeDialContext_Exported(t *testing.T) {
	ctx := context.Background()
	_, err := SSRFSafeDialContext(ctx, "tcp", "127.0.0.1:80")
	if err == nil {
		t.Error("expected loopback address to be blocked via exported SSRFSafeDialContext")
	}
}

// TestSSRFSafeDialContext_InvalidAddress exercises the net.SplitHostPort error
// branch (validate.go:112-115) in ssrfSafeDialContext.
func TestSSRFSafeDialContext_InvalidAddress(t *testing.T) {
	ctx := context.Background()
	// An address without a port triggers net.SplitHostPort to return an error.
	_, err := ssrfSafeDialContext(ctx, "tcp", "no-port")
	if err == nil {
		t.Error("expected invalid address (no port) to return error")
	}
}

// TestSSRFSafeDialContext_DNSFailure exercises the DNS lookup failure branch
// (validate.go:117-120) in ssrfSafeDialContext using a canceled context.
func TestSSRFSafeDialContext_DNSFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-canceled causes LookupIPAddr to fail
	_, err := ssrfSafeDialContext(ctx, "tcp", "example.invalid:80")
	if err == nil {
		t.Error("expected DNS lookup to fail with canceled context or invalid hostname")
	}
}
