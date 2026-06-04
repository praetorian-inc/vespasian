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

package netutil

import (
	"context"
	"net"
	"strings"
	"testing"
)

func TestIsPrivateIP_Private(t *testing.T) {
	privates := []string{
		"127.0.0.1",
		"10.0.0.1",
		"172.16.0.1",
		"192.168.1.1",
		"169.254.169.254",
		"::1",
		"0.0.0.0",
		"100.64.0.1",
	}
	for _, addr := range privates {
		t.Run(addr, func(t *testing.T) {
			ip := net.ParseIP(addr)
			if ip == nil {
				t.Fatalf("failed to parse IP %q", addr)
			}
			if !IsPrivateIP(ip) {
				t.Errorf("IsPrivateIP(%q) = false, want true", addr)
			}
		})
	}
}

func TestIsPrivateIP_Public(t *testing.T) {
	publics := []string{
		"8.8.8.8",
		"93.184.215.14",
		"1.1.1.1",
	}
	for _, addr := range publics {
		t.Run(addr, func(t *testing.T) {
			ip := net.ParseIP(addr)
			if ip == nil {
				t.Fatalf("failed to parse IP %q", addr)
			}
			if IsPrivateIP(ip) {
				t.Errorf("IsPrivateIP(%q) = true, want false", addr)
			}
		})
	}
}

// TestSSRFSafeDialContext_SplitHostPortError exercises the SplitHostPort error
// branch when the address has no port component.
func TestSSRFSafeDialContext_SplitHostPortError(t *testing.T) {
	ctx := context.Background()
	_, err := SSRFSafeDialContext(ctx, "tcp", "nohost")
	if err == nil {
		t.Fatal("expected error for address with no port, got nil")
	}
	if !strings.Contains(err.Error(), "invalid address") {
		t.Errorf("expected 'invalid address' in error, got: %v", err)
	}
}

// TestSSRFSafeDialContext_PrivateIPBlocked exercises the private-IP rejection
// branch when the resolved host is a loopback address.
func TestSSRFSafeDialContext_PrivateIPBlocked(t *testing.T) {
	ctx := context.Background()
	_, err := SSRFSafeDialContext(ctx, "tcp", "127.0.0.1:80")
	if err == nil {
		t.Fatal("expected error for private IP 127.0.0.1, got nil")
	}
	if !strings.Contains(err.Error(), "blocked") || !strings.Contains(err.Error(), "private IP") {
		t.Errorf("expected SSRF guard rejection ('blocked: ... private IP'), got: %v", err)
	}
}

// TestSSRFSafeDialContext_DNSFailure exercises the DNS-failure branch using a
// guaranteed-NXDOMAIN hostname (the .invalid TLD is reserved by RFC 2606).
func TestSSRFSafeDialContext_DNSFailure(t *testing.T) {
	ctx := context.Background()
	_, err := SSRFSafeDialContext(ctx, "tcp", "no-such-host.invalid:80")
	if err == nil {
		t.Fatal("expected error for NXDOMAIN host, got nil")
	}
	if !strings.Contains(err.Error(), "DNS lookup failed") {
		t.Errorf("expected 'DNS lookup failed' in error, got: %v", err)
	}
}

// Note: the dial-success path (public IP that actually connects) and the
// multi-IP fallback path require a reachable public endpoint and are therefore
// not unit-testable here — loopback is blocked by the SSRF guard itself.
// Those paths are covered by live/integration tests.
