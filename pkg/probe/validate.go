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
	"net"

	"github.com/praetorian-inc/vespasian/pkg/ssrf"
)

// ValidateProbeURL checks that rawURL is safe to probe. It rejects non-HTTP(S)
// schemes and URLs that resolve to private/internal IP addresses (SSRF protection).
//
// Equivalent to [ssrf.ValidateURL]; kept as a thin wrapper so existing callers
// of pkg/probe continue to work.
func ValidateProbeURL(rawURL string) error {
	return ssrf.ValidateURL(rawURL)
}

// validateProbeURL is the internal implementation of ValidateProbeURL.
func validateProbeURL(rawURL string) error {
	return ssrf.ValidateURL(rawURL)
}

// SSRFSafeDialContext is a net.Dialer DialContext replacement that re-checks
// resolved IPs against the SSRF blocklist at connect time, preventing TOCTOU
// DNS rebinding attacks.
//
// Equivalent to [ssrf.SafeDialContext]; kept as a thin wrapper so existing
// callers of pkg/probe continue to work.
func SSRFSafeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return ssrf.SafeDialContext(ctx, network, addr)
}

// ssrfSafeDialContext is the internal implementation of SSRFSafeDialContext.
func ssrfSafeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return ssrf.SafeDialContext(ctx, network, addr)
}
