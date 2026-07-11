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
	"net/http"
	"time"

	"github.com/praetorian-inc/vespasian/pkg/ssrf"
)

// Config holds shared configuration for probe strategies.
type Config struct {
	// Client is the HTTP client used for probe requests.
	// If nil, a default client with the Timeout is created.
	Client *http.Client

	// Timeout is the per-request timeout for probe HTTP calls.
	// Defaults to 10 seconds if zero.
	Timeout time.Duration

	// AuthHeaders are injected into every probe request.
	AuthHeaders map[string]string

	// URLValidator is called before each probe request to validate the target URL.
	// If nil, the default SSRF-prevention validator is used. Set to a no-op
	// function in tests that use httptest servers on loopback addresses.
	URLValidator func(string) error

	// MaxEndpoints limits the number of unique URLs probed per strategy.
	// If zero, defaults to DefaultMaxEndpoints.
	MaxEndpoints int

	// Dialer is used by probes that establish their own connections (e.g., the
	// gRPC reflection probe, which cannot reuse the http.Client). If nil, the
	// default SSRF-safe dialer is used. Tests targeting loopback should set a
	// plain net.Dialer.
	Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

	// GRPCInsecureSkipVerify disables TLS certificate verification when the
	// gRPC reflection probe dials a TLS target. Default false (verify). Enable
	// only to enumerate self-signed/internal-CA targets you trust; SSRF is
	// still enforced by the Dialer regardless.
	GRPCInsecureSkipVerify bool

	// MaxReflectionDescriptors caps how many discovered services the reflection
	// probe enumerates before stopping (the loop-level guard against a hostile
	// server advertising unbounded services). Zero means use the package
	// default (maxGRPCFileDescriptors). Overridable primarily for tests.
	MaxReflectionDescriptors int

	// MaxReflectionDescriptorBytes caps the aggregate retained descriptor bytes
	// at which the reflection probe stops enumerating further services. Zero
	// means use the package default (maxGRPCDescriptorBytes). Overridable
	// primarily for tests.
	MaxReflectionDescriptorBytes int

	// MaxTotalReflectionDescriptorBytes caps the AGGREGATE retained descriptor
	// bytes summed across ALL probed targets. Once cumulative retained bytes reach
	// this ceiling, Probe stops dialing further targets — bounding total memory
	// even when many distinct hostile targets each stay under the per-target cap.
	// Zero means use the package default (DefaultMaxTotalReflectionDescriptorBytes).
	// Overridable primarily for tests.
	MaxTotalReflectionDescriptorBytes int
}

// DefaultMaxEndpoints is the default limit on unique URLs probed per strategy.
const DefaultMaxEndpoints = 500

// DefaultMaxTotalReflectionDescriptorBytes is the default aggregate cross-target
// retained-descriptor budget. Set to a small multiple (4x) of the per-target
// maxGRPCDescriptorBytes cap (= 256 MiB), so worst-case retained memory is
// bounded to ~256 MiB (plus at most one in-flight target's ≤64 MiB, since the
// target that crosses the threshold is fully retained before Probe breaks),
// versus the unbounded ~32 GiB (MaxEndpoints × 64 MiB) without this ceiling.
// Generous enough not to affect real scans (typical targets retain KB),
// aggressive enough to stop a pathological many-hostile-target capture.
const DefaultMaxTotalReflectionDescriptorBytes = 4 * maxGRPCDescriptorBytes

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Timeout: 10 * time.Second,
	}
}

// DefaultTransport returns a new *http.Transport configured with the probe
// package's default settings: the SSRF-safe dialer plus the TLS-handshake,
// response-header, and idle-connection timeouts. It is the single source of
// truth for the default transport — withDefaults uses it to build the default
// Client, and callers that need to loosen exactly one setting (e.g. the
// --dangerous-allow-private path, which swaps DialContext for a plain net.Dialer
// to disable SSRF re-resolution) should clone it and override that one field
// rather than hand-rolling a bare transport that would silently drop these (and
// any future proxy/CA/idle) settings.
func DefaultTransport() *http.Transport {
	return &http.Transport{
		DialContext:           ssrf.SafeDialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		IdleConnTimeout:       90 * time.Second,
	}
}

// withDefaults returns a copy of cfg with zero values replaced by defaults.
func (cfg Config) withDefaults() Config {
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.URLValidator == nil {
		cfg.URLValidator = ssrf.ValidateURL
	}
	if cfg.MaxEndpoints == 0 {
		cfg.MaxEndpoints = DefaultMaxEndpoints
	}
	if cfg.Dialer == nil {
		cfg.Dialer = ssrf.SafeDialContext
	}
	if cfg.MaxReflectionDescriptors == 0 {
		cfg.MaxReflectionDescriptors = maxGRPCFileDescriptors
	}
	if cfg.MaxReflectionDescriptorBytes == 0 {
		cfg.MaxReflectionDescriptorBytes = maxGRPCDescriptorBytes
	}
	if cfg.MaxTotalReflectionDescriptorBytes == 0 {
		cfg.MaxTotalReflectionDescriptorBytes = DefaultMaxTotalReflectionDescriptorBytes
	}
	if cfg.Client == nil {
		cfg.Client = &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: DefaultTransport(),
		}
	}
	return cfg
}
