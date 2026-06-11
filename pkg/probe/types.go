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
}

// DefaultMaxEndpoints is the default limit on unique URLs probed per strategy.
const DefaultMaxEndpoints = 500

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Timeout: 10 * time.Second,
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
	if cfg.Client == nil {
		cfg.Client = &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: &http.Transport{
				DialContext:           ssrf.SafeDialContext,
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: 10 * time.Second,
				IdleConnTimeout:       90 * time.Second,
			},
		}
	}
	return cfg
}
