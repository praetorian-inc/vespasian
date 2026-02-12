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
}

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
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: cfg.Timeout}
	}
	return cfg
}
