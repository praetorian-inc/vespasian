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

// Package probe — internal tests for the unexported withDefaults proxy
// wiring. Uses `package probe` (not probe_test) because withDefaults is
// unexported (LAB-4993).
package probe

import (
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/vespasian/pkg/httpx"
)

// TestConfig_WithDefaults_ProxyClient verifies that when Config.Proxy is
// enabled and Client is nil, withDefaults builds a proxied client: the
// transport routes through the proxy, has no SSRF dial pin installed (we dial
// the proxy, not the target), and preserves the probe package's redirect
// policy (ErrUseLastResponse).
func TestConfig_WithDefaults_ProxyClient(t *testing.T) {
	proxyURL, err := url.Parse("http://127.0.0.1:8080")
	require.NoError(t, err)

	cfg := Config{Proxy: httpx.ProxyConfig{URL: proxyURL}}.withDefaults()

	require.NotNil(t, cfg.Client)
	tr, ok := cfg.Client.Transport.(*http.Transport)
	require.True(t, ok, "Transport must be *http.Transport, got %T", cfg.Client.Transport)
	assert.NotNil(t, tr.Proxy, "proxied client must set Transport.Proxy")
	assert.Nil(t, tr.DialContext, "proxied client must NOT install the SSRF dial pin (no target pin when proxied)")

	require.NotNil(t, cfg.Client.CheckRedirect)
	gotErr := cfg.Client.CheckRedirect(nil, nil)
	assert.True(t, errors.Is(gotErr, http.ErrUseLastResponse),
		"proxied client must keep the probe package's ErrUseLastResponse redirect policy")
}

// TestConfig_WithDefaults_NoProxyUnchanged verifies that a zero-value Proxy
// leaves the existing SSRF-safe default client construction untouched.
func TestConfig_WithDefaults_NoProxyUnchanged(t *testing.T) {
	cfg := Config{}.withDefaults()

	require.NotNil(t, cfg.Client)
	tr, ok := cfg.Client.Transport.(*http.Transport)
	require.True(t, ok, "Transport must be *http.Transport, got %T", cfg.Client.Transport)
	assert.NotNil(t, tr.DialContext, "unproxied default client must keep the SSRF-safe dial guard")
}
