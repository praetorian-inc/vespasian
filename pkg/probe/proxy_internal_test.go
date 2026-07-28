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
	"bytes"
	"errors"
	"log/slog"
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
// the proxy, not the target), preserves the probe package's redirect policy
// (ErrUseLastResponse), and (TEST-011) that Config.Proxy.Insecure survives the
// withDefaults->BuildHTTPClient hop for an http/https proxy but never for
// socks5 (a transparent TCP tunnel with no substitute CA to trust).
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

	t.Run("http proxy Insecure=true", func(t *testing.T) {
		insecureURL, err := url.Parse("http://127.0.0.1:8080")
		require.NoError(t, err)

		insecureCfg := Config{Proxy: httpx.ProxyConfig{URL: insecureURL, Insecure: true}}.withDefaults()

		insecureTr, ok := insecureCfg.Client.Transport.(*http.Transport)
		require.True(t, ok, "Transport must be *http.Transport, got %T", insecureCfg.Client.Transport)
		require.NotNil(t, insecureTr.TLSClientConfig, "Insecure=true must install a TLSClientConfig")
		assert.True(t, insecureTr.TLSClientConfig.InsecureSkipVerify,
			"Config.Proxy.Insecure must survive the withDefaults->BuildHTTPClient hop for an http/https proxy")
	})

	t.Run("socks5 proxy Insecure=true stays verified", func(t *testing.T) {
		socksURL, err := url.Parse("socks5://127.0.0.1:1080")
		require.NoError(t, err)

		socksCfg := Config{Proxy: httpx.ProxyConfig{URL: socksURL, Insecure: true}}.withDefaults()

		socksTr, ok := socksCfg.Client.Transport.(*http.Transport)
		require.True(t, ok, "Transport must be *http.Transport, got %T", socksCfg.Client.Transport)
		if socksTr.TLSClientConfig != nil {
			assert.False(t, socksTr.TLSClientConfig.InsecureSkipVerify,
				"socks5 is a transparent tunnel; Insecure must never skip verification of the real target")
		}
	})
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

// TestConfig_WithDefaults_WarnsWhenClientInjectedWithProxy is the SEC-BE-004
// proof for the probe stage: when a caller injects Config.Client (which owns
// its own transport) AND enables Config.Proxy, withDefaults must not silently
// bypass the proxy — it emits a loud warning via the default slog logger
// (probe/types.go's withDefaults has no per-Config Logger field, unlike the
// crawl/jsstatic stages, so this captures the process-wide default logger).
func TestConfig_WithDefaults_WarnsWhenClientInjectedWithProxy(t *testing.T) {
	var buf bytes.Buffer
	origLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	defer slog.SetDefault(origLogger)

	proxyURL, err := url.Parse("http://127.0.0.1:8080")
	require.NoError(t, err)

	injectedClient := &http.Client{}
	cfg := Config{Client: injectedClient, Proxy: httpx.ProxyConfig{URL: proxyURL}}.withDefaults()

	assert.Same(t, injectedClient, cfg.Client, "an injected Client must not be replaced when Proxy is enabled")
	assert.Contains(t, buf.String(), "BYPASS the proxy",
		"withDefaults must warn that probe traffic will bypass the proxy when a Client is injected alongside a configured Proxy")
}
