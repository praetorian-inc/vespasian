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

// This file is package pipeline (internal) so it can exercise the unexported
// buildWSDLProbeClient helper directly. Most pipeline tests live in the
// external pipeline_test package (see wsdl_probe_test.go); this one needs
// internal access, mirroring reasons_test.go / grpc_enrich_test.go in this
// same directory.
package pipeline

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/praetorian-inc/vespasian/pkg/httpx"
)

// TestBuildWSDLProbeClient_ProxyInsecure is the TEST-002 proof that
// buildWSDLProbeClient's proxy branch honors --proxy-insecure exactly like
// the other four proxy-aware stages (mirrors
// pkg/probe/proxy_internal_test.go's TestConfig_WithDefaults_ProxyClient
// subtests, and the equivalent subtests in
// pkg/crawl/jsreplay_test.go:TestJSReplayConfig_WithDefaults_ProxyClient and
// pkg/analyze/jsstatic/sourcemap_test.go:TestDefaultSourcemapClient_ProxyVsSSRF):
// Insecure=true installs TLSClientConfig.InsecureSkipVerify for an http/https
// proxy, but never for socks5 (a transparent TCP tunnel with no substitute CA
// to trust, so verification of the real target must stay on). Before this
// test, `grep -rn "Insecure: *true" internal/pipeline` returned nothing —
// this stage's Insecure wiring had no direct-unit coverage at all.
func TestBuildWSDLProbeClient_ProxyInsecure(t *testing.T) {
	t.Run("http proxy Insecure=true skips verification", func(t *testing.T) {
		proxyURL, err := url.Parse("http://127.0.0.1:8080")
		if err != nil {
			t.Fatalf("parse proxy URL: %v", err)
		}

		client := buildWSDLProbeClient(false, httpx.ProxyConfig{URL: proxyURL, Insecure: true})
		tr, ok := client.Transport.(*http.Transport)
		if !ok {
			t.Fatalf("Transport = %T, want *http.Transport", client.Transport)
		}
		if tr.TLSClientConfig == nil {
			t.Fatal("expected Insecure=true to install a TLSClientConfig")
		}
		if !tr.TLSClientConfig.InsecureSkipVerify {
			t.Error("http proxy Insecure=true must set TLSClientConfig.InsecureSkipVerify")
		}
	})

	t.Run("socks5 proxy Insecure=true stays verified", func(t *testing.T) {
		socksURL, err := url.Parse("socks5://127.0.0.1:1080")
		if err != nil {
			t.Fatalf("parse socks5 proxy URL: %v", err)
		}

		client := buildWSDLProbeClient(false, httpx.ProxyConfig{URL: socksURL, Insecure: true})
		tr, ok := client.Transport.(*http.Transport)
		if !ok {
			t.Fatalf("Transport = %T, want *http.Transport", client.Transport)
		}
		if tr.TLSClientConfig != nil && tr.TLSClientConfig.InsecureSkipVerify {
			t.Error("socks5 is a transparent tunnel; Insecure must never skip verification of the real target")
		}
	})
}
