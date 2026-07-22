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

package probe_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/vespasian/pkg/classify"
	"github.com/praetorian-inc/vespasian/pkg/crawl"
	"github.com/praetorian-inc/vespasian/pkg/httpx"
	"github.com/praetorian-inc/vespasian/pkg/probe"
)

// TestProbe_OptionsStrategy_RoutesThroughProxy is an end-to-end proof (AC-1)
// that the OPTIONS probe strategy — and by extension all 5 HTTP-based probe
// strategies that share Config.Client — routes its traffic through the
// configured proxy. Modeled on the recording-proxy pattern from
// pkg/crawl/http_crawler_test.go:195 and the probe injection pattern from
// options_test.go:48.
func TestProbe_OptionsStrategy_RoutesThroughProxy(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodOptions {
			return
		}
		w.Header().Set("Allow", "GET, POST")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer origin.Close()

	var proxied atomic.Int64
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxied.Add(1)
		outReq, err := http.NewRequestWithContext(r.Context(), r.Method, r.RequestURI, nil) //nolint:gosec // test proxy forwards the received request URI
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		resp, err := http.DefaultTransport.RoundTrip(outReq)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close() //nolint:errcheck // test cleanup
		w.WriteHeader(resp.StatusCode)
	}))
	defer proxy.Close()

	proxyURL, err := url.Parse(proxy.URL)
	require.NoError(t, err)

	cfg := probe.Config{
		Proxy:        httpx.ProxyConfig{URL: proxyURL},
		Timeout:      5 * time.Second,
		URLValidator: func(string) error { return nil }, // no-op for loopback, mirroring gRPC tests
	}
	p := probe.NewOptionsProbe(cfg)

	endpoints := []classify.ClassifiedRequest{
		{ObservedRequest: crawl.ObservedRequest{Method: "GET", URL: origin.URL + "/api/users"}, IsAPI: true},
	}

	_, err = p.Probe(context.Background(), endpoints)
	require.NoError(t, err)

	assert.NotZero(t, proxied.Load(), "OPTIONS strategy must route its request through the configured proxy")
}
