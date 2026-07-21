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

package pipeline

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/praetorian-inc/vespasian/pkg/crawl"
	wsdlgen "github.com/praetorian-inc/vespasian/pkg/generate/wsdl"
	"github.com/praetorian-inc/vespasian/pkg/httpx"
	"github.com/praetorian-inc/vespasian/pkg/probe"
)

// writeStatus writes a status message to w if w is non-nil. Used to forward
// optional progress output without forcing every call site to nil-check.
func writeStatus(w io.Writer, format string, args ...any) {
	if w == nil {
		return
	}
	fmt.Fprintf(w, format, args...) //nolint:errcheck,gosec // best-effort status output
}

// wsdlStageTimeout caps each connection phase (TLS handshake, response header)
// independently of the overall Client.Timeout, so a slow or malicious target
// can't burn the whole budget on a single stage. Both transport branches share
// this cap — the only real difference is the dialer (SSRF-safe vs permissive).
const wsdlStageTimeout = 10 * time.Second

// buildWSDLProbeClient constructs the HTTP client used by ProbeWSDLDocument.
// When proxy is enabled the transport routes through it (no dial-time SSRF pin —
// we dial the proxy, not the target). Otherwise, when allowPrivate is false the
// transport uses SSRF-safe dialing; when true it mirrors the timeouts applied to
// AllowPrivate probes elsewhere.
func buildWSDLProbeClient(allowPrivate bool, proxy httpx.ProxyConfig) *http.Client {
	if proxy.Enabled() {
		return httpx.BuildHTTPClient(proxy, 15*time.Second, func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		})
	}
	transport := &http.Transport{
		DialContext:           probe.SSRFSafeDialContext,
		TLSHandshakeTimeout:   wsdlStageTimeout,
		ResponseHeaderTimeout: wsdlStageTimeout,
	}
	if allowPrivate {
		transport = &http.Transport{
			TLSHandshakeTimeout:   wsdlStageTimeout,
			ResponseHeaderTimeout: wsdlStageTimeout,
		}
	}
	return &http.Client{
		Timeout:   15 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// ProbeWSDLDocument attempts to fetch a WSDL document from targetURL?wsdl.
// Returns the raw WSDL bytes on success, or nil if the probe fails or the
// response is not a valid WSDL document. status is an optional io.Writer
// for progress messages; pass nil or io.Discard to suppress them.
func ProbeWSDLDocument(ctx context.Context, targetURL string, allowPrivate bool, proxy httpx.ProxyConfig, status io.Writer) []byte {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		writeStatus(status, "wsdl discovery: invalid URL %q: %v\n", targetURL, err)
		return nil
	}
	parsedURL.RawQuery = "wsdl"
	wsdlURL := parsedURL.String()

	writeStatus(status, "wsdl discovery: probing %s\n", wsdlURL)

	if !allowPrivate {
		if err := probe.ValidateProbeURL(wsdlURL); err != nil {
			writeStatus(status, "wsdl discovery: skipping %s (SSRF protection: %v)\n", wsdlURL, err)
			return nil
		}
	}

	client := buildWSDLProbeClient(allowPrivate, proxy)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wsdlURL, nil)
	if err != nil {
		writeStatus(status, "wsdl discovery: failed to create request: %v\n", err)
		return nil
	}

	resp, err := client.Do(req)
	if err != nil {
		writeStatus(status, "wsdl discovery: request failed: %v\n", err)
		return nil
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)) //nolint:errcheck // best-effort drain
		_ = resp.Body.Close()                                       //nolint:errcheck // best-effort close
	}()

	if resp.StatusCode >= 400 {
		writeStatus(status, "wsdl discovery: %s returned HTTP %d\n", wsdlURL, resp.StatusCode)
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20)) // 2MB limit
	if err != nil {
		return nil
	}

	// Validate the response is actually a WSDL document.
	if _, parseErr := wsdlgen.ParseWSDL(body); parseErr != nil {
		writeStatus(status, "wsdl discovery: response is not valid WSDL: %v\n", parseErr)
		return nil
	}

	return body
}

// ProbeAndAppendWSDLRequest probes targetURL?wsdl for a WSDL document. On
// success it appends a synthetic ObservedRequest (Method=GET, URL=<targetURL>?wsdl,
// Response={200, text/xml, body}) to requests and returns the augmented slice
// along with foundWSDL=true and resolvedAPIType=APITypeWSDL. When the probe
// finds no valid WSDL the original requests slice is returned unchanged,
// foundWSDL=false, and resolvedAPIType="".
//
// The URL for the synthetic request is built via url.URL.RawQuery to avoid the
// double-query-separator bug that occurs when targetURL already carries a query
// string (e.g. https://x.com/svc?foo=1 + "?wsdl" → https://x.com/svc?wsdl).
//
// This helper is the single source of truth for WSDL discovery shared by
// ScanCmd.Run (cmd/vespasian/main.go) and Capability.runScan (pkg/sdk).
func ProbeAndAppendWSDLRequest(ctx context.Context, targetURL string, requests []crawl.ObservedRequest, allowPrivate bool, proxy httpx.ProxyConfig, status io.Writer) ([]crawl.ObservedRequest, bool, string) {
	wsdlDoc := ProbeWSDLDocument(ctx, targetURL, allowPrivate, proxy, status)
	if wsdlDoc == nil {
		return requests, false, ""
	}

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		// ProbeWSDLDocument already succeeded, so URL is valid; this branch
		// should be unreachable in practice.
		return requests, false, ""
	}
	parsedURL.RawQuery = "wsdl"
	wsdlURL := parsedURL.String()

	requests = append(requests, crawl.ObservedRequest{
		Method: "GET",
		URL:    wsdlURL,
		Response: crawl.ObservedResponse{
			StatusCode:  200,
			ContentType: "text/xml",
			Body:        wsdlDoc,
		},
	})
	return requests, true, APITypeWSDL
}

// ResolveWSDLType is the single gating point for active WSDL discovery shared by
// ScanCmd.Run (cmd/vespasian) and Capability.runScan (pkg/sdk). It probes
// targetURL?wsdl and promotes the API type to WSDL only when probing is enabled
// and the resolved type is WSDL or REST (SOAP services often return HTML to
// browser GETs, so crawl traffic rarely carries WSDL signals — active probing is
// the reliable discovery method). When the probe is skipped or finds nothing, the
// original requests slice and apiType are returned unchanged. It returns the
// (possibly augmented) requests, the resolved API type, and whether a WSDL
// document was found.
func ResolveWSDLType(ctx context.Context, targetURL, apiType string, requests []crawl.ObservedRequest, probe, allowPrivate bool, proxy httpx.ProxyConfig, status io.Writer) ([]crawl.ObservedRequest, string, bool) {
	if !probe || (apiType != APITypeWSDL && apiType != APITypeREST) {
		return requests, apiType, false
	}
	augmented, foundWSDL, _ := ProbeAndAppendWSDLRequest(ctx, targetURL, requests, allowPrivate, proxy, status)
	if foundWSDL {
		return augmented, APITypeWSDL, true
	}
	return requests, apiType, false
}
