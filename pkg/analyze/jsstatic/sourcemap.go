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

package jsstatic

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/praetorian-inc/vespasian/pkg/probe"
)

// sourceMapDoc is the minimal structure we unmarshal from a .js.map file.
// We only use sourcesContent (the embedded source strings); we do NOT
// follow Sources[] URLs (per §7 "Sourcemap Sources[] resolution" deferred).
type sourceMapDoc struct {
	Sources        []string `json:"sources"`
	SourcesContent []string `json:"sourcesContent"`
}

// sourceMappingCommentPrefixes are the two canonical forms of the
// sourceMappingURL pragma. The //@ form is the original (deprecated) syntax.
var sourceMappingCommentPrefixes = [][]byte{
	[]byte("//# sourceMappingURL="),
	[]byte("//@ sourceMappingURL="),
}

// trailingWindowSize is the number of trailing bytes we scan for the
// sourceMappingURL comment. Scanning the full bundle is expensive on large
// files; the pragma is always at the very end so 2 KB is ample.
const trailingWindowSize = 2048

// maxSourcemapResponseSize is the maximum response body we will read from a
// remote sourcemap fetch. Responses exceeding this are rejected and counted
// as failures to prevent memory exhaustion.
const maxSourcemapResponseSize = 10 * 1024 * 1024 // 10 MB

// recoverSourcemap scans the trailing window of the bundle for a
// sourceMappingURL pragma. If found and it points to a data: URI, it decodes
// and parses the sourcesContent inline. If it points to a remote URL and
// opts.FetchSourcemaps is true, it fetches the remote sourcemap.
//
// Returns the recovered source strings and partial Stats for accounting.
func recoverSourcemap(bundle []byte, bundleURL string, opts Options) ([]string, Stats) {
	var stats Stats

	if len(bundle) == 0 {
		return nil, stats
	}

	// Only scan the trailing window.
	window := bundle
	if len(window) > trailingWindowSize {
		window = window[len(window)-trailingWindowSize:]
	}

	// Locate the sourceMappingURL comment.
	var mappingURL string
	for _, prefix := range sourceMappingCommentPrefixes {
		idx := bytes.LastIndex(window, prefix)
		if idx == -1 {
			continue
		}
		rest := window[idx+len(prefix):]
		// URL ends at the next newline or end of buffer.
		if nl := bytes.IndexByte(rest, '\n'); nl != -1 {
			rest = rest[:nl]
		}
		mappingURL = strings.TrimSpace(string(rest))
		break
	}

	if mappingURL == "" {
		return nil, stats
	}

	// Handle data: URIs inline (no network required).
	if strings.HasPrefix(mappingURL, "data:") {
		sources, err := parseDataURISourcemap(mappingURL)
		if err != nil {
			stats.SourcemapFetchFails++
			return nil, stats
		}
		if len(sources) > 0 {
			stats.SourcemapsRecovered++
		}
		return sources, stats
	}

	// Remote URL: only fetch when FetchSourcemaps is enabled.
	if !opts.FetchSourcemaps {
		return nil, stats
	}

	// Cross-host protection: only fetch when the sourcemap URL is on the same
	// host as the bundle (§7 "Cross-host sourcemap fetch" deferred/refused).
	if !sameHost(bundleURL, mappingURL) {
		return nil, stats
	}

	// Build HTTP client.
	client := opts.HTTPClient
	if client == nil {
		client = defaultSourcemapClient(opts.AllowPrivate)
	}

	// Fetch the remote sourcemap.
	sources, err := fetchRemoteSourcemap(client, mappingURL, opts.AllowPrivate)
	if err != nil {
		stats.SourcemapFetchFails++
		return nil, stats
	}
	if len(sources) > 0 {
		stats.SourcemapsRecovered++
	}
	return sources, stats
}

// sameHost returns true when both rawA and rawB are valid URLs sharing the
// same host (scheme+host pair). If either cannot be parsed, returns false.
func sameHost(rawA, rawB string) bool {
	if rawA == "" || rawB == "" {
		return false
	}
	a, err := url.Parse(rawA)
	if err != nil || a.Host == "" {
		return false
	}
	b, err := url.Parse(rawB)
	if err != nil || b.Host == "" {
		return false
	}
	return a.Host == b.Host
}

// defaultSourcemapClient builds an http.Client for sourcemap fetches.
// When allowPrivate is false, the SSRF-safe dial context from pkg/probe is
// used. When allowPrivate is true, a permissive dialer is used instead.
func defaultSourcemapClient(allowPrivate bool) *http.Client {
	timeout := 10 * time.Second
	if allowPrivate {
		return &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				DialContext: (&net.Dialer{
					Timeout: timeout,
				}).DialContext,
				TLSHandshakeTimeout:   timeout,
				ResponseHeaderTimeout: timeout,
			},
		}
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext:           probe.SSRFSafeDialContext,
			TLSHandshakeTimeout:   timeout,
			ResponseHeaderTimeout: timeout,
		},
	}
}

// fetchRemoteSourcemap GETs the sourcemap URL, reads up to maxSourcemapResponseSize
// bytes, and returns sourcesContent strings.
func fetchRemoteSourcemap(client *http.Client, mapURL string, allowPrivate bool) ([]string, error) {
	resp, err := client.Get(mapURL) //nolint:noctx
	if err != nil {
		return nil, err
	}
	defer closeQuietly(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sourcemap fetch: HTTP %d for %s", resp.StatusCode, mapURL)
	}

	// Limit response body size.
	limited := io.LimitReader(resp.Body, int64(maxSourcemapResponseSize)+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(body) > maxSourcemapResponseSize {
		return nil, fmt.Errorf("sourcemap fetch: response too large (>%d bytes) for %s", maxSourcemapResponseSize, mapURL)
	}

	var doc sourceMapDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}

	var sources []string
	for _, s := range doc.SourcesContent {
		if s != "" {
			sources = append(sources, s)
		}
	}
	return sources, nil
}

// parseDataURISourcemap decodes a data:application/json;base64,... URI and
// returns the sourcesContent strings.
func parseDataURISourcemap(uri string) ([]string, error) {
	// Strip the "data:" prefix.
	rest := strings.TrimPrefix(uri, "data:")

	// Find the comma separating the media-type from the data.
	commaIdx := strings.Index(rest, ",")
	if commaIdx == -1 {
		return nil, &sourcemapError{"missing comma in data URI"}
	}

	mediaType := rest[:commaIdx]
	data := rest[commaIdx+1:]

	var raw []byte
	if strings.Contains(mediaType, "base64") {
		decoded, err := base64.StdEncoding.DecodeString(data)
		if err != nil {
			return nil, err
		}
		raw = decoded
	} else {
		raw = []byte(data)
	}

	var doc sourceMapDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}

	// Only return non-empty content strings.
	var sources []string
	for _, s := range doc.SourcesContent {
		if s != "" {
			sources = append(sources, s)
		}
	}
	return sources, nil
}

// sourcemapError is a simple error type for sourcemap parsing failures.
type sourcemapError struct {
	msg string
}

func (e *sourcemapError) Error() string { return "sourcemap: " + e.msg }

// closeQuietly closes a body and logs any error at debug level; close-failure
// during cleanup is not actionable from the caller's perspective.
func closeQuietly(c io.Closer) {
	if c == nil {
		return
	}
	if err := c.Close(); err != nil {
		slog.Default().Debug("jsstatic: close failed during cleanup", "error", err)
	}
}
