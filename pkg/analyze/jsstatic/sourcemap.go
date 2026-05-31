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
	"context"
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
// ctx is propagated into remote fetch HTTP requests so that cancellation and
// deadlines from the caller are honored.
//
// Returns the recovered source strings and partial Stats for accounting.
func recoverSourcemap(ctx context.Context, bundle []byte, bundleURL string, opts Options) ([]string, Stats) {
	var stats Stats

	mappingURL := findSourceMappingURL(bundle)
	if mappingURL == "" {
		return nil, stats
	}

	// Handle data: URIs inline (no network required).
	if strings.HasPrefix(mappingURL, "data:") {
		return decodeDataURISourcemap(mappingURL)
	}

	// Remote URL: only fetch when FetchSourcemaps is enabled.
	if !opts.FetchSourcemaps {
		return nil, stats
	}

	mappingURL = resolveRelativeMapURL(bundleURL, mappingURL)

	// Cross-host protection: only fetch when the sourcemap URL is on the same
	// host as the bundle (§7 "Cross-host sourcemap fetch" deferred/refused).
	if !sameHost(bundleURL, mappingURL) {
		return nil, stats
	}

	client := opts.HTTPClient
	if client == nil {
		client = defaultSourcemapClient(opts.AllowPrivate)
	} else {
		// Caller-supplied client: enforce both noFollowRedirects and an SSRF-safe
		// DialContext on a shallow-copy so neither mutation touches the caller's
		// original client.
		//
		// noFollowRedirects: a same-host .js.map URL that 302s to an attacker
		// host would bypass the sameHost pre-flight check above.
		//
		// SSRFSafeDialContext (or permissive dialer when AllowPrivate is true):
		// the caller's Transport may not be SSRF-safe. We overlay it to match the
		// posture of defaultSourcemapClient, mirroring how the probe stage defends
		// against DNS-rebinding attacks regardless of how the caller configured the
		// Transport. We do NOT mutate the caller's Transport — a new *http.Transport
		// is constructed so that AllowPrivate semantics are respected.
		clientCopy := *client
		clientCopy.CheckRedirect = noFollowRedirects
		clientCopy.Transport = ssrfSafeTransport(opts.AllowPrivate)
		// Enforce the same overall deadline as the default client so a slow-drip
		// body read is bounded even when the caller's client left Timeout unset
		// (zero == no limit). http.Client.Timeout covers the full exchange,
		// including the response-body read.
		clientCopy.Timeout = 10 * time.Second
		client = &clientCopy
	}

	sources, err := fetchRemoteSourcemap(ctx, client, mappingURL)
	if err != nil {
		stats.SourcemapFetchFails++
		return nil, stats
	}
	if len(sources) > 0 {
		stats.SourcemapsRecovered++
	}
	return sources, stats
}

// findSourceMappingURL scans the trailing window of a JS bundle for a
// `//# sourceMappingURL=` (or `//@`) pragma and returns the URL portion.
func findSourceMappingURL(bundle []byte) string {
	if len(bundle) == 0 {
		return ""
	}
	window := bundle
	if len(window) > trailingWindowSize {
		window = window[len(window)-trailingWindowSize:]
	}
	for _, prefix := range sourceMappingCommentPrefixes {
		idx := bytes.LastIndex(window, prefix)
		if idx == -1 {
			continue
		}
		rest := window[idx+len(prefix):]
		if nl := bytes.IndexByte(rest, '\n'); nl != -1 {
			rest = rest[:nl]
		}
		return strings.TrimSpace(string(rest))
	}
	return ""
}

// decodeDataURISourcemap parses an inline data: sourceMappingURL and returns
// the recovered sources plus accounting stats.
func decodeDataURISourcemap(mappingURL string) ([]string, Stats) {
	var stats Stats
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

// resolveRelativeMapURL resolves a possibly-relative mapping URL against the
// bundle URL so that "app.js.map" becomes "https://h/static/js/app.js.map"
// before the same-host check (which requires a non-empty Host component).
//
// On parse failure, returns mappingURL unchanged. This is safe because the
// caller (recoverSourcemap) immediately runs the result through sameHost,
// which rejects URLs with empty Hostname/Scheme — a parse-failed value will
// not pass that gate. This preserves the "fail closed" property without
// needing a separate error channel.
func resolveRelativeMapURL(bundleURL, mappingURL string) string {
	if bundleURL == "" {
		return mappingURL
	}
	base, err := url.Parse(bundleURL)
	if err != nil {
		return mappingURL
	}
	ref, err := url.Parse(mappingURL)
	if err != nil {
		return mappingURL
	}
	return base.ResolveReference(ref).String()
}

// sameHost returns true when both rawA and rawB are valid URLs sharing the
// same hostname, scheme, AND effective port. Default ports are normalised
// (http -> 80, https -> 443) so https://example.com and https://example.com:443
// compare equal, but https://example.com:8443 and https://example.com:443 do
// NOT — a non-default-port bundle must match a non-default-port sourcemap.
// Cross-scheme (http vs https) is rejected to prevent mixed-content fetches.
func sameHost(rawA, rawB string) bool {
	if rawA == "" || rawB == "" {
		return false
	}
	a, err := url.Parse(rawA)
	if err != nil || a.Hostname() == "" || a.Scheme == "" {
		return false
	}
	b, err := url.Parse(rawB)
	if err != nil || b.Hostname() == "" || b.Scheme == "" {
		return false
	}
	if a.Hostname() != b.Hostname() || a.Scheme != b.Scheme {
		return false
	}
	return effectivePort(a) == effectivePort(b)
}

// effectivePort returns the port for u, falling back to the scheme's default
// (80 for http, 443 for https) when no explicit port is set.
func effectivePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	switch u.Scheme {
	case "http":
		return "80"
	case "https":
		return "443"
	}
	return ""
}

// noFollowRedirects is a CheckRedirect function that prevents the HTTP client
// from following 3xx responses. A same-host .js.map URL that redirects to a
// different host would bypass the sameHost pre-flight check; blocking all
// redirects closes this gap.
func noFollowRedirects(_ *http.Request, _ []*http.Request) error {
	return http.ErrUseLastResponse
}

// ssrfSafeTransport returns a new *http.Transport with the appropriate
// DialContext for sourcemap fetches. When allowPrivate is false, the SSRF-safe
// dial context from pkg/probe is used. When allowPrivate is true, a permissive
// dialer is used instead. Used by both defaultSourcemapClient (nil HTTPClient
// path) and the caller-supplied HTTPClient path in recoverSourcemap.
func ssrfSafeTransport(allowPrivate bool) *http.Transport {
	timeout := 10 * time.Second
	if allowPrivate {
		return &http.Transport{
			DialContext: (&net.Dialer{
				Timeout: timeout,
			}).DialContext,
			TLSHandshakeTimeout:   timeout,
			ResponseHeaderTimeout: timeout,
		}
	}
	return &http.Transport{
		DialContext:           probe.SSRFSafeDialContext,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
	}
}

// defaultSourcemapClient builds an http.Client for sourcemap fetches.
// When allowPrivate is false, the SSRF-safe dial context from pkg/probe is
// used. When allowPrivate is true, a permissive dialer is used instead.
// Redirects are disabled unconditionally to prevent host-redirect bypass.
func defaultSourcemapClient(allowPrivate bool) *http.Client {
	return &http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: noFollowRedirects,
		Transport:     ssrfSafeTransport(allowPrivate),
	}
}

// fetchRemoteSourcemap GETs the sourcemap URL, reads up to maxSourcemapResponseSize
// bytes, and returns sourcesContent strings. ctx is propagated into the HTTP
// request so that cancellation from the caller is honored. The SSRF posture
// is established on the client argument by the caller (recoverSourcemap picks
// either defaultSourcemapClient(allowPrivate) or the user-supplied client
// wrapped with noFollowRedirects), so this function does not need to know
// about it.
func fetchRemoteSourcemap(ctx context.Context, client *http.Client, mapURL string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, mapURL, nil)
	if err != nil {
		return nil, err
	}
	// gosec G107/G704: mapURL is host-validated (sameHost) and dial-validated
	// (probe.SSRFSafeDialContext or, when AllowPrivate is true, an explicit
	// opt-in). Redirects are blocked via CheckRedirect=noFollowRedirects on
	// the default client. The taint warning here is a known false positive.
	resp, err := client.Do(req) //nolint:gosec // mapURL pre-validated; see comment above
	if err != nil {
		return nil, err
	}
	defer closeQuietly(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sourcemap fetch: HTTP %d for %s", resp.StatusCode, mapURL)
	}

	// Read the body with a size cap. No separate read deadline is needed:
	// http.Client.Timeout (set to 10 s on the sourcemap client) covers the
	// entire exchange including the response-body read, so a slow-drip sender
	// is already bounded to 10 s. The LimitReader (+1) caps memory use at
	// maxSourcemapResponseSize (10 MB) and the len check below rejects
	// exactly-at-limit responses cleanly.
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
		// Non-base64 data URIs are URL-encoded; decode before JSON parsing.
		unescaped, err := url.PathUnescape(data)
		if err != nil {
			return nil, err
		}
		raw = []byte(unescaped)
	}

	// Explicit size cap mirroring the remote-fetch limit. The trailing-window
	// scan (trailingWindowSize = 2 KB) bounds the raw data: URI string that
	// arrives here, but an attacker can embed a heavily compressed payload that
	// expands well beyond 2 KB after base64/URL decoding. Rejecting oversized
	// decoded payloads prevents memory exhaustion from adversarial inline maps.
	if len(raw) > maxSourcemapResponseSize {
		return nil, fmt.Errorf("sourcemap: inline data URI decoded payload too large (>%d bytes)", maxSourcemapResponseSize)
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
