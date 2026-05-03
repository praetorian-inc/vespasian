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

// Package crawl drives a headless Chrome browser to capture HTTP traffic from
// web applications. It intercepts all outbound requests—including XHR, fetch,
// and dynamically constructed calls from JavaScript—and records them as
// [ObservedRequest] values.
//
// In headless mode (default), the package uses [go-rod] directly to run
// concurrent browser tabs, overlapping DOM stability waits for significantly
// faster crawls. In non-headless mode (--headless=false), it falls back to
// [Katana]'s standard HTTP engine.
//
// The package also defines the capture file format: a JSON array of
// ObservedRequest structs that serves as the interchange format between the
// capture stage (crawl or import) and the generation stage.
//
// After the headless crawl, the package runs a post-crawl JS extraction
// step that scans response bodies of JavaScript bundles for API path
// strings and probes them with raw HTTP requests. This recovers endpoints
// that the headless browser cannot exercise (paths gated behind user
// interactions or built from runtime string concatenations) and bypasses
// SPA catch-all routing that would otherwise return index.html instead of
// API responses.
//
// Key types:
//   - [Crawler] orchestrates a browser crawl with configurable depth,
//     page limits, timeouts, concurrency, and scope restrictions.
//   - [BrowserManager] manages Chrome process lifecycle, including proxy
//     configuration and graceful shutdown.
//   - [ObservedRequest] and [ObservedResponse] represent captured HTTP traffic.
//   - [JSReplayConfig] and [ReplayJSExtracted] implement the post-crawl JS
//     bundle scanning step. The replay step enforces a same-origin gate
//     (auth headers and probes are restricted to the scan target's origin
//     by default) and uses [github.com/praetorian-inc/vespasian/pkg/ssrf]
//     for SSRF protection unless the operator explicitly opts out via
//     AllowPrivate.
//
// Session-cookie helpers (LAB-2222) let callers bootstrap Chrome's cookie
// store from a user-supplied Cookie header so subsequent navigations are
// authenticated. Callers typically extract a Cookie header from their input
// headers, convert it to CDP cookie parameters for the target origin, and
// set those on the browser before navigation:
//   - [ExtractCookieHeader] separates Cookie values (case-insensitively)
//     from the remaining headers, returning a concatenated cookie string
//     and a map of the non-cookie headers.
//   - [ParseCookiesToParams] converts a Cookie header value into CDP
//     [proto.NetworkCookieParam] entries scoped to the target URL's host
//     and scheme. Rejects non-http(s) or hostless target URLs.
//
// [go-rod]: https://github.com/go-rod/rod
// [Katana]: https://github.com/projectdiscovery/katana
package crawl
