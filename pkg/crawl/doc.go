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

// Package crawl captures HTTP traffic from web applications and exposes it as
// [ObservedRequest] values. Two crawler backends are available, selected via
// [CrawlerOptions.Headless]:
//
// Headless mode ([RodCrawler], default): uses [go-rod] to drive concurrent
// Chrome tabs. All outbound requests—XHR, fetch, dynamically constructed
// JavaScript calls—are intercepted via Chrome DevTools Protocol network
// listeners. This is the correct choice for single-page applications and any
// site that requires JavaScript execution. External .js bundles are fetched by
// the browser itself; this path does not perform separate JS file retrieval.
//
// Non-headless mode ([HTTPCrawler]): uses the Go stdlib net/http client with a
// depth-first search frontier, 150 req/s rate limiter, and a 10 MB per-page
// read cap. HTML pages are parsed with goquery (single parse per page) using
// the same link selectors as the headless path; inline <script> blocks are
// analyzed with jsluice to surface additional endpoints. Redirect chains are
// validated by a scope+SSRF guard (redirectScopeGuard, defense-in-depth) and
// the authoritative DNS-rebinding control is ssrfSafeDialContext, which
// re-resolves the host at connect time: redirects and connections that target
// private/link-local addresses (e.g. 169.254.169.254) are blocked.
//
// The headless ([RodCrawler]) path relies on Chrome's own networking stack for
// DNS resolution and does NOT have a Go dial-time IP pin. The upfront
// scopeChecker SSRF check applies, but Chrome-resolved addresses are not
// re-validated at dial time (known limitation; see crawlHeadless).
//
// The package also defines the capture file format: a JSON array of
// ObservedRequest structs that serves as the interchange format between the
// capture stage (crawl or import) and the generation stage.
//
// Key types:
//   - [Crawler] is the common interface satisfied by [RodCrawler], [HTTPCrawler],
//     and [FakeCrawler]. Use [NewCrawler] to obtain the right implementation.
//   - [RodCrawler] is the headless go-rod backend (Chrome required).
//   - [HTTPCrawler] is the non-headless stdlib net/http backend (DFS, 150 rps,
//     10 MB read cap, scope+SSRF redirect guard).
//   - [FakeCrawler] is a test double that returns a pre-configured slice of
//     [ObservedRequest] values with no network activity.
//   - [BrowserManager] manages Chrome process lifecycle, including proxy
//     configuration and graceful shutdown (headless path only).
//   - [ObservedRequest] and [ObservedResponse] represent captured HTTP traffic.
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
package crawl
