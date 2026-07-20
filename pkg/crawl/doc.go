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
// Proxy support (LAB-4011): both backends honor [CrawlerOptions.Proxy]
// (http/https/socks5), validated by [ValidateProxyAddr]. On the HTTP path the
// proxy is wired into the transport via http.ProxyURL. Two consequences follow
// from routing through an intercepting proxy (Burp, mitmproxy):
//   - TLS certificate verification stays ON by default. For an http/https
//     intercepting proxy it can be disabled (InsecureSkipVerify) only by the
//     explicit opt-in [CrawlerOptions.ProxyInsecure] (--proxy-insecure), so the
//     proxy's own MITM certificate is accepted. This opt-in applies to the HTTP
//     backend only; on the headless path Chrome validates against the OS trust
//     store, so the operator must trust the proxy CA out-of-band and
//     --proxy-insecure has no effect there. For socks5 proxies the Go client
//     does TLS directly with the target through the tunnel, so verification is
//     always kept regardless of ProxyInsecure.
//   - The dial-time SSRF pin (ssrfSafeDialContext) is NOT installed for proxy
//     connections: the client dials the proxy (commonly loopback), not the
//     target, so pinning the dialed IP would block the proxy and gives no
//     target protection. The upfront scopeChecker SSRF check and
//     redirectScopeGuard still confine targets at the URL level, so crawling a
//     private target through a proxy still requires AllowPrivate. DNS-rebinding
//     protection at the target is delegated to the trusted proxy.
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
// After the headless crawl, the package runs a post-crawl JS extraction
// step that scans response bodies of JavaScript bundles for API path
// strings and probes them with raw HTTP requests. This recovers endpoints
// that the headless browser cannot exercise (paths gated behind user
// interactions or built from runtime string concatenations) and bypasses
// SPA catch-all routing that would otherwise return index.html instead of
// API responses. The extractor recognizes quoted-string paths, template
// literals, full URLs, literal+literal `+` service-prefix concatenations,
// and identifier-bearing concatenations using either String.prototype.concat
// or the `+` operator (LAB-1368) — the last form reconstructs a path by
// substituting a numeric sentinel for non-literal operands so the result is
// probeable and the REST normalizer can parameterize it.
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
//   - [ValidateProxyAddr] validates a proxy address (http/https/socks5, host
//     required, no embedded credentials) for both backends.
//   - [ObservedRequest] and [ObservedResponse] represent captured HTTP traffic.
//   - [JSReplayConfig] and [ReplayJSExtracted] implement the post-crawl JS
//     bundle scanning step. The replay step enforces a same-origin gate
//     (auth headers and probes are restricted to the scan target's origin
//     by default) and uses [github.com/praetorian-inc/vespasian/pkg/ssrf]
//     for SSRF protection unless the operator explicitly opts out via
//     AllowPrivate.
//   - [ExtractStaticConcatPaths] is the network-free subset of the concat /
//     service-prefix reconstruction, shared with pkg/analyze/jsstatic (LAB-4992)
//     so the fully-offline static analyzer reconstructs these forms identically
//     to the active replay path. The active path (extractAPIPaths) runs the same
//     underlying extractors — extractConcatPaths AND servicePrefixPlusPaths — so
//     both paths recover the concat/+-chain and literal service-prefix forms
//     identically; the active path additionally probes them and does a
//     speculative service-prefix fan-out that the offline path omits (that
//     fan-out is only safe when 404-filtered by probing).
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
