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

// Package crawl captures HTTP traffic and exposes it as [ObservedRequest] values.
// Two backends, selected by [CrawlerOptions.Headless]:
//
// Headless ([RodCrawler], default) drives concurrent Chrome tabs via [go-rod] and
// intercepts every outbound request through CDP network listeners. Required for
// SPAs. The browser fetches .js bundles itself. Each page settles on network quiet
// rather than a fixed window ([DefaultNetworkIdleFloor], [DefaultNetworkQuietPeriod],
// [DefaultPerRequestTimeout] and the per-page timeout bound it), so late and dynamic
// requests are still captured. Captured requests are scope-filtered like frontier
// links, except that a JavaScript body is retained even out of scope, because
// pkg/analyze/jsstatic has no other input. URLs differing only in query string are
// DISTINCT pages, capped at [maxQueryVariantsPerPath] per path: ?page=2 and
// ?tab=billing select a different page, not a different row of the same one. The
// scope predicate also learns the seed's EFFECTIVE origin from the seed's own
// navigation, so a seed that redirects http -> https or apex -> www does not discard
// every capture; the widening is one-shot, still SSRF-gated, reported on Stderr, and
// bounded to the seed's own host or a leading-"www." variant — a sibling subdomain or
// foreign domain is refused, which is what --scope same-domain is for.
//
// An opt-in interaction pass ([CrawlerOptions.Interact], headless only, off by
// default; the net/http backend warns and ignores it) clicks a bounded set of
// controls per page to surface endpoints that only fire on interaction. It matches
// form submit buttons too, so it submits forms and can mutate state; destructive,
// session-ending and irreversible-commit labels are skipped on a best-effort match,
// and a click that navigates returns the tab to its assigned page so no surface is
// attributed to a document the worker was not assigned.
//
// Non-headless ([HTTPCrawler]) uses net/http with a DFS frontier, a 150 req/s
// limiter and a 10 MB per-page read cap. goquery parses each page once with the
// same link selectors as the headless path; jsluice reads inline <script> blocks.
//
// [FakeCrawler] is the no-network test double for [Crawler].
//
// # Browser binary (LAB-4999)
//
// The headless path pins [BrowserOptions.ChromePath] or the system browser from
// launcher.LookPath, and will NOT let go-rod auto-download a Chromium from
// third-party mirrors — a supply-chain risk and nondeterministic egress. With no
// system browser it errors unless [BrowserOptions.AllowBrowserDownload] or
// VESPASIAN_ALLOW_BROWSER_DOWNLOAD=true opts in, for dev platforms with no Chrome
// build. It also sets telemetry-disabling launch flags.
//
// # SSRF
//
// On the HTTP path ssrfSafeDialContext is authoritative: it re-resolves at connect
// time, so redirects and connections to private or link-local addresses
// (169.254.169.254) are blocked. redirectScopeGuard is defense in depth.
//
// The headless path has NO Go dial-time pin — Chrome resolves DNS itself, so only
// the upfront scopeChecker check applies and Chrome-resolved addresses are never
// re-validated. Known limitation; see crawlHeadless.
//
// # Proxy support (LAB-4011)
//
// Both backends honor [CrawlerOptions.Proxy] (http/https/socks5, validated by
// [ValidateProxyAddr]), and since LAB-4993 so do probe and JS replay, so --proxy is
// no longer crawl-only. Two consequences of routing through an intercepting proxy:
//
//   - TLS verification stays ON. [CrawlerOptions.ProxyInsecure]
//     (--proxy-insecure) disables it for an http/https MITM proxy, HTTP backend
//     only: the headless path validates against the OS trust store, so trust the
//     proxy CA out of band there. socks5 always verifies, since the Go client does
//     TLS to the target through the tunnel.
//   - No dial-time SSRF pin is installed for proxy connections: the client dials
//     the proxy, usually loopback, so pinning would block the proxy and protect
//     nothing. URL-level scope still applies, so a private target still needs
//     AllowPrivate, and rebinding protection is delegated to the proxy.
//
// # Page budget (LAB-4678)
//
// [CrawlerOptions.MaxPages] counts pages, not captured requests — one SPA page
// fires dozens of XHR calls. Workers reserve a slot before navigating, so the cap
// is exact, and reaching it does NOT cancel the browser context: in-flight pages
// finish their bounded visit and emit everything they captured.
//
// # JS replay
//
// After a headless crawl, [ReplayJSExtracted] scans captured JS bundles for API
// path strings and probes them over raw HTTP, recovering endpoints the browser
// cannot exercise: paths gated behind interaction, paths built by runtime
// concatenation, and paths a browser can only reach by navigating, where an SPA
// serves its shell instead. Raw HTTP does not escape a server-side catch-all,
// though: a wrong path still returns that shell, which is why fetchJSBodyHop
// filters HTML.
//
// Recognized forms are quoted paths, template literals, full URLs,
// literal+literal `+` prefixes, and identifier-bearing concatenation via
// String.prototype.concat or `+` (LAB-1368) — the last substitutes a numeric
// sentinel for non-literal operands so the path stays probeable and
// parameterizable. Runs under a same-origin gate and pkg/ssrf unless AllowPrivate.
//
// # Session cookies (LAB-2222)
//
// [ExtractCookieHeader] pulls the Cookie header out, [ParseCookiesToParams]
// converts it, and the result is set on the browser before navigating. Cookies
// must go through the CDP Storage domain rather than Network.setExtraHTTPHeaders:
// only those survive redirects, new tabs and page-initiated fetch().
//
// The package also defines the capture format: a JSON array of ObservedRequest,
// the interchange between the capture and generation stages.
//
// # Cross-run resume (LAB-4678 Phase 4)
//
// [Checkpoint] serializes the frontier's pending queue and seen-set so coverage
// accumulates across separate crawls, gated by [ComputeConfigFingerprint] and
// [DefaultCheckpointMaxAge]. Both backends honor it; drive it through
// [CrawlerOptions.ResumeFrom] and [CrawlerOptions.OnCheckpoint], which also fires on
// budget truncation and cancellation, the case resume exists for. A checkpoint is
// parsed input, not trusted in-process state: restored entries are re-validated
// against depth and scope, and a fingerprint or age mismatch is reported on Stderr
// and ignored, so a config change costs a re-crawl rather than a failed run. Storing
// it between runs is the host's concern. See [Checkpoint] for the seen-set lifecycle
// the host owns and for transient-failure requeue.
//
// [go-rod]: https://github.com/go-rod/rod
package crawl
