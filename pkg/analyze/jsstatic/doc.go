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

// Package jsstatic statically analyses JavaScript bundles to recover API
// endpoints, methods, path parameters and request-body field names. It runs
// between capture and classify/generate, returning the input captures with
// synthesized [crawl.ObservedRequest] entries appended.
//
// It wraps BishopFox/jsluice's tree-sitter URL matchers with three extensions:
//
//   - "EXPR" placeholders in URL paths become OpenAPI {param}, using the original
//     template-literal identifiers where recoverable.
//
//   - For fetch(url, {body: JSON.stringify({a, b})}) and axios.<m>(url, {a, b}), the
//     top-level keys of the object literal are emitted as a synthetic JSON body
//     ({"a": null, "b": null}) so pkg/generate/rest.InferSchema produces a real
//     object schema.
//
//   - Paths built by JS string concatenation that jsluice's AST analysis
//     cannot resolve — String.prototype.concat, "+"-operator chains, and
//     literal service-prefix "+"-concatenation — are reconstructed via the
//     shared crawl.ExtractStaticConcatPaths extractor (LAB-4992), with a numeric
//     sentinel ("0") substituted for non-literal operands so the REST normalizer
//     can parameterize them (e.g. /api/users/0/orders -> /api/users/{userId}/orders).
//     This makes fully-offline `generate` recover concat/service-prefix SPA
//     endpoints without a reachable target — the same forms the active,
//     network-bound crawl.ReplayJSExtracted path probes. Emitted as GET
//     candidates (a bare path carries no method) and deduped, via a
//     representation-agnostic AND origin-scoped key (numeric sentinel "0" and
//     {param} placeholders both normalized; key prefixed with the endpoint's
//     host so a same-path endpoint on a DIFFERENT host is never suppressed),
//     against the URLs the AST walkers already recovered so no phantom-GET
//     companions appear for a path recovered both ways on the same origin.
//
//     An absolute reconstruction (a bundle literal that concatenates a full
//     http(s) URL) must additionally share the bundle's own origin — scheme,
//     host AND port, via crawl.SameOrigin — enforced by the concat producer
//     itself (extractConcatEndpoints), since a speculative recombination that
//     lands on a different host or downgrades https to http is far more
//     likely an artifact or a plant than a real call site (SEC-BE-001,
//     LAB-4992).
//
//     Credential rejection, the byte policy, and scheme validity are enforced
//     once for EVERY producer (AST literal, sourcemap-recovered, and concat
//     alike) at a single synthesis choke point, specSafeURL in toRequests,
//     which runs on each endpoint's final RESOLVED URL rather than the
//     pre-resolution literal. It is deliberately parse-based, with no
//     string-prefix test: given the parsed form, (1) every byte must be
//     printable ASCII, whether raw or reached via a percent-escape, so a
//     hostile bundle cannot make a spec path key or servers entry render
//     differently from its bytes (SEC-BE-002); (2) the URL may carry no
//     userinfo, however spelled (u:p@host, the scheme-relative //u:p@host,
//     or an explicit scheme://u:p@host) — this is the credential-injection
//     sink, since ssrf.ValidateURL never inspects u.User and
//     probe.Config.AuthHeaders is set by no non-test caller, so net/http
//     would otherwise derive an `Authorization: Basic` header from an
//     attacker-chosen credential on every probe (SEC-BE-001); (3) the URL may
//     carry no opaque part (scheme:opaque-data, e.g. "mailto:x@y.com" or
//     "https:api/x" — no host, no resolvable path); and (4) any URL that
//     carries a host must use the http or https scheme (catching a
//     scheme-relative literal that resolution left without one), AND an
//     http(s)-scheme URL must carry a host — "https:/api/x" parses to
//     Scheme="https", Host="" (a single slash after the scheme is not an
//     authority marker), and without this check it produced a degenerate
//     "https://" spec server entry that sorted before every real host and
//     blanked info.title (LAB-4992 review). A hostile bundle literal cannot
//     steer the offline candidate set — or the probe stage that later
//     consumes it — at an attacker-chosen host, credential, or byte-spoofed
//     path.
//
//     Capture compatibility (QUAL-001, LAB-4992): this applies to captures whose
//     JS bundles have not ALREADY been through an older jsstatic pass.
//     pipeline.AnalyzeJS short-circuits on crawl.AnyStaticSource — "this capture
//     was produced by a stage that already ran jsstatic.Analyze" — and CrawlCmd
//     runs jsstatic at crawl time, writing static:js entries into the capture.
//     That guard's premise ("already ran jsstatic" implies "has all jsstatic
//     output") was version-independent before this change and no longer is: a
//     capture written by any pre-LAB-4992 `crawl`/`scan` build carries static:js
//     entries but NO static:js-concat entries, so `generate` skips the analysis
//     entirely and recovers no concat endpoint. Re-run the capture to pick these
//     up (documented in CLAUDE.md's Capture Format section alongside the
//     LAB-2110 precedent). Re-running the analysis instead of re-capturing is not
//     an option here: the guard is what makes `crawl | generate` byte-identical
//     to `scan`, and re-running jsstatic over a capture that already contains its
//     own output would duplicate entries. Captures from `import` (Burp/HAR/
//     mitmproxy) carry no static:js source at all, so they always exercise this
//     path regardless of the build that produced them.
//
// # Next.js App Router routes
//
// Body extraction only finds paths that exist as literals. React Server
// Components and Server Actions build their request paths at runtime, so an RSC
// bundle can contain no API path at all — a marker scan of one real 44-bundle
// capture found zero.
//
// The route is still recoverable, because the App Router names each page and
// route-handler chunk after the route's own directory:
//
//	/_next/static/chunks/app/vaults/%5BvaultId%5D/page-8ca1aac6111f15fc.js
//	  -> /vaults/{vaultId}
//
// nextroute.go derives routes from those URLs independently of the body, so it
// works on bundles that yield nothing to jsluice and on bundles whose parse
// fails outright. Route groups, parallel-route slots, private folders and
// intercepting prefixes are dropped; dynamic and catch-all segments become
// OpenAPI {param} form. Server-action endpoints remain unrecoverable statically.
//
// # Source tagging
//
// Each synthesized [crawl.ObservedRequest] carries one of Source = "static:js"
// (AST-recovered literal), "static:js-sourcemap" (from a .js.map source),
// "static:js-concat" (a never-probed concat/+-chain/service-prefix reconstruction,
// LAB-4992), "static:js-nextroute" (an App Router route handler) or
// "static:js-nextpage" (an App Router page route). The OpenAPI generator strips the
// "static:" prefix for x-vespasian-source ("js-bundle", "js-sourcemap",
// "js-bundle-concat", "js-nextroute", "js-nextpage"); the last two never appear in
// emitted output because pkg/classify Rule 6a reports both chunk sources as
// not-an-API at any --confidence (TestNextRoute_NeverAnOperationAtAnyThreshold),
// and exist so the tag vocabulary stays total. A group mixing distinct
// JS-static tags resolves to its least-confident member, not to "dynamic", which is
// reserved for a group holding a genuinely non-JS-static source. The distinct tags
// let consumers weight speculative reconstructions and chunk-URL recoveries below
// directly-observed literals.
//
// # Confidence at generation
//
// Fully offline a candidate has no probed response, so it scores only the REST
// classifier's path heuristic. RESTClassifier Rule 7 floors any JS-static candidate
// whose path carries an API indicator to the default --confidence (0.5) so these
// survive default-confidence generation instead of being dropped silently.
//
// A recovered Next.js route is deliberately exempt from that floor: the chunk URL
// proves the path is served but says nothing about which verbs the route exports, so
// a floored route would enter the spec under a guessed verb. pkg/classify needs both
// halves of the exemption. Rule 6a returns isAPI=false, the gate RunClassifiers
// applies and NearMisses ignores, so the route stays out of the spec at every
// --confidence value. Rule 6a also scores it at NextRouteProvenanceConfidence,
// pinned to classify.NearMissFloor, which is what keeps it VISIBLE under -v. Scoring
// alone was not enough — at --confidence 0.1 the routes classified and the generator
// emitted a guessed `get` — and scoring 0 drops the route below the near-miss floor
// so it appears nowhere at all, which is what happened to every route off the /api/
// path allowlist, /vaults/{vaultId} included.
//
// # Security
//
// Against attacker-controlled bundles, --analyze-js carries a bounded
// resource-exhaustion risk. jsluice/tree-sitter is not context-aware, so a
// goroutine inside it cannot be canceled. PerBundleTimeout (default 5s) bounds
// each input separately — the bundle and every sourcemap source — so one bundle
// can hold a worker for (1+N) x PerBundleTimeout, and a bundle that deadlocks the
// parser leaks its goroutine for the life of the process.
//
// Concurrency does not bound the leak: it caps how many extractions run at once,
// while a worker that times out moves on, so leaks accumulate one per timed-out
// extraction across the run — worst case one for every bundle plus every
// sourcemap source. For long-running processes over untrusted input, process
// isolation, vespasian per target under a wall-clock timeout, is the mitigation.
package jsstatic
