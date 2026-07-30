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
// endpoints, methods, path parameters, and request-body field names.
//
// It is invoked between the capture stage (pkg/crawl, pkg/importer) and the
// classify/generate stages (pkg/classify, pkg/generate). It returns the input
// captures unchanged, with newly synthesized [crawl.ObservedRequest] entries
// appended (Source = "static:js" or "static:js-sourcemap").
//
// The analyser is a thin wrapper over BishopFox/jsluice's tree-sitter URL
// matchers, with two extensions over the upstream library:
//
//   - "EXPR" placeholders in URL paths are normalised to OpenAPI {param}
//     form using the names of the original template-literal identifiers when
//     they can be recovered.
//   - For fetch(url, {body: JSON.stringify({a, b})}) and axios.<m>(url, {a, b})
//     calls, the names of the top-level keys of the object literal are
//     captured as body parameter names. They are emitted as a synthesized
//     JSON body ({"a": null, "b": null}) so the existing
//     pkg/generate/rest.InferSchema produces an object schema downstream.
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
// Each synthesized [crawl.ObservedRequest] carries one of Source = "static:js",
// "static:js-sourcemap", "static:js-nextroute" (an App Router route handler) or
// "static:js-nextpage" (an App Router page route). Neither Next.js tag carries an
// API signal: the chunk URL proves the path is served but not which verbs the
// route exports, so recovered routes surface as sub-threshold near-misses under
// -v rather than as invented operations in the spec. pkg/classify scores them at
// NextRouteProvenanceConfidence for exactly that: it sits at classify.NearMissFloor,
// which is the level the -v near-miss report filters on. Scoring them at 0 instead
// made this sentence false for every route off the /api/ path allowlist — including
// the /vaults/{vaultId} example above, which then appeared nowhere at all.
// The OpenAPI generator strips the "static:" prefix when emitting the
// x-vespasian-source extension on each operation ("static:js" -> "js-bundle",
// "static:js-sourcemap" -> "js-sourcemap"; any dynamic-source group resolves to
// "dynamic", which wins on mixed groups).
//
// # Security and Operator Considerations
//
// When analyzing attacker-controlled JavaScript bundles (i.e., when the crawled
// application serves malicious content), enabling --analyze-js carries a bounded
// resource-exhaustion risk. The underlying jsluice/tree-sitter parser is not
// context-aware: if it hangs on adversarial input, the per-bundle goroutine will
// remain in-flight until jsluice returns (it cannot be canceled). Per-bundle and
// per-source timeouts (PerBundleTimeout, default 5s) bound wait time per input,
// but a bundle that causes the parser to deadlock will leak that goroutine for
// the duration of the process. The worst-case number of leaked goroutines is
// Concurrency × (1 + N) where N is the number of sourcesContent entries in
// a recovered sourcemap. Operators analyzing untrusted bundles in long-running
// processes should be aware of this residual risk; process isolation (running
// vespasian per-target with a wall-clock timeout) is the recommended mitigation.
package jsstatic
