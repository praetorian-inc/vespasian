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
// matchers, with three extensions over the upstream library:
//
//   - "EXPR" placeholders in URL paths are normalised to OpenAPI {param}
//     form using the names of the original template-literal identifiers when
//     they can be recovered.
//   - For fetch(url, {body: JSON.stringify({a, b})}) and axios.<m>(url, {a, b})
//     calls, the names of the top-level keys of the object literal are
//     captured as body parameter names. They are emitted as a synthesized
//     JSON body ({"a": null, "b": null}) so the existing
//     pkg/generate/rest.InferSchema produces an object schema downstream.
//   - Paths built by JS string concatenation that jsluice's AST analysis
//     cannot resolve — String.prototype.concat, "+"-operator chains, and
//     literal service-prefix "+"-concatenation — are reconstructed via the
//     shared crawl.ExtractStaticConcatPaths extractor (LAB-4992), with a numeric
//     sentinel ("0") substituted for non-literal operands so the REST normalizer
//     can parameterize them (e.g. /api/users/0/orders -> /api/users/{userId}/orders).
//     This makes fully-offline `generate` recover concat/service-prefix SPA
//     endpoints without a reachable target — the same forms the active,
//     network-bound crawl.ReplayJSExtracted path probes. Emitted as GET
//     candidates (a bare path carries no method) and deduped against the URLs
//     the AST walkers already recovered so no phantom-GET companions appear.
//
// # Source tagging
//
// Each synthesized [crawl.ObservedRequest] carries Source = "static:js" or
// "static:js-sourcemap". The OpenAPI generator strips the "static:" prefix
// when emitting the x-vespasian-source extension on each operation
// ("static:js" -> "js-bundle", "static:js-sourcemap" -> "js-sourcemap";
// any dynamic-source group resolves to "dynamic", which wins on mixed groups).
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
