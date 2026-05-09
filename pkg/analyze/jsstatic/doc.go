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
// # Source tagging
//
// Each synthesized [crawl.ObservedRequest] carries Source = "static:js" or
// "static:js-sourcemap". The OpenAPI generator strips the "static:" prefix
// when emitting the x-vespasian-source extension on each operation
// ("static:js" -> "js-bundle", "static:js-sourcemap" -> "js-sourcemap";
// any dynamic-source group resolves to "dynamic", which wins on mixed groups).
package jsstatic
