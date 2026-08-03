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
// It wraps BishopFox/jsluice's tree-sitter URL matchers with two extensions:
// "EXPR" placeholders become OpenAPI {param} using the original template-literal
// identifiers where recoverable, and the top-level keys of a fetch/axios body
// object are emitted as a synthetic JSON body ({"a": null}) so
// rest.InferSchema produces a real object schema.
//
// # Source tagging
//
// Entries carry Source="static:js" or "static:js-sourcemap". The OpenAPI
// generator strips the prefix for x-vespasian-source ("js-bundle",
// "js-sourcemap"); any dynamic source in a group wins over both.
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
