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
