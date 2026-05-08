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
//   - Path normalization replaces dynamic path segments with parameterized
//     templates. Single-path detection covers UUIDs, MongoDB ObjectIDs,
//     numeric IDs, short hex hashes, and base64/base64url tokens.
//     Observation-based detection ([NormalizePathsWithNames]) additionally
//     identifies slug-style identifiers when multiple distinct values are
//     observed at the same path position. Known literals (`me`, `current`,
//     `self`, `new`, `list`, `search`) are preserved against all forms of
//     parameterization.
//   - Schema inference examines response JSON to generate OpenAPI schema
//     objects with depth and property guards.
package rest
