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

// Package graphql generates GraphQL SDL (Schema Definition Language)
// specifications from classified requests. It supports two generation modes:
//
//   - Introspection-based: when the probe stage successfully runs a GraphQL
//     introspection query, the full type system is converted to SDL.
//   - Traffic-based inference: when introspection is disabled, the package
//     infers a partial schema from observed queries and mutations in the
//     captured traffic.
//
// The [Generator] type implements the [generate.SpecGenerator] interface.
package graphql
