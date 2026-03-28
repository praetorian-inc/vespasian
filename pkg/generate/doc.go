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

// Package generate defines the [SpecGenerator] interface for producing API
// specifications from classified requests, and provides a registry for looking
// up generators by API type.
//
// Generators are implemented in sub-packages:
//   - [rest]: OpenAPI 3.0 (YAML) from REST traffic
//   - [graphql]: GraphQL SDL from introspection or traffic inference
//   - [wsdl]: WSDL XML from SOAP traffic
//
// Use [Get] to retrieve a generator by API type name, and [SupportedTypes] to
// list all registered generators.
package generate
