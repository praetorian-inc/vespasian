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

// Package classify separates API calls from static assets and other non-API
// traffic using confidence-based heuristic rules. Each classifier implements
// [APIClassifier] and returns a boolean plus a confidence score (0.0–1.0).
//
// Supported API types:
//   - REST: detected via content-type, path patterns (/api/, /v1/), HTTP
//     methods, and response structure. Static assets are excluded.
//   - GraphQL: detected via /graphql path, query syntax in POST body, and
//     data/errors keys in response JSON.
//   - WSDL/SOAP: detected via SOAPAction header, SOAP envelope in body, and
//     ?wsdl URL parameter.
//
// [RunClassifiers] applies one or more classifiers to a slice of observed
// requests, returning only those that exceed the confidence threshold.
// [Deduplicate] removes duplicate endpoints based on method, normalized URL,
// and (for non-empty bodies) Content-Type plus an 8-byte body fingerprint.
// Bodyless requests still collapse by method and path. Distinct request body
// shapes on the same endpoint+content-type survive as separate entries so
// downstream merge logic can union their fields.
package classify
