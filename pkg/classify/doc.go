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
//     methods, and response structure. A request-side signal (an API path plus
//     a JSON/XML Accept or request content-type) also classifies an endpoint
//     whose response was not captured, so the verdict does not depend on
//     response timing. Static assets are excluded. [DefaultConfidenceThreshold]
//     is the default minimum confidence.
//   - GraphQL: detected via /graphql path, query syntax in POST body, and
//     data/errors keys in response JSON.
//   - WSDL/SOAP: detected via SOAPAction header, SOAP envelope in body, and
//     ?wsdl URL parameter.
//   - gRPC: detected via application/grpc* content-type, grpc-status /
//     grpc-message response headers, or POST + /<pkg.Service>/<Method> path.
//
// [RunClassifiers] applies one or more classifiers to a slice of observed
// requests, returning only those that exceed the confidence threshold.
// [Deduplicate] removes duplicate endpoints based on method, normalized URL,
// and (for non-empty bodies) Content-Type plus an 8-byte body fingerprint.
// Bodyless requests still collapse by method and path. Distinct request body
// shapes on the same endpoint+content-type survive as separate entries so
// downstream merge logic can union their fields. When duplicate observations
// carry different responses, the retained response is selected deterministically
// (a populated response is preferred over a half-captured empty one, with a
// stable content-fingerprint tie-break) so a fixed capture yields the same
// documented response regardless of observation order.
//
// [MergeUniqueOrdered] provides an order-preserving set-union for []string
// slices, capped at [crawl.MaxQueryParamValues] entries; it is used by
// [Deduplicate] to union per-key query-parameter values across duplicate
// observations.
//
// The [ClassifiedRequest.MultiValueQueryKeys] field records which
// query-parameter keys carried multiple values in a single observation,
// allowing downstream OpenAPI generation (pkg/generate/rest) to emit
// array-typed parameters with explode=true rather than scalar string fields.
package classify
