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

// Package probe enriches classified API endpoints with additional information
// gathered through active HTTP requests. Each probe strategy implements
// [ProbeStrategy] and targets a specific API type.
//
// Strategies:
//   - [OptionsProbe]: sends OPTIONS requests to discover allowed HTTP methods.
//   - [SchemaProbe]: infers JSON schema from endpoint responses.
//   - [WSDLProbe]: fetches ?wsdl documents from SOAP service URLs.
//   - [GraphQLProbe]: runs tiered introspection queries (3 tiers for WAF bypass)
//     and falls back to traffic-based inference when introspection is disabled.
//   - [GRPCProbe]: enumerates services, methods, and message types via the
//     gRPC Server Reflection Protocol (v1 with v1alpha fallback), capturing the
//     transitive FileDescriptorProto closure for downstream .proto generation.
//     When the server is reachable but reflection is not registered (gRPC
//     Unimplemented), the probe returns a structured GRPCReflectionResult
//     with ReflectionEnabled=false to distinguish "probed but disabled" from
//     "not probed at all" (which is signaled by a nil result).
//   - [GRPCGatewayProbe]: reflection-off recovery of gRPC service/method names
//     from a grpc-gateway/Envoy OpenAPI (swagger) document served alongside the
//     HTTP/JSON transcoding gateway. Scrapes a bounded set of well-known
//     document paths over HTTP, recognizes grpc-gateway documents by their
//     operationId/tags shape, and records the recovered service names on the
//     endpoint's GRPCSchema. The scraped path set is a fixed, small list of
//     common literals; per-service swagger files (/openapiv2/<service>.swagger.json)
//     are intentionally not enumerated (the service name is unknown before
//     scraping and the list is bounded for SSRF hygiene). It does not synthesize
//     descriptors itself —
//     descriptor generation from those names is deferred to pkg/generate/grpc.
//     Defers to a reflection result when one is already present (reflection has
//     real message fields).
//
// SSRF protection is built in: [ValidateProbeURL] blocks requests to private
// and loopback addresses (RFC 1918, RFC 4193, link-local) with DNS rebinding
// mitigation. [SSRFSafeDialContext] provides a net.Dialer-compatible dial
// function that re-checks resolved IPs at connect time, eliminating the
// TOCTOU window between DNS validation and connection. This can be bypassed
// with --dangerous-allow-private for testing internal targets.
//
// Probing is also gated to the scan's own origin (SEC-BE-001): the single
// probe.Config construction site in internal/pipeline wraps [Config.URLValidator]
// (composed with, not replacing, the SSRF check above) so that any classified
// candidate whose URL does not share the scan target's scheme+host+port —
// including a candidate promoted purely by classify's offline JS-static
// confidence floor, which carries no probed response of its own — is skipped
// rather than probed. This mirrors pkg/crawl's JSReplayConfig.AllowCrossOrigin:
// internal-only, default false, no CLI flag; --dangerous-allow-private
// disables only the SSRF check above, never this origin gate.
//
// [RunStrategies] applies a set of strategies to classified requests and
// returns the enriched results along with any non-fatal probe errors.
package probe
