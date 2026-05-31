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

// Package wsdl generates WSDL specifications from classified SOAP requests.
// It supports two generation modes:
//
//   - Document-based: when a ?wsdl probe fetches an existing WSDL document,
//     it is returned directly after validation.
//   - Inference-based: when no WSDL document is available, the package infers
//     WSDL operations from observed SOAPAction headers and SOAP envelope
//     structures in the captured traffic.
//
// In inference mode, the package also extracts typed parameters from observed
// SOAP request bodies and populates the generated WSDL's <types> section with
// inferred XSD element definitions for each operation.
//
// Type inference applies rules in this order: (1) xsi:type attribute wins;
// (2) nested child elements produce a complex type; (3) empty text is skipped;
// (4–8) value heuristics match boolean, integer, decimal, date, and dateTime;
// (9) anything else falls back to xsd:string.
//
// When the same operation appears in multiple captures, parameter observations
// are unioned: new parameters are appended, and the first-observed XSD type
// wins on conflict. Recursion is capped at maxBodyDepth = 32 levels to prevent
// pathological inputs from causing unbounded stack growth.
//
// Extraction is best-effort on malformed input: when an XML stream is truncated
// mid-envelope, the parameters collected before the truncation are preserved
// rather than discarded, so a partial body still contributes what it observed.
//
// The generated WSDL's targetNamespace (shared by the definitions element, the
// tns prefix, and the embedded XSD schema) is taken from the namespace observed
// on the SOAP operation elements, so the service's real namespace is preserved
// in the output. It falls back to a URL-derived namespace when the traffic
// carried no operation namespace or when different operations disagreed.
//
// The package also provides [ParseWSDL] for parsing and validating WSDL XML
// documents, and type definitions for WSDL XML unmarshaling.
package wsdl
