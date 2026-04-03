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
// The package also provides [ParseWSDL] for parsing and validating WSDL XML
// documents, and type definitions for WSDL XML unmarshaling.
package wsdl
