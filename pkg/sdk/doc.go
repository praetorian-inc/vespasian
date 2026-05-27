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

// Package sdk integrates Vespasian into the Chariot platform as a capability.
// It implements the [capability.Capability] interface for [capmodel.WebApplication]
// inputs, bridging the headless-browser crawl → classify → probe → generate
// pipeline with the Chariot capability execution model.
//
// Exported surface: [Capability] (implements capability.Capability), [ClassifyProbeGenerate],
// [DetectAPIType], [ClassifiersForType], [BuildWSDLProbeClient], [BuildWSDLProbeURL],
// [IsRejectedWSDLStatus], [IsAcceptableWSDLContentType], and [ProbeStrategiesForType].
//
// SSRF note: The SDK enforces fail-closed SSRF protection for both the crawl
// frontier and the WSDL probe. Private/loopback targets (e.g., 127.0.0.1,
// RFC1918 addresses) are rejected even though [Capability.Match] accepts them
// under the Chariot trusted-seed model. To scan a private or internal SOAP
// service, use the CLI with --dangerous-allow-private instead of this package.
package sdk
