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

// Package pipeline contains the shared crawl → classify → probe → generate
// orchestration consumed by both the cmd/vespasian CLI and the pkg/sdk
// Capability. The package is internal because it is an implementation
// detail of vespasian; external consumers should use pkg/sdk.Capability,
// which exposes the pipeline through the capability-sdk interface.
//
// The package exposes these orchestration primitives:
//
//   - DetectAPIType, ClassifiersForType, StrategiesForType — classification
//     routing helpers keyed by API type.
//   - ClassifyProbeGenerate — the classify → probe → generate step.
//   - ResolveWSDLType, ProbeWSDLDocument, ProbeAndAppendWSDLRequest — active
//     WSDL discovery shared by both surfaces.
//   - Augment / AnalyzeJS — captured-request augmentation. Augment runs the
//     canonical static-HTML-forms-then-JS-static order; AnalyzeJS runs only the
//     JS-bundle stage (used by CrawlCmd, which defers form extraction to
//     generate time).
//   - ResolveAndGenerate — the bundled detect → wsdl-resolve →
//     (optional AfterWSDL hook) → classify/probe/generate sequence. Its
//     AfterWSDL hook lets the CLI keep its JS-replay step in position while the
//     SDK passes nil.
package pipeline
