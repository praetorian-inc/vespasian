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
package pipeline
