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

// Package grpc generates .proto specifications from classified gRPC endpoints.
//
// Phase 1: When an endpoint carries reflection-derived FileDescriptors, the
// generator builds the descriptor graph and renders proto3 files via
// protoprint, producing output directly consumable by protoc and buf generate.
//
// Phase 2: Traffic-only inference is not supported — gRPC's wire format strips
// field names, so reconstructing .proto from observed traffic alone is not
// reliable. Generate returns an error when no reflection data is present.
package grpc
