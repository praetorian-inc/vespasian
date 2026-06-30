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

// Package grpcwire parses the gRPC length-prefixed framing and the protobuf
// wire format used inside it. It is foundation for a future traffic-based
// RPC inference path and is not yet wired into the classifier, probe, or
// generator, which currently rely on server-reflection descriptors.
//
// Reference: https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md
package grpcwire
