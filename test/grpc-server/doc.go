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

// Package main provides a simple gRPC server for live testing of vespasian.
//
// Registers three reflectable services — UserService (with one server-stream),
// OrderService, and AccountService — defined in lab.proto. Server Reflection
// is enabled so vespasian's GRPCProbe can enumerate everything end-to-end.
//
// Usage:
//
//	go run ./test/grpc-server                # listens on :50051 (or $GRPC_PORT)
//	./grpc-server -port 50052                # override port via flag
//
// Validate with:
//
//	# build a one-line capture for a gRPC method, then generate the .proto
//	vespasian generate grpc capture.json --dangerous-allow-private -o lab.proto
package main
