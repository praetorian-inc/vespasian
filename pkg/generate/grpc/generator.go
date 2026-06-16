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

package grpc

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/jhump/protoreflect/desc"            //nolint:staticcheck // SA1019: protoprint requires v1 desc; no v2 equivalent exists
	"github.com/jhump/protoreflect/desc/protoprint" //nolint:staticcheck // SA1019: protoprint requires v1 desc; no v2 equivalent exists
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"

	"github.com/praetorian-inc/vespasian/pkg/classify"
)

// Generator produces .proto specifications from classified gRPC requests.
type Generator struct{}

// APIType returns the API type this generator supports.
func (g *Generator) APIType() string {
	return "grpc"
}

// DefaultExtension returns the default file extension for .proto output.
func (g *Generator) DefaultExtension() string {
	return ".proto"
}

// Generate produces a .proto specification from classified gRPC endpoints.
// Phase 1: If any endpoint has reflection FileDescriptors, render them via
// protoprint. Phase 2: traffic-only inference is unsupported.
func (g *Generator) Generate(endpoints []classify.ClassifiedRequest) ([]byte, error) {
	if len(endpoints) == 0 {
		return nil, errors.New("no endpoints provided")
	}

	for _, ep := range endpoints {
		if ep.GRPCSchema != nil && ep.GRPCSchema.ReflectionEnabled && len(ep.GRPCSchema.FileDescriptors) > 0 {
			return renderProto(ep.GRPCSchema)
		}
	}

	return nil, errors.New("gRPC spec generation requires server reflection; no FileDescriptors available")
}

// renderProto reconstructs the descriptor graph from wire bytes and emits
// proto3 source via protoprint. google.protobuf.* well-known files are
// skipped from output since any consumer of the .proto already has them.
// Output is deterministic: filenames are sorted, and within each file
// protoprint sorts elements.
func renderProto(schema *classify.GRPCReflectionResult) ([]byte, error) {
	fdProtos := make([]*descriptorpb.FileDescriptorProto, 0, len(schema.FileDescriptors))
	for _, raw := range schema.FileDescriptors {
		var fdp descriptorpb.FileDescriptorProto
		if err := proto.Unmarshal(raw, &fdp); err != nil {
			return nil, fmt.Errorf("unmarshal file descriptor: %w", err)
		}
		fdProtos = append(fdProtos, &fdp)
	}

	fds, err := desc.CreateFileDescriptorsFromSet(&descriptorpb.FileDescriptorSet{File: fdProtos})
	if err != nil {
		return nil, fmt.Errorf("build descriptor graph: %w", err)
	}

	names := make([]string, 0, len(fds))
	for name := range fds {
		if strings.HasPrefix(name, "google/protobuf/") {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)

	if len(names) == 0 {
		return nil, errors.New("no user-defined .proto files in reflection result")
	}

	printer := &protoprint.Printer{SortElements: true}
	var buf bytes.Buffer
	for _, name := range names {
		if buf.Len() > 0 {
			buf.WriteString("\n// ---\n\n")
		}
		if err := printer.PrintProtoFile(fds[name], &buf); err != nil {
			return nil, fmt.Errorf("print %s: %w", name, err)
		}
	}
	return buf.Bytes(), nil
}
