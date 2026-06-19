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
//
// It is the single synthesis point for the gRPC pipeline. Real reflection
// descriptors (endpoints carrying FileDescriptors) are merged first; the
// service FQNs they define are recorded. Name-only techniques (grpc-gateway,
// gRPC-Web bindings) contribute GRPCSchema.Services across all endpoints; their
// union is deduped by FQN, FQNs already covered by reflection are dropped, and
// the remainder is synthesized into descriptors in one pass. The combined set
// is rendered via protoprint.
func (g *Generator) Generate(endpoints []classify.ClassifiedRequest) ([]byte, error) {
	if len(endpoints) == 0 {
		return nil, errors.New("no endpoints provided")
	}

	// Aggregate FileDescriptors across every endpoint that carries them. A
	// single capture can hold multiple gRPC targets (or one target observed at
	// several URLs); returning on the first match would drop the rest and emit
	// an incomplete .proto. Keyed by .proto filename — the same filename is
	// expected to carry identical descriptor bytes (same import graph), so a
	// byte mismatch is a real conflict, surfaced rather than silently dropped.
	//
	// The gate keys off descriptor presence, not ReflectionEnabled: name-only
	// techniques set ReflectionEnabled=false but never populate FileDescriptors,
	// so "endpoints that carry FileDescriptors" is exactly the set of real
	// reflection descriptors.
	merged := map[string][]byte{}
	for _, ep := range endpoints {
		if ep.GRPCSchema == nil || len(ep.GRPCSchema.FileDescriptors) == 0 {
			continue
		}
		for name, raw := range ep.GRPCSchema.FileDescriptors {
			if existing, ok := merged[name]; ok {
				if !bytes.Equal(existing, raw) {
					return nil, fmt.Errorf("conflicting file descriptors for %q across gRPC endpoints", name)
				}
				continue
			}
			merged[name] = raw
		}
	}

	// Collect the FQNs already defined by the merged reflection descriptors so
	// name-only techniques never re-synthesize (and re-declare) the same
	// service in a separate synthetic file — that would be a duplicate symbol.
	reflectedFQNs := map[string]bool{}
	if len(merged) > 0 {
		reflectedFDs, err := parseDescriptorSet(merged)
		if err != nil {
			return nil, err
		}
		reflectedFQNs = reflectedServiceFQNs(reflectedFDs)
	}

	// Union the name-only recovered Services across all endpoints, deduped by
	// FQN with reflection-covered FQNs dropped, then synthesize the remainder
	// in a single call. Synthetic filenames are namespaced (synthetic.proto)
	// and cannot key-collide with reflection filenames.
	if synthServices := unionRecoveredServices(endpoints, reflectedFQNs); len(synthServices) > 0 {
		synthFDs, err := FileDescriptorsFromServices(synthServices)
		if err != nil {
			return nil, err
		}
		for name, raw := range synthFDs {
			merged[name] = raw
		}
	}

	if len(merged) == 0 {
		return nil, errors.New("gRPC spec generation requires server reflection or recovered service names; none available")
	}

	return renderProto(merged)
}

// reflectedServiceFQNs returns the set of fully-qualified service names defined
// by the given parsed reflection descriptors.
func reflectedServiceFQNs(fds map[string]*desc.FileDescriptor) map[string]bool {
	out := map[string]bool{}
	for _, fd := range fds {
		for _, sd := range fd.GetServices() {
			out[sd.GetFullyQualifiedName()] = true
		}
	}
	return out
}

// unionRecoveredServices collects Services across all endpoints, dedupes by FQN
// (first occurrence in endpoint order wins), and drops any FQN already defined
// by the reflection descriptors. Methods are not merged across duplicate FQNs:
// the first service definition for an FQN is kept (gateway/bindings methods for
// the same FQN are name-only duplicates).
func unionRecoveredServices(endpoints []classify.ClassifiedRequest, reflectedFQNs map[string]bool) []classify.GRPCService {
	seen := map[string]bool{}
	var out []classify.GRPCService
	for _, ep := range endpoints {
		if ep.GRPCSchema == nil {
			continue
		}
		for _, svc := range ep.GRPCSchema.Services {
			fqn := strings.TrimPrefix(svc.Name, ".")
			if reflectedFQNs[fqn] || seen[fqn] {
				continue
			}
			seen[fqn] = true
			out = append(out, svc)
		}
	}
	return out
}

// renderProto reconstructs the descriptor graph from wire bytes and emits
// proto3 source via protoprint. It is a thin wrapper retained for callers that
// want a one-shot parse-then-print; Generate uses parseDescriptorSet and
// printDescriptors separately so it can inspect the parsed graph (to extract
// reflected service FQNs) before printing.
func renderProto(fileDescriptors map[string][]byte) ([]byte, error) {
	fds, err := parseDescriptorSet(fileDescriptors)
	if err != nil {
		return nil, err
	}
	return printDescriptors(fds)
}

// parseDescriptorSet reconstructs the descriptor graph from wire bytes.
func parseDescriptorSet(fileDescriptors map[string][]byte) (map[string]*desc.FileDescriptor, error) {
	fdProtos := make([]*descriptorpb.FileDescriptorProto, 0, len(fileDescriptors))
	for _, raw := range fileDescriptors {
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
	return fds, nil
}

// printDescriptors emits proto3 source for user-defined files via protoprint.
// google.protobuf.* well-known files are skipped from output since any consumer
// of the .proto already has them. Output is deterministic: filenames are
// sorted, and within each file protoprint sorts elements.
func printDescriptors(fds map[string]*desc.FileDescriptor) ([]byte, error) {
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
