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

	// Aggregate FileDescriptors across every reflection-enabled endpoint. A
	// single capture can hold multiple gRPC targets (or one target observed at
	// several URLs); returning on the first match would drop the rest and emit
	// an incomplete .proto. Keyed by .proto filename — the same filename is
	// expected to carry identical descriptor bytes (same import graph), so a
	// byte mismatch is a real conflict, surfaced rather than silently dropped.
	merged := map[string][]byte{}
	for _, ep := range endpoints {
		if ep.GRPCSchema == nil || !ep.GRPCSchema.ReflectionEnabled {
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

	if len(merged) == 0 {
		return nil, errors.New("gRPC spec generation requires server reflection; no FileDescriptors available")
	}

	return renderProto(merged)
}

// renderProto reconstructs the descriptor graph from wire bytes and emits
// proto3 source via protoprint. google.protobuf.* well-known files are
// skipped from output since any consumer of the .proto already has them.
// Output is deterministic: filenames are sorted, and within each file
// protoprint sorts elements.
func renderProto(fileDescriptors map[string][]byte) ([]byte, error) {
	fdProtos := make([]*descriptorpb.FileDescriptorProto, 0, len(fileDescriptors))
	for _, raw := range fileDescriptors {
		var fdp descriptorpb.FileDescriptorProto
		if err := proto.Unmarshal(raw, &fdp); err != nil {
			return nil, fmt.Errorf("unmarshal file descriptor: %w", err)
		}
		fdProtos = append(fdProtos, &fdp)
	}

	fds, skipped, err := buildDescriptorGraph(fdProtos)
	if err != nil {
		return nil, err
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
	if len(skipped) > 0 {
		fmt.Fprintf(&buf, "// WARNING: %d .proto file(s) omitted due to unresolved imports or link errors:\n", len(skipped))
		for _, s := range skipped {
			fmt.Fprintf(&buf, "//   - %s\n", s)
		}
		buf.WriteString("\n")
	}
	for i, name := range names {
		if i > 0 {
			buf.WriteString("\n// ---\n\n")
		}
		if err := printer.PrintProtoFile(fds[name], &buf); err != nil {
			return nil, fmt.Errorf("print %s: %w", name, err)
		}
	}
	return buf.Bytes(), nil
}

// buildDescriptorGraph resolves fdProtos into linked descriptors. It first
// tries the strict all-or-nothing path (the common case, where reflection
// returned a complete import closure). If that fails — e.g. the probe
// truncated a large import graph at maxGRPCFileDescriptors and left a
// dangling import — it degrades to resolving each file independently,
// returning every file it can link plus the sorted names of those it had
// to skip, rather than discarding the entire result. Only when nothing
// links does it surface the original strict error.
func buildDescriptorGraph(fdProtos []*descriptorpb.FileDescriptorProto) (map[string]*desc.FileDescriptor, []string, error) {
	fds, strictErr := desc.CreateFileDescriptorsFromSet(&descriptorpb.FileDescriptorSet{File: fdProtos})
	if strictErr == nil {
		return fds, nil, nil
	}

	// Strict resolution failed (e.g. the probe truncated a large import graph
	// and left a dangling import). Degrade to resolving each file
	// independently.
	files := make(map[string]*descriptorpb.FileDescriptorProto, len(fdProtos))
	for _, fdp := range fdProtos {
		files[fdp.GetName()] = fdp
	}

	resolved := map[string]*desc.FileDescriptor{}
	var resolve func(name string, stack map[string]bool) (*desc.FileDescriptor, error)
	resolve = func(name string, stack map[string]bool) (*desc.FileDescriptor, error) {
		if fd, ok := resolved[name]; ok {
			return fd, nil
		}
		if stack[name] {
			return nil, fmt.Errorf("cyclic import involving %q", name)
		}
		fdp, ok := files[name]
		if !ok {
			return nil, fmt.Errorf("missing dependency %q", name)
		}
		stack[name] = true
		deps := make([]*desc.FileDescriptor, 0, len(fdp.GetDependency()))
		for _, dep := range fdp.GetDependency() {
			d, err := resolve(dep, stack)
			if err != nil {
				delete(stack, name)
				return nil, err
			}
			deps = append(deps, d)
		}
		delete(stack, name)
		fd, err := desc.CreateFileDescriptor(fdp, deps...)
		if err != nil {
			return nil, err
		}
		resolved[name] = fd
		return fd, nil
	}

	var skipped []string
	for name := range files {
		if _, err := resolve(name, map[string]bool{}); err != nil {
			skipped = append(skipped, name)
		}
	}
	sort.Strings(skipped)

	if len(resolved) == 0 {
		return nil, nil, fmt.Errorf("build descriptor graph: %w", strictErr)
	}
	return resolved, skipped, nil
}
