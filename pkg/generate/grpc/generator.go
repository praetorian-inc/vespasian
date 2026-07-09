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
	"unicode"

	"github.com/jhump/protoreflect/desc"            //nolint:staticcheck // SA1019: protoprint requires v1 desc; no v2 equivalent exists
	"github.com/jhump/protoreflect/desc/protoprint" //nolint:staticcheck // SA1019: protoprint requires v1 desc; no v2 equivalent exists
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"

	"github.com/praetorian-inc/vespasian/pkg/classify"
)

// Descriptor caps shared with the probe path via pkg/classify (single
// source of truth) so the offline `generate` entry point enforces the same
// descriptor-count and aggregate-byte bounds instead of trusting
// capture-file provenance (SEC-BE-001).
const (
	maxGRPCFileDescriptors = classify.MaxGRPCFileDescriptors
	maxGRPCDescriptorBytes = classify.MaxGRPCDescriptorBytes
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
// union merges methods per service FQN (higher-precedence endpoints seen first
// win each method definition), FQNs already covered by reflection are dropped,
// and the remainder is synthesized into descriptors in one pass. The combined
// set is rendered via protoprint.
func (g *Generator) Generate(endpoints []classify.ClassifiedRequest) ([]byte, error) {
	if len(endpoints) == 0 {
		return nil, errors.New("no endpoints provided")
	}

	merged, err := aggregateReflectionDescriptors(endpoints)
	if err != nil {
		return nil, err
	}

	// Enforce caps on the reflection descriptors BEFORE any parse (SEC-BE-001).
	if err := enforceDescriptorCaps(merged); err != nil {
		return nil, err
	}

	// Union name-only recovered services and synthesize them into merged.
	if err := mergeRecoveredServices(merged, endpoints); err != nil {
		return nil, err
	}

	if len(merged) == 0 {
		return nil, errors.New("gRPC spec generation requires server reflection or recovered service names; none available")
	}

	return renderProto(merged)
}

// aggregateReflectionDescriptors merges FileDescriptors across every endpoint
// that carries them. A single capture can hold multiple gRPC targets (or one
// target observed at several URLs); returning on the first match would drop the
// rest and emit an incomplete .proto. Keyed by .proto filename — the same
// filename is expected to carry identical descriptor bytes (same import graph),
// so a byte mismatch is a real conflict, surfaced rather than silently dropped.
//
// The gate keys off descriptor presence, not ReflectionEnabled: name-only
// techniques set ReflectionEnabled=false but never populate FileDescriptors, so
// "endpoints that carry FileDescriptors" is exactly the set of real reflection
// descriptors.
func aggregateReflectionDescriptors(endpoints []classify.ClassifiedRequest) (map[string][]byte, error) {
	merged := map[string][]byte{}
	for _, ep := range endpoints {
		if ep.GRPCSchema == nil || len(ep.GRPCSchema.FileDescriptors) == 0 {
			continue
		}
		for name, raw := range ep.GRPCSchema.FileDescriptors {
			existing, ok := merged[name]
			if !ok {
				merged[name] = raw
				continue
			}
			if !bytes.Equal(existing, raw) {
				return nil, fmt.Errorf("conflicting file descriptors for %q across gRPC endpoints", name)
			}
		}
	}
	return merged, nil
}

// enforceDescriptorCaps re-checks the descriptor-count and aggregate-byte caps
// on the merged reflection descriptors BEFORE any parse (SEC-BE-001). The
// offline `generate` entry point cannot trust that a capture's FileDescriptors
// were bounded by the probe, so it re-checks the same limits pkg/probe enforces
// rather than parsing an unbounded set. Synthetic descriptors are generated
// later from bounded recovered service names, so the cap targets the untrusted
// capture-derived set specifically.
func enforceDescriptorCaps(merged map[string][]byte) error {
	if len(merged) > maxGRPCFileDescriptors {
		return fmt.Errorf("too many gRPC file descriptors: %d (max %d)", len(merged), maxGRPCFileDescriptors)
	}
	var totalBytes int
	for _, raw := range merged {
		totalBytes += len(raw)
	}
	if totalBytes > maxGRPCDescriptorBytes {
		return fmt.Errorf("gRPC file descriptors too large: %d bytes (max %d)", totalBytes, maxGRPCDescriptorBytes)
	}
	return nil
}

// mergeRecoveredServices parses the merged reflection descriptors to collect the
// service and message FQNs they already define, unions the name-only recovered
// Services across all endpoints at method granularity (reflection-covered FQNs
// dropped), synthesizes the remainder in a single pass, and merges the synthetic
// descriptors into merged.
//
// Reflection-defined FQNs are collected so name-only techniques never
// re-synthesize (and re-declare) the same service or message in a separate
// synthetic file — that would be a duplicate symbol. Reflection-covered service
// FQNs are dropped entirely (not augmented with synthetic methods); the
// remaining name-only FQNs are method-unioned across endpoints so a service
// only partially covered by one name-only technique still surfaces methods a
// lower-precedence technique recovered. Messages are deduped by importing the
// reflection file that declares them instead of emitting a duplicate stub.
// Synthetic filenames are namespaced (synthetic.proto) and cannot key-collide
// with reflection filenames.
func mergeRecoveredServices(merged map[string][]byte, endpoints []classify.ClassifiedRequest) error {
	reflectedFQNs := map[string]bool{}
	reflectedMsgs := map[string]string{}
	if len(merged) > 0 {
		reflectedFDs, _, err := parseDescriptorSet(merged)
		if err != nil {
			return err
		}
		reflectedFQNs = reflectedServiceFQNs(reflectedFDs)
		reflectedMsgs = reflectedMessageFQNs(reflectedFDs)
	}

	synthServices := unionRecoveredServices(endpoints, reflectedFQNs)
	if len(synthServices) == 0 {
		return nil
	}
	synthFDs, err := FileDescriptorsFromServices(synthServices, reflectedMsgs)
	if err != nil {
		return err
	}
	for name, raw := range synthFDs {
		merged[name] = raw
	}
	return nil
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

// reflectedMessageFQNs maps every message FQN declared by the given parsed
// reflection descriptors (including nested messages, package-qualified) to the
// name of the .proto file that declares it. Synthesis consults this map so a
// referenced message already provided by reflection is imported from its
// reflection file rather than re-declared as a duplicate stub.
func reflectedMessageFQNs(fds map[string]*desc.FileDescriptor) map[string]string {
	out := map[string]string{}
	for _, fd := range fds {
		fileName := fd.GetName()
		var walk func(msgs []*desc.MessageDescriptor)
		walk = func(msgs []*desc.MessageDescriptor) {
			for _, md := range msgs {
				out[md.GetFullyQualifiedName()] = fileName
				walk(md.GetNestedMessageTypes())
			}
		}
		walk(fd.GetMessageTypes())
	}
	return out
}

// unionRecoveredServices collects Services across all endpoints and unions them
// at METHOD granularity per service FQN. An FQN already defined by the
// reflection descriptors is dropped entirely: reflection is authoritative and
// its real FileDescriptors are never augmented with synthetic method stubs, so
// the union applies only to the name-only (grpc-gateway + gRPC-Web bindings)
// path.
//
// For a name-only FQN, the first endpoint that carries it establishes the
// service and its method set; a later endpoint carrying the same FQN
// contributes only the methods whose Name is not already present — the
// first-seen definition of a method wins. Endpoint iteration order places
// higher-precedence gateway-probed endpoints before the appended
// lower-precedence bindings endpoint, so a method the gateway transcoded keeps
// the gateway's definition while bindings-only methods (e.g. client-streaming
// or bidi RPCs the gateway cannot transcode) are added rather than dropped.
//
// Method order within a merged service is first-seen and therefore
// deterministic given deterministic endpoint order (protoprint additionally
// sorts elements on output).
func unionRecoveredServices(endpoints []classify.ClassifiedRequest, reflectedFQNs map[string]bool) []classify.GRPCService {
	index := map[string]int{}                  // FQN -> position in out
	methodSeen := map[string]map[string]bool{} // FQN -> set of method names already present
	var out []classify.GRPCService
	for _, ep := range endpoints {
		if ep.GRPCSchema == nil {
			continue
		}
		for _, svc := range ep.GRPCSchema.Services {
			fqn := strings.TrimPrefix(svc.Name, ".")
			if reflectedFQNs[fqn] {
				continue
			}
			pos, ok := index[fqn]
			if !ok {
				index[fqn] = len(out)
				out = append(out, copyServiceWithMethods(svc))
				methodSeen[fqn] = methodNameSet(svc.Methods)
				continue
			}
			// Repeat FQN: merge in only the methods not already present.
			out[pos].Methods = mergeNewMethods(out[pos].Methods, methodSeen[fqn], svc.Methods)
		}
	}
	return out
}

// copyServiceWithMethods returns a copy of svc that owns its own Methods slice,
// so later in-place method merges never mutate the caller's backing array.
func copyServiceWithMethods(svc classify.GRPCService) classify.GRPCService {
	svc.Methods = append([]classify.GRPCMethod(nil), svc.Methods...)
	return svc
}

// methodNameSet returns the set of method names present in methods.
func methodNameSet(methods []classify.GRPCMethod) map[string]bool {
	seen := make(map[string]bool, len(methods))
	for _, m := range methods {
		seen[m.Name] = true
	}
	return seen
}

// mergeNewMethods appends every method from extra whose Name is not yet in seen
// to dst, recording newly added names in seen. Methods whose name is already
// present are skipped (first-seen, higher-precedence definition wins).
func mergeNewMethods(dst []classify.GRPCMethod, seen map[string]bool, extra []classify.GRPCMethod) []classify.GRPCMethod {
	for _, m := range extra {
		if seen[m.Name] {
			continue
		}
		seen[m.Name] = true
		dst = append(dst, m)
	}
	return dst
}

// renderProto reconstructs the descriptor graph from wire bytes and emits
// proto3 source via protoprint. It is a thin wrapper retained for callers that
// want a one-shot parse-then-print; Generate uses parseDescriptorSet and
// printDescriptors separately so it can inspect the parsed graph (to extract
// reflected service FQNs) before printing.
func renderProto(fileDescriptors map[string][]byte) ([]byte, error) {
	fds, skipped, err := parseDescriptorSet(fileDescriptors)
	if err != nil {
		return nil, err
	}
	return printDescriptors(fds, skipped)
}

// parseDescriptorSet reconstructs the descriptor graph from wire bytes. It
// returns the linked descriptors, the sorted names of any files that could not
// be linked (propagated from buildDescriptorGraph's degraded-resolution path),
// and an error only when nothing links.
func parseDescriptorSet(fileDescriptors map[string][]byte) (map[string]*desc.FileDescriptor, []string, error) {
	fdProtos := make([]*descriptorpb.FileDescriptorProto, 0, len(fileDescriptors))
	for _, raw := range fileDescriptors {
		var fdp descriptorpb.FileDescriptorProto
		if err := proto.Unmarshal(raw, &fdp); err != nil {
			return nil, nil, fmt.Errorf("unmarshal file descriptor: %w", err)
		}
		fdProtos = append(fdProtos, &fdp)
	}

	fds, skipped, err := buildDescriptorGraph(fdProtos)
	if err != nil {
		return nil, nil, err
	}
	return fds, skipped, nil
}

// printDescriptors emits proto3 source for user-defined files via protoprint.
// google.protobuf.* well-known files are skipped from output since any consumer
// of the .proto already has them. Output is deterministic: filenames are
// sorted, and within each file protoprint sorts elements.
func printDescriptors(fds map[string]*desc.FileDescriptor, skipped []string) ([]byte, error) {
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
			fmt.Fprintf(&buf, "//   - %s\n", sanitizeComment(s))
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

// sanitizeComment strips characters that could break out of, or visually
// reorder, the single-line // comment a reflection-derived filename is embedded
// in. It removes C0/C1 control chars (incl. CR/LF) and DEL, the Unicode
// line/paragraph separators U+2028/U+2029, and Unicode format/bidi controls
// (category Cf, e.g. U+202E) — so a hostile descriptor filename cannot inject
// or reorder lines in the emitted .proto for any downstream consumer, not just
// protoc (which only treats '\n' as a // terminator).
func sanitizeComment(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
}
