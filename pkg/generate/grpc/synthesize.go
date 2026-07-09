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
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"

	"github.com/praetorian-inc/vespasian/pkg/classify"
)

// syntheticFileSuffix namespaces synthesized .proto filenames so they never
// collide with the real filenames produced by reflection (which use the
// server's actual proto paths). This guarantees Generator.Generate's
// per-filename byte-conflict check (generator.go merge step) never trips when
// reflection-derived and synthesized descriptors coexist in one capture.
const syntheticFileSuffix = "synthetic.proto"

// FileDescriptorsFromServices synthesizes FileDescriptorProto wire bytes from
// service/method/type names recovered by a name-only technique (gRPC-Web JS
// bindings, grpc-gateway OpenAPI). One file is produced per proto package.
// Referenced message types that have no recovered field definitions are
// emitted as empty proto3 messages. The returned map is keyed by synthetic
// .proto filename and is suitable for classify.GRPCReflectionResult.FileDescriptors
// (and therefore for Generator.Generate via the existing renderProto path).
//
// Names recovered from a scan target are untrusted. Every service, method, and
// message/type name is validated against the proto identifier grammar (each
// dot-separated segment must match [A-Za-z_][A-Za-z0-9_]*) before it is used to
// build a descriptor. A service whose name is malformed is dropped entirely; a
// method whose name or input/output type is malformed is dropped; a service
// left with no valid methods produces no descriptor. Drops are logged at debug
// level. A single malformed name never fails the whole render.
//
// reflectedMsgs maps every message FQN already declared by reflection
// descriptors to the .proto filename that declares it. A referenced type
// present in this map is NOT re-synthesized as a stub (that would duplicate the
// reflection symbol and fail the combined descriptor set); instead the
// synthetic file imports the reflection file that declares it. Callers with no
// reflection descriptors pass nil.
//
// The caller must ensure no duplicate service FQNs are present in services;
// duplicates emit duplicate symbols (two ServiceDescriptorProto with the same
// name in one file). Generate dedupes by service FQN (via unionRecoveredServices)
// and threads reflection message FQNs here, so this function performs no
// internal service-FQN dedup and relies on reflectedMsgs for message-FQN dedup.
//
// Returns an error only when services is empty (never for a malformed name).
func FileDescriptorsFromServices(services []classify.GRPCService, reflectedMsgs map[string]string) (map[string][]byte, error) {
	if len(services) == 0 {
		return nil, errors.New("no services provided")
	}

	// Builders accumulate per-package descriptor state before marshaling. The
	// map key is the proto package (may be empty for unqualified service names).
	builders := map[string]*fileBuilder{}

	getBuilder := func(pkg string) *fileBuilder {
		b, ok := builders[pkg]
		if !ok {
			b = &fileBuilder{pkg: pkg, messages: map[string]bool{}, deps: map[string]bool{}}
			builders[pkg] = b
		}
		return b
	}

	for _, svc := range services {
		sd, pkg, stubs, depSet, ok := buildService(svc, reflectedMsgs)
		if !ok {
			continue
		}

		b := getBuilder(pkg)
		for _, s := range stubs {
			getBuilder(s.pkg).messages[s.local] = true
		}
		for dep := range depSet {
			b.deps[dep] = true
		}
		b.services = append(b.services, sd)
	}

	return marshalBuilders(builders)
}

// buildService validates a single recovered service and assembles its
// ServiceDescriptorProto plus the message stubs and imports its methods
// reference. Builder mutations are deferred to the caller (via the returned
// stubs/depSet) until the service is known to survive, so a service whose
// methods are all malformed leaves no empty descriptor behind. ok is false when
// the service name is malformed or no method survives validation; in both cases
// the drop is logged at debug level and the descriptor is discarded.
func buildService(svc classify.GRPCService, reflectedMsgs map[string]string) (sd *descriptorpb.ServiceDescriptorProto, pkg string, stubs []pendingMsg, depSet map[string]bool, ok bool) {
	pkg, localName := splitServiceFQN(svc.Name)
	if !isValidProtoIdent(localName) || (pkg != "" && !isValidProtoDottedIdent(pkg)) {
		slog.Debug("grpc synthesize: dropping service with malformed name", "service", svc.Name)
		return nil, "", nil, nil, false
	}

	sd = &descriptorpb.ServiceDescriptorProto{Name: proto.String(localName)}
	depSet = map[string]bool{}

	for _, m := range svc.Methods {
		md, mok := buildMethod(m, svc.Name, pkg, reflectedMsgs, &stubs, depSet)
		if !mok {
			continue
		}
		sd.Method = append(sd.Method, md)
	}

	if len(sd.Method) == 0 {
		slog.Debug("grpc synthesize: dropping service with no valid methods", "service", svc.Name)
		return nil, "", nil, nil, false
	}

	return sd, pkg, stubs, depSet, true
}

// buildMethod validates a single recovered method and assembles its
// MethodDescriptorProto, appending any referenced message stubs and imports to
// stubs/depSet. ok is false when the method name or its input/output type FQN is
// malformed; the drop is logged at debug level.
func buildMethod(m classify.GRPCMethod, svcName, pkg string, reflectedMsgs map[string]string, stubs *[]pendingMsg, depSet map[string]bool) (md *descriptorpb.MethodDescriptorProto, ok bool) {
	if !isValidProtoIdent(m.Name) {
		slog.Debug("grpc synthesize: dropping method with malformed name", "service", svcName, "method", m.Name)
		return nil, false
	}

	inPkg, inLocal := qualifyType(m.InputType, pkg)
	outPkg, outLocal := qualifyType(m.OutputType, pkg)
	inFQN := fqn(inPkg, inLocal)
	outFQN := fqn(outPkg, outLocal)
	if !isValidProtoDottedIdent(inFQN) {
		slog.Debug("grpc synthesize: dropping method with malformed input type", "service", svcName, "method", m.Name, "type", m.InputType)
		return nil, false
	}
	if !isValidProtoDottedIdent(outFQN) {
		slog.Debug("grpc synthesize: dropping method with malformed output type", "service", svcName, "method", m.Name, "type", m.OutputType)
		return nil, false
	}

	// Satisfy the referenced messages. desc.CreateFileDescriptorsFromSet
	// resolves cross-file type references via the Dependency (import) list, not
	// by scanning the whole set, so each referenced type must either be stubbed
	// locally or imported from the file that declares it (a reflection file,
	// when reflection already declares the FQN).
	collectMessageRef(inFQN, inPkg, inLocal, pkg, reflectedMsgs, stubs, depSet)
	collectMessageRef(outFQN, outPkg, outLocal, pkg, reflectedMsgs, stubs, depSet)

	md = &descriptorpb.MethodDescriptorProto{
		Name:       proto.String(m.Name),
		InputType:  proto.String("." + inFQN),
		OutputType: proto.String("." + outFQN),
	}
	if m.ClientStreaming {
		md.ClientStreaming = proto.Bool(true)
	}
	if m.ServerStreaming {
		md.ServerStreaming = proto.Bool(true)
	}
	return md, true
}

// marshalBuilders renders every accumulated fileBuilder to its wire bytes,
// keyed by synthetic .proto filename.
func marshalBuilders(builders map[string]*fileBuilder) (map[string][]byte, error) {
	out := make(map[string][]byte, len(builders))
	for _, b := range builders {
		fdp, err := b.build()
		if err != nil {
			return nil, err
		}
		raw, err := proto.Marshal(fdp)
		if err != nil {
			return nil, fmt.Errorf("marshal synthetic descriptor for package %q: %w", b.pkg, err)
		}
		out[fdp.GetName()] = raw
	}

	return out, nil
}

// fileBuilder accumulates the services and referenced message stubs for a
// single proto package before it is turned into a FileDescriptorProto.
type fileBuilder struct {
	pkg      string
	services []*descriptorpb.ServiceDescriptorProto
	messages map[string]bool // local message names (dedup set)
	deps     map[string]bool // imported synthetic filenames (dedup set)
}

// pendingMsg is a referenced message stub queued for registration once its
// owning service is known to survive name validation.
type pendingMsg struct {
	pkg   string
	local string
}

// collectMessageRef records how a method's referenced message type is
// satisfied. If reflectedMsgs already declares the FQN, the synthetic file
// imports that reflection file rather than emitting a stub (a duplicate symbol
// would fail the combined descriptor set). Otherwise an empty stub is queued
// for the type's owning package and, when that package differs from the
// service's, that package's synthetic file is imported.
func collectMessageRef(msgFQN, msgPkg, msgLocal, svcPkg string, reflectedMsgs map[string]string, stubs *[]pendingMsg, depSet map[string]bool) {
	if reflFile, ok := reflectedMsgs[msgFQN]; ok {
		depSet[reflFile] = true
		return
	}
	*stubs = append(*stubs, pendingMsg{pkg: msgPkg, local: msgLocal})
	if msgPkg != svcPkg {
		depSet[syntheticFileName(msgPkg)] = true
	}
}

// protoIdentPattern matches a single proto identifier segment.
var protoIdentPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// isValidProtoIdent reports whether s is a single valid proto identifier
// segment ([A-Za-z_][A-Za-z0-9_]*).
func isValidProtoIdent(s string) bool {
	return protoIdentPattern.MatchString(s)
}

// isValidProtoDottedIdent reports whether s is a dotted proto identifier where
// every '.'-separated segment is a valid proto identifier. Empty is invalid.
func isValidProtoDottedIdent(s string) bool {
	if s == "" {
		return false
	}
	for _, seg := range strings.Split(s, ".") {
		if !isValidProtoIdent(seg) {
			return false
		}
	}
	return true
}

// build assembles the FileDescriptorProto. Message stubs, services, and
// dependencies are sorted for deterministic output.
func (b *fileBuilder) build() (*descriptorpb.FileDescriptorProto, error) {
	fdp := &descriptorpb.FileDescriptorProto{
		Name:   proto.String(syntheticFileName(b.pkg)),
		Syntax: proto.String("proto3"),
	}
	if b.pkg != "" {
		fdp.Package = proto.String(b.pkg)
	}

	deps := make([]string, 0, len(b.deps))
	for dep := range b.deps {
		deps = append(deps, dep)
	}
	sort.Strings(deps)
	fdp.Dependency = deps

	msgNames := make([]string, 0, len(b.messages))
	for name := range b.messages {
		msgNames = append(msgNames, name)
	}
	sort.Strings(msgNames)
	for _, name := range msgNames {
		fdp.MessageType = append(fdp.MessageType, &descriptorpb.DescriptorProto{
			Name: proto.String(name),
		})
	}

	sort.Slice(b.services, func(i, j int) bool {
		return b.services[i].GetName() < b.services[j].GetName()
	})
	fdp.Service = b.services

	return fdp, nil
}

// splitServiceFQN splits a service FQN into (package, localName). A name with
// no dot has empty package and uses the bare name as the local service name.
// "users.v1.UserService" → ("users.v1", "UserService").
func splitServiceFQN(name string) (pkg, local string) {
	name = strings.TrimPrefix(name, ".")
	idx := strings.LastIndex(name, ".")
	if idx < 0 {
		return "", name
	}
	return name[:idx], name[idx+1:]
}

// qualifyType resolves a recovered input/output type name into (package,
// localName). A bare name (no dot) is qualified with the service's package.
// An already-qualified name keeps its own package. A leading "." is stripped.
func qualifyType(typeName, svcPkg string) (pkg, local string) {
	typeName = strings.TrimPrefix(typeName, ".")
	idx := strings.LastIndex(typeName, ".")
	if idx < 0 {
		return svcPkg, typeName
	}
	return typeName[:idx], typeName[idx+1:]
}

// fqn joins a package and local name into a dotted fully-qualified name.
func fqn(pkg, local string) string {
	if pkg == "" {
		return local
	}
	return pkg + "." + local
}

// syntheticFileName derives a unique synthetic .proto filename per package.
// The empty package maps to "synthetic.proto"; "users.v1" maps to
// "users/v1/synthetic.proto". The filename is not surfaced in output (the
// generator prints body only), it only needs to be unique per package.
func syntheticFileName(pkg string) string {
	if pkg == "" {
		return syntheticFileSuffix
	}
	return strings.ReplaceAll(pkg, ".", "/") + "/" + syntheticFileSuffix
}
