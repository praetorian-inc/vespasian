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
// The caller must ensure no duplicate service FQNs are present in services;
// duplicates emit duplicate symbols (two ServiceDescriptorProto with the same
// name in one file). Generate dedupes by FQN (via unionRecoveredServices)
// before calling, so this function performs no internal dedup.
//
// Returns an error if services is empty or a service/method name is malformed.
func FileDescriptorsFromServices(services []classify.GRPCService) (map[string][]byte, error) {
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
		pkg, localName := splitServiceFQN(svc.Name)
		if localName == "" {
			return nil, fmt.Errorf("malformed service name %q", svc.Name)
		}

		b := getBuilder(pkg)
		sd := &descriptorpb.ServiceDescriptorProto{Name: proto.String(localName)}

		for _, m := range svc.Methods {
			if m.Name == "" {
				return nil, fmt.Errorf("malformed method name in service %q", svc.Name)
			}

			inPkg, inLocal := qualifyType(m.InputType, pkg)
			outPkg, outLocal := qualifyType(m.OutputType, pkg)

			// Register referenced messages in their owning package's file so
			// the descriptor graph resolves. Empty stubs — names only.
			getBuilder(inPkg).messages[inLocal] = true
			getBuilder(outPkg).messages[outLocal] = true

			// desc.CreateFileDescriptorsFromSet resolves cross-file type
			// references via the Dependency (import) list, not by scanning the
			// whole set — so a method whose input/output type lives in another
			// package's synthetic file must import that file.
			if inPkg != pkg {
				b.deps[syntheticFileName(inPkg)] = true
			}
			if outPkg != pkg {
				b.deps[syntheticFileName(outPkg)] = true
			}

			md := &descriptorpb.MethodDescriptorProto{
				Name:       proto.String(m.Name),
				InputType:  proto.String("." + fqn(inPkg, inLocal)),
				OutputType: proto.String("." + fqn(outPkg, outLocal)),
			}
			if m.ClientStreaming {
				md.ClientStreaming = proto.Bool(true)
			}
			if m.ServerStreaming {
				md.ServerStreaming = proto.Bool(true)
			}
			sd.Method = append(sd.Method, md)
		}

		b.services = append(b.services, sd)
	}

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
