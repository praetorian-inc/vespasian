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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"

	"github.com/praetorian-inc/vespasian/pkg/classify"
)

// fileDescriptorBytes builds a minimal FileDescriptorProto and returns its
// wire-format bytes. The returned file declares two messages and one service
// with a single RPC.
func fileDescriptorBytes(t *testing.T) []byte {
	t.Helper()
	fdp := &descriptorpb.FileDescriptorProto{
		Name:    proto.String("users.proto"),
		Package: proto.String("users.v1"),
		Syntax:  proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{
			{
				Name: proto.String("GetUserRequest"),
				Field: []*descriptorpb.FieldDescriptorProto{
					{
						Name:     proto.String("id"),
						Number:   proto.Int32(1),
						Type:     descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
						Label:    descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
						JsonName: proto.String("id"),
					},
				},
			},
			{
				Name: proto.String("GetUserResponse"),
				Field: []*descriptorpb.FieldDescriptorProto{
					{
						Name:     proto.String("name"),
						Number:   proto.Int32(1),
						Type:     descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
						Label:    descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
						JsonName: proto.String("name"),
					},
				},
			},
		},
		Service: []*descriptorpb.ServiceDescriptorProto{
			{
				Name: proto.String("UserService"),
				Method: []*descriptorpb.MethodDescriptorProto{
					{
						Name:       proto.String("GetUser"),
						InputType:  proto.String(".users.v1.GetUserRequest"),
						OutputType: proto.String(".users.v1.GetUserResponse"),
					},
				},
			},
		},
	}
	raw, err := proto.Marshal(fdp)
	require.NoError(t, err)
	return raw
}

func TestGenerator_APIType(t *testing.T) {
	g := &Generator{}
	assert.Equal(t, "grpc", g.APIType())
}

func TestGenerator_DefaultExtension(t *testing.T) {
	g := &Generator{}
	assert.Equal(t, ".proto", g.DefaultExtension())
}

func TestGenerator_Generate_NoEndpoints(t *testing.T) {
	g := &Generator{}
	_, err := g.Generate(nil)
	assert.Error(t, err)
}

func TestGenerator_Generate_NoReflection(t *testing.T) {
	g := &Generator{}
	endpoints := []classify.ClassifiedRequest{
		{APIType: "grpc"},
	}
	_, err := g.Generate(endpoints)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "server reflection")
}

func TestGenerator_Generate_ReflectionEnabledButNoDescriptors(t *testing.T) {
	g := &Generator{}
	endpoints := []classify.ClassifiedRequest{
		{
			APIType: "grpc",
			GRPCSchema: &classify.GRPCReflectionResult{
				ReflectionEnabled: true,
				// FileDescriptors empty → Phase 1 should not fire
			},
		},
	}
	_, err := g.Generate(endpoints)
	assert.Error(t, err)
}

func TestGenerator_Generate_FromFileDescriptors(t *testing.T) {
	g := &Generator{}
	raw := fileDescriptorBytes(t)

	endpoints := []classify.ClassifiedRequest{
		{
			APIType: "grpc",
			GRPCSchema: &classify.GRPCReflectionResult{
				ReflectionEnabled: true,
				FileDescriptors:   map[string][]byte{"users.proto": raw},
			},
		},
	}
	out, err := g.Generate(endpoints)
	require.NoError(t, err)
	output := string(out)

	assert.Contains(t, output, "syntax = \"proto3\"")
	assert.Contains(t, output, "package users.v1")
	assert.Contains(t, output, "message GetUserRequest")
	assert.Contains(t, output, "message GetUserResponse")
	assert.Contains(t, output, "service UserService")
	assert.Contains(t, output, "rpc GetUser")
	assert.Contains(t, output, "string id = 1")
	assert.Contains(t, output, "string name = 1")
}

func TestGenerator_Generate_Deterministic(t *testing.T) {
	g := &Generator{}
	raw := fileDescriptorBytes(t)

	endpoints := []classify.ClassifiedRequest{
		{
			APIType: "grpc",
			GRPCSchema: &classify.GRPCReflectionResult{
				ReflectionEnabled: true,
				FileDescriptors:   map[string][]byte{"users.proto": raw},
			},
		},
	}
	out1, err := g.Generate(endpoints)
	require.NoError(t, err)
	out2, err := g.Generate(endpoints)
	require.NoError(t, err)
	assert.Equal(t, string(out1), string(out2))
}

func TestGenerator_Generate_SkipsWellKnownImports(t *testing.T) {
	g := &Generator{}
	raw := fileDescriptorBytes(t)

	// A google/protobuf/* file should be excluded from output even if present
	// in the descriptor map.
	timestampFile := &descriptorpb.FileDescriptorProto{
		Name:    proto.String("google/protobuf/timestamp.proto"),
		Package: proto.String("google.protobuf"),
		Syntax:  proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{
			{Name: proto.String("Timestamp")},
		},
	}
	tsRaw, err := proto.Marshal(timestampFile)
	require.NoError(t, err)

	endpoints := []classify.ClassifiedRequest{
		{
			APIType: "grpc",
			GRPCSchema: &classify.GRPCReflectionResult{
				ReflectionEnabled: true,
				FileDescriptors: map[string][]byte{
					"users.proto":                     raw,
					"google/protobuf/timestamp.proto": tsRaw,
				},
			},
		},
	}
	out, err := g.Generate(endpoints)
	require.NoError(t, err)
	output := string(out)
	assert.NotContains(t, output, "google/protobuf/timestamp.proto")
	assert.NotContains(t, output, "message Timestamp")
	assert.Contains(t, output, "service UserService")
}

// ---------------------------------------------------------------------------
// T1 — Reflection + bindings, same service FQN, through Generate
// ---------------------------------------------------------------------------

// TestGenerator_Generate_ReflectionWinsOverBindingsSameFQN reproduces the
// original review bug (LAB-3864): reflection provides real FileDescriptors
// defining pkg.FooService; a bindings-style endpoint carries the same FQN
// with ReflectionEnabled=false and no FileDescriptors. Generate must produce
// no error, no duplicate symbol, and the output must contain real message
// fields (reflection wins, the synthetic stub is dropped).
func TestGenerator_Generate_ReflectionWinsOverBindingsSameFQN(t *testing.T) {
	// Build a real FileDescriptorProto with a real message field.
	fdp := &descriptorpb.FileDescriptorProto{
		Name:    proto.String("pkg/foo.proto"),
		Package: proto.String("pkg"),
		Syntax:  proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{
			{
				Name: proto.String("BarRequest"),
				Field: []*descriptorpb.FieldDescriptorProto{
					{
						Name:     proto.String("real_field"),
						Number:   proto.Int32(1),
						Type:     descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
						Label:    descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
						JsonName: proto.String("realField"),
					},
				},
			},
			{
				Name:  proto.String("BarResponse"),
				Field: []*descriptorpb.FieldDescriptorProto{},
			},
		},
		Service: []*descriptorpb.ServiceDescriptorProto{
			{
				Name: proto.String("FooService"),
				Method: []*descriptorpb.MethodDescriptorProto{
					{
						Name:       proto.String("Bar"),
						InputType:  proto.String(".pkg.BarRequest"),
						OutputType: proto.String(".pkg.BarResponse"),
					},
				},
			},
		},
	}
	raw, err := proto.Marshal(fdp)
	require.NoError(t, err)

	// Endpoint A: real reflection result — FileDescriptors populated.
	reflectionEP := classify.ClassifiedRequest{
		APIType: "grpc",
		GRPCSchema: &classify.GRPCReflectionResult{
			ReflectionEnabled: true,
			FileDescriptors:   map[string][]byte{"pkg/foo.proto": raw},
			Services: []classify.GRPCService{
				{Name: "pkg.FooService", Methods: []classify.GRPCMethod{{Name: "Bar", InputType: "BarRequest", OutputType: "BarResponse"}}},
			},
		},
	}

	// Endpoint B: bindings-style — same FQN, ReflectionEnabled=false, no FileDescriptors.
	bindingsEP := classify.ClassifiedRequest{
		APIType: "grpc",
		GRPCSchema: &classify.GRPCReflectionResult{
			ReflectionEnabled: false,
			Services: []classify.GRPCService{
				{Name: "pkg.FooService", Methods: []classify.GRPCMethod{{Name: "Bar", InputType: "BarRequest", OutputType: "BarResponse"}}},
			},
		},
	}

	g := &Generator{}
	out, err := g.Generate([]classify.ClassifiedRequest{reflectionEP, bindingsEP})
	require.NoError(t, err, "Generate must not return a conflicting-descriptor or duplicate-symbol error")

	output := string(out)
	// Reflection wins: real message field must be present.
	assert.Contains(t, output, "real_field", "reflection-defined field must appear in output (reflection wins)")
	assert.Contains(t, output, "service FooService", "FooService must be present in output")
	// Only one service definition — no duplicate symbol.
	assert.Equal(t, 1, strings.Count(output, "service FooService"), "FooService must appear exactly once (no duplicate symbol)")
}

// ---------------------------------------------------------------------------
// T2 — Gateway + bindings, same package different services, through Generate
// ---------------------------------------------------------------------------

// TestGenerator_Generate_TwoServicesOnePackageBothPresent reproduces the
// second variant of the original review bug: gateway recovers greet.v1.Greeter,
// bindings recover greet.v1.Farewell (different FQN, same package). Generate
// must produce one coherent .proto, one package declaration, both services
// present, no conflicting-file-descriptors or duplicate-symbol error.
func TestGenerator_Generate_TwoServicesOnePackageBothPresent(t *testing.T) {
	gatewayEP := classify.ClassifiedRequest{
		APIType: "grpc",
		GRPCSchema: &classify.GRPCReflectionResult{
			ReflectionEnabled: false,
			Services: []classify.GRPCService{
				{Name: "greet.v1.Greeter", Methods: []classify.GRPCMethod{{Name: "SayHello", InputType: "HelloRequest", OutputType: "HelloResponse"}}},
			},
		},
	}
	bindingsEP := classify.ClassifiedRequest{
		APIType: "grpc",
		GRPCSchema: &classify.GRPCReflectionResult{
			ReflectionEnabled: false,
			Services: []classify.GRPCService{
				{Name: "greet.v1.Farewell", Methods: []classify.GRPCMethod{{Name: "SayBye", InputType: "ByeRequest", OutputType: "ByeResponse"}}},
			},
		},
	}

	g := &Generator{}
	out, err := g.Generate([]classify.ClassifiedRequest{gatewayEP, bindingsEP})
	require.NoError(t, err, "Generate must not return a conflicting file descriptors or duplicate symbol error")

	output := string(out)
	// Single package declaration.
	assert.Equal(t, 1, strings.Count(output, "package greet.v1"), "exactly one package declaration for greet.v1")
	// Both services present.
	assert.Contains(t, output, "service Greeter", "Greeter must be present")
	assert.Contains(t, output, "service Farewell", "Farewell must be present")
	assert.Contains(t, output, "rpc SayHello", "SayHello method must be present")
	assert.Contains(t, output, "rpc SayBye", "SayBye method must be present")
}

// ---------------------------------------------------------------------------
// unionRecoveredServices unit tests (T-coverage: dedup-by-FQN + reflection-drop)
// ---------------------------------------------------------------------------

// TestUnionRecoveredServices_DedupesByFQN verifies that when two endpoints
// carry the same service FQN, only the first occurrence is kept (first wins).
func TestUnionRecoveredServices_DedupesByFQN(t *testing.T) {
	ep1 := classify.ClassifiedRequest{
		APIType: "grpc",
		GRPCSchema: &classify.GRPCReflectionResult{
			Services: []classify.GRPCService{
				{Name: "pkg.Alpha", Methods: []classify.GRPCMethod{{Name: "M1"}}},
			},
		},
	}
	ep2 := classify.ClassifiedRequest{
		APIType: "grpc",
		GRPCSchema: &classify.GRPCReflectionResult{
			Services: []classify.GRPCService{
				{Name: "pkg.Alpha", Methods: []classify.GRPCMethod{{Name: "M2"}}}, // duplicate FQN
				{Name: "pkg.Beta", Methods: []classify.GRPCMethod{{Name: "M3"}}},
			},
		},
	}

	result := unionRecoveredServices([]classify.ClassifiedRequest{ep1, ep2}, nil)
	require.Len(t, result, 2, "should have Alpha (deduped) and Beta")

	var names []string
	for _, s := range result {
		names = append(names, s.Name)
	}
	assert.Contains(t, names, "pkg.Alpha")
	assert.Contains(t, names, "pkg.Beta")
	// Alpha from ep1 wins (M1 kept, M2 dropped).
	for _, s := range result {
		if s.Name == "pkg.Alpha" {
			require.Len(t, s.Methods, 1)
			assert.Equal(t, "M1", s.Methods[0].Name, "first-occurrence methods win on FQN tie")
		}
	}
}

// TestUnionRecoveredServices_DropsReflectedFQNs verifies that FQNs already
// defined by the merged reflection descriptors are excluded from synthesis.
func TestUnionRecoveredServices_DropsReflectedFQNs(t *testing.T) {
	reflectedFQNs := map[string]bool{
		"pkg.FooService": true,
	}
	ep := classify.ClassifiedRequest{
		APIType: "grpc",
		GRPCSchema: &classify.GRPCReflectionResult{
			Services: []classify.GRPCService{
				{Name: "pkg.FooService"}, // covered by reflection
				{Name: "pkg.BarService"}, // not covered
			},
		},
	}

	result := unionRecoveredServices([]classify.ClassifiedRequest{ep}, reflectedFQNs)
	require.Len(t, result, 1, "FooService (covered by reflection) must be dropped")
	assert.Equal(t, "pkg.BarService", result[0].Name)
}

// TestUnionRecoveredServices_NilSchemaSkipped verifies endpoints with nil
// GRPCSchema do not panic and are skipped.
func TestUnionRecoveredServices_NilSchemaSkipped(t *testing.T) {
	ep := classify.ClassifiedRequest{
		APIType:    "grpc",
		GRPCSchema: nil,
	}
	result := unionRecoveredServices([]classify.ClassifiedRequest{ep}, nil)
	assert.Empty(t, result)
}
