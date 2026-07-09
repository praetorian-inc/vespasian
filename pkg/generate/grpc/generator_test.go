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
	"fmt"
	"regexp"
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
// T3 — Gateway partial coverage + bindings streaming method, through Generate
// ---------------------------------------------------------------------------

// TestGenerator_Generate_GreeterGatewayPrecedenceOverBindingsStreamingChat
// pins gateway>bindings precedence at METHOD granularity through Generate: a
// grpc-gateway-style endpoint (name-only, ReflectionEnabled=false) recovers
// Greeter.SayHello as a unary method; a separate bindings-recovered endpoint
// independently recovers the SAME Greeter FQN with a method of the SAME name
// (SayHello) but a DIFFERENT (streaming) definition, plus a bindings-only
// method (Chat) that grpc-gateway cannot transcode. The generated .proto must
// contain BOTH SayHello and Chat on Greeter, with SayHello rendered using the
// gateway's unary definition — proving precedence is resolved per-method
// (method union), not by dropping or fully overwriting the service.
func TestGenerator_Generate_GreeterGatewayPrecedenceOverBindingsStreamingChat(t *testing.T) {
	gatewayEP := classify.ClassifiedRequest{
		APIType: "grpc",
		GRPCSchema: &classify.GRPCReflectionResult{
			ReflectionEnabled: false,
			Services: []classify.GRPCService{
				{Name: "greet.v1.Greeter", Methods: []classify.GRPCMethod{
					{Name: "SayHello", InputType: "HelloRequest", OutputType: "HelloResponse"},
				}},
			},
		},
	}
	bindingsEP := classify.ClassifiedRequest{
		APIType: "grpc",
		GRPCSchema: &classify.GRPCReflectionResult{
			ReflectionEnabled: false,
			Services: []classify.GRPCService{
				{Name: "greet.v1.Greeter", Methods: []classify.GRPCMethod{
					// Same method name as the gateway's SayHello, but declared
					// client-streaming here — a conflicting definition. The
					// gateway's (higher-precedence) definition must win.
					{Name: "SayHello", InputType: "HelloRequest", OutputType: "HelloResponse", ClientStreaming: true},
					// Bindings-only method: grpc-gateway cannot transcode a
					// client-streaming RPC, so only bindings recover it.
					{Name: "Chat", InputType: "ChatRequest", OutputType: "ChatResponse", ClientStreaming: true},
				}},
			},
		},
	}

	g := &Generator{}
	// gatewayEP precedes bindingsEP, mirroring enrichGRPCFromBindings appending
	// bindings on a trailing endpoint after the gateway's: reflection > gateway
	// > bindings ordering, so the gateway's SayHello definition must win.
	out, err := g.Generate([]classify.ClassifiedRequest{gatewayEP, bindingsEP})
	require.NoError(t, err)

	output := string(out)
	assert.Contains(t, output, "service Greeter")
	assert.Contains(t, output, "rpc SayHello", "SayHello (gateway-recovered) must be present")
	assert.Contains(t, output, "rpc Chat", "Chat (bindings-only method) must be present in addition to SayHello")

	// Prove gateway precedence at method granularity: SayHello must render
	// unary (gateway's definition), while Chat (bindings-only, no gateway
	// counterpart) keeps its streaming keyword.
	sayHello := extractRPCSignature(t, output, "SayHello")
	assert.NotContains(t, sayHello, "stream", "SayHello must keep the GATEWAY's unary definition, not bindings' conflicting streaming one")

	chat := extractRPCSignature(t, output, "Chat")
	assert.Contains(t, chat, "stream", "Chat (bindings-only) must carry its streaming keyword")
}

// extractRPCSignature returns the `rpc <method>(...) returns (...)` signature
// text for method from a rendered .proto, so a test can assert on the
// presence/absence of the `stream` keyword scoped to one specific method
// (rather than anywhere in the file).
func extractRPCSignature(t *testing.T, output, method string) string {
	t.Helper()
	re := regexp.MustCompile(`(?s)rpc\s+` + regexp.QuoteMeta(method) + `\s*\([^)]*\)\s*returns\s*\([^)]*\)`)
	m := re.FindString(output)
	require.NotEmpty(t, m, "rpc %s signature not found in output:\n%s", method, output)
	return m
}

// ---------------------------------------------------------------------------
// unionRecoveredServices unit tests (T-coverage: dedup-by-FQN + reflection-drop)
// ---------------------------------------------------------------------------

// TestUnionRecoveredServices_MergesMethodsAcrossSameFQN verifies that when two
// endpoints carry the same service FQN, the union keeps BOTH endpoints'
// distinctly-named methods (method-level union), and that on a method NAME
// collision the first (higher-precedence) endpoint's method definition wins
// rather than the later one's.
func TestUnionRecoveredServices_MergesMethodsAcrossSameFQN(t *testing.T) {
	ep1 := classify.ClassifiedRequest{
		APIType: "grpc",
		GRPCSchema: &classify.GRPCReflectionResult{
			Services: []classify.GRPCService{
				{Name: "pkg.Alpha", Methods: []classify.GRPCMethod{
					{Name: "M1", InputType: "M1Request"},
				}},
			},
		},
	}
	ep2 := classify.ClassifiedRequest{
		APIType: "grpc",
		GRPCSchema: &classify.GRPCReflectionResult{
			Services: []classify.GRPCService{
				{Name: "pkg.Alpha", Methods: []classify.GRPCMethod{
					// Same method NAME as ep1's M1, but a DIFFERENT definition
					// (different InputType, and streaming where ep1's is not).
					// The merge must keep ep1's (first/higher-precedence) M1,
					// not this one.
					{Name: "M1", InputType: "M1RequestStream", ClientStreaming: true},
					{Name: "M2"}, // new method name: must be added
				}},
				{Name: "pkg.Beta", Methods: []classify.GRPCMethod{{Name: "M3"}}},
			},
		},
	}

	result := unionRecoveredServices([]classify.ClassifiedRequest{ep1, ep2}, nil)
	require.Len(t, result, 2, "should have Alpha (method-unioned) and Beta")

	var names []string
	for _, s := range result {
		names = append(names, s.Name)
	}
	assert.Contains(t, names, "pkg.Alpha")
	assert.Contains(t, names, "pkg.Beta")

	for _, s := range result {
		if s.Name != "pkg.Alpha" {
			continue
		}
		require.Len(t, s.Methods, 2, "Alpha must contain both M1 and M2 (method union, not whole-service drop)")

		var methodNames []string
		byName := map[string]classify.GRPCMethod{}
		for _, m := range s.Methods {
			methodNames = append(methodNames, m.Name)
			byName[m.Name] = m
		}
		assert.Contains(t, methodNames, "M1")
		assert.Contains(t, methodNames, "M2", "M2 (new method name from ep2) must be added")

		m1 := byName["M1"]
		assert.Equal(t, "M1Request", m1.InputType, "merged Alpha.M1 must keep ep1's (first/higher-precedence) definition")
		assert.False(t, m1.ClientStreaming, "merged Alpha.M1 must not pick up ep2's streaming flag")
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

// danglingImportFileBytes builds a FileDescriptorProto that depends on a file
// ("missing.proto") which is NOT present in the descriptor set, so its import
// cannot be resolved. Used to exercise the partial-resolution path.
func danglingImportFileBytes(t *testing.T) []byte {
	t.Helper()
	fdp := &descriptorpb.FileDescriptorProto{
		Name:       proto.String("broken.proto"),
		Package:    proto.String("broken.v1"),
		Syntax:     proto.String("proto3"),
		Dependency: []string{"missing.proto"},
		MessageType: []*descriptorpb.DescriptorProto{
			{
				Name: proto.String("BrokenMessage"),
				Field: []*descriptorpb.FieldDescriptorProto{
					{
						Name:     proto.String("value"),
						Number:   proto.Int32(1),
						Type:     descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
						Label:    descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
						JsonName: proto.String("value"),
					},
				},
			},
		},
	}
	raw, err := proto.Marshal(fdp)
	require.NoError(t, err)
	return raw
}

func TestGenerator_Generate_PartialResolutionSkipsBrokenFile(t *testing.T) {
	g := &Generator{}

	endpoints := []classify.ClassifiedRequest{
		{
			APIType: "grpc",
			GRPCSchema: &classify.GRPCReflectionResult{
				ReflectionEnabled: true,
				FileDescriptors: map[string][]byte{
					"users.proto":  fileDescriptorBytes(t),
					"broken.proto": danglingImportFileBytes(t),
				},
			},
		},
	}

	out, err := g.Generate(endpoints)
	require.NoError(t, err)
	output := string(out)

	// users.proto survived and was emitted.
	assert.Contains(t, output, "service UserService")
	assert.Contains(t, output, "message GetUserRequest")

	// broken.proto was skipped and reported.
	assert.Contains(t, output, "WARNING")
	assert.Contains(t, output, "broken.proto")
}

func TestGenerator_Generate_AllUnresolvableErrors(t *testing.T) {
	g := &Generator{}

	endpoints := []classify.ClassifiedRequest{
		{
			APIType: "grpc",
			GRPCSchema: &classify.GRPCReflectionResult{
				ReflectionEnabled: true,
				FileDescriptors: map[string][]byte{
					"broken.proto": danglingImportFileBytes(t),
				},
			},
		},
	}

	_, err := g.Generate(endpoints)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "build descriptor graph")
}

// ordersFileDescriptorBytes builds a minimal FileDescriptorProto for a
// DISJOINT file from fileDescriptorBytes: name "orders.proto", package
// "orders.v1", messages GetOrderRequest/GetOrderResponse, and service
// "OrderService" with rpc "GetOrder". Returns wire-format bytes.
func ordersFileDescriptorBytes(t *testing.T) []byte {
	t.Helper()
	fdp := &descriptorpb.FileDescriptorProto{
		Name:    proto.String("orders.proto"),
		Package: proto.String("orders.v1"),
		Syntax:  proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{
			{
				Name: proto.String("GetOrderRequest"),
				Field: []*descriptorpb.FieldDescriptorProto{
					{
						Name:     proto.String("order_id"),
						Number:   proto.Int32(1),
						Type:     descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
						Label:    descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
						JsonName: proto.String("orderId"),
					},
				},
			},
			{
				Name: proto.String("GetOrderResponse"),
				Field: []*descriptorpb.FieldDescriptorProto{
					{
						Name:     proto.String("status"),
						Number:   proto.Int32(1),
						Type:     descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
						Label:    descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
						JsonName: proto.String("status"),
					},
				},
			},
		},
		Service: []*descriptorpb.ServiceDescriptorProto{
			{
				Name: proto.String("OrderService"),
				Method: []*descriptorpb.MethodDescriptorProto{
					{
						Name:       proto.String("GetOrder"),
						InputType:  proto.String(".orders.v1.GetOrderRequest"),
						OutputType: proto.String(".orders.v1.GetOrderResponse"),
					},
				},
			},
		},
	}
	raw, err := proto.Marshal(fdp)
	require.NoError(t, err)
	return raw
}

// TestGenerator_Generate_AggregatesAcrossEndpoints verifies that descriptors
// from multiple endpoints are merged into a single output. Endpoint A carries
// users.proto (UserService); endpoint B carries orders.proto (OrderService).
// Both must appear in the generated .proto.
func TestGenerator_Generate_AggregatesAcrossEndpoints(t *testing.T) {
	g := &Generator{}
	usersRaw := fileDescriptorBytes(t)
	ordersRaw := ordersFileDescriptorBytes(t)

	endpoints := []classify.ClassifiedRequest{
		{
			APIType: "grpc",
			GRPCSchema: &classify.GRPCReflectionResult{
				ReflectionEnabled: true,
				FileDescriptors:   map[string][]byte{"users.proto": usersRaw},
			},
		},
		{
			APIType: "grpc",
			GRPCSchema: &classify.GRPCReflectionResult{
				ReflectionEnabled: true,
				FileDescriptors:   map[string][]byte{"orders.proto": ordersRaw},
			},
		},
	}

	out, err := g.Generate(endpoints)
	require.NoError(t, err)
	output := string(out)

	assert.Contains(t, output, "service UserService", "users.proto descriptor must be in output")
	assert.Contains(t, output, "service OrderService", "orders.proto descriptor must be in output")
}

// TestGenerator_Generate_ConflictingDescriptorsError verifies that two
// endpoints carrying the same filename but different bytes are rejected with a
// "conflicting file descriptors" error.
func TestGenerator_Generate_ConflictingDescriptorsError(t *testing.T) {
	g := &Generator{}
	usersRaw := fileDescriptorBytes(t)
	ordersRaw := ordersFileDescriptorBytes(t)

	// Both endpoints key their descriptor under "users.proto", but the bytes
	// differ (endpoint B uses the orders descriptor under that name).
	endpoints := []classify.ClassifiedRequest{
		{
			APIType: "grpc",
			GRPCSchema: &classify.GRPCReflectionResult{
				ReflectionEnabled: true,
				FileDescriptors:   map[string][]byte{"users.proto": usersRaw},
			},
		},
		{
			APIType: "grpc",
			GRPCSchema: &classify.GRPCReflectionResult{
				ReflectionEnabled: true,
				FileDescriptors:   map[string][]byte{"users.proto": ordersRaw},
			},
		},
	}

	_, err := g.Generate(endpoints)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "conflicting file descriptors")
}

// TestGenerator_Generate_TooManyDescriptorsErrors verifies that Generate
// rejects a merged descriptor set exceeding maxGRPCFileDescriptors before it
// ever attempts to unmarshal the (arbitrary, non-descriptor) bytes.
func TestGenerator_Generate_TooManyDescriptorsErrors(t *testing.T) {
	g := &Generator{}

	fileDescriptors := make(map[string][]byte, maxGRPCFileDescriptors+1)
	for i := 0; i < maxGRPCFileDescriptors+1; i++ {
		fileDescriptors[fmt.Sprintf("f%d.proto", i)] = []byte{0x00}
	}

	endpoints := []classify.ClassifiedRequest{
		{
			APIType: "grpc",
			GRPCSchema: &classify.GRPCReflectionResult{
				ReflectionEnabled: true,
				FileDescriptors:   fileDescriptors,
			},
		},
	}

	spec, err := g.Generate(endpoints)
	require.Error(t, err)
	assert.Empty(t, spec)
	assert.Contains(t, err.Error(), "too many")
}

// TestGenerator_Generate_DescriptorsExceedByteCapErrors verifies that Generate
// rejects a merged descriptor set whose aggregate byte size exceeds
// maxGRPCDescriptorBytes. The count stays at one entry so execution reaches
// the byte-cap check (which runs after the count check).
func TestGenerator_Generate_DescriptorsExceedByteCapErrors(t *testing.T) {
	g := &Generator{}

	// The ~64 MiB allocation below is intentional: it's the smallest way to
	// exercise the aggregate-byte guard, and it's transient (freed once the
	// test returns).
	oversized := make([]byte, maxGRPCDescriptorBytes+1)

	endpoints := []classify.ClassifiedRequest{
		{
			APIType: "grpc",
			GRPCSchema: &classify.GRPCReflectionResult{
				ReflectionEnabled: true,
				FileDescriptors:   map[string][]byte{"huge.proto": oversized},
			},
		},
	}

	spec, err := g.Generate(endpoints)
	require.Error(t, err)
	assert.Empty(t, spec)
	assert.Contains(t, err.Error(), "too large")
}

// TestGenerator_Generate_MalformedDescriptorErrors verifies that Generate
// surfaces a proto.Unmarshal failure on a descriptor blob that is non-empty and
// within both the count and byte caps but is not valid protobuf wire format.
// This pins the "unmarshal file descriptor" error branch in renderProto, which
// is reachable from the offline `generate` command when a capture carries
// corrupt/truncated descriptor bytes.
func TestGenerator_Generate_MalformedDescriptorErrors(t *testing.T) {
	g := &Generator{}
	// 0x0A = field 1, wire type 2 (length-delimited); the 0x05 length prefix
	// promises 5 payload bytes that are absent, so proto.Unmarshal fails while
	// the 2-byte blob still passes the count and aggregate-byte caps.
	endpoints := []classify.ClassifiedRequest{
		{
			APIType: "grpc",
			GRPCSchema: &classify.GRPCReflectionResult{
				ReflectionEnabled: true,
				FileDescriptors:   map[string][]byte{"broken.proto": {0x0A, 0x05}},
			},
		},
	}
	spec, err := g.Generate(endpoints)
	require.Error(t, err)
	assert.Empty(t, spec)
	assert.Contains(t, err.Error(), "unmarshal file descriptor")
}

// TestSanitizeComment verifies control chars (notably CR/LF), Unicode line/
// paragraph separators (U+2028/U+2029), C1 controls (U+0085 NEL), and format/
// bidi controls (U+202E, category Cf) are stripped so a hostile descriptor
// filename cannot inject or reorder lines in a // comment — while ordinary
// characters, including ASCII space, pass through unchanged.
func TestSanitizeComment(t *testing.T) {
	assert.Equal(t, "evil.protoINJECTED", sanitizeComment("evil.proto\nINJECTED"))
	assert.Equal(t, "abc", sanitizeComment("a\r\nb\tc"))
	assert.Equal(t, "clean.proto", sanitizeComment("clean.proto"))
	// Unicode separators / format controls, built from code points to keep the
	// source pure ASCII.
	assert.Equal(t, "ab", sanitizeComment("a"+string(rune(0x2028))+"b"), "U+2028 line separator must be stripped")
	assert.Equal(t, "ab", sanitizeComment("a"+string(rune(0x2029))+"b"), "U+2029 paragraph separator must be stripped")
	assert.Equal(t, "ab", sanitizeComment("a"+string(rune(0x0085))+"b"), "U+0085 NEL must be stripped")
	assert.Equal(t, "ab", sanitizeComment("a"+string(rune(0x202E))+"b"), "U+202E bidi override (Cf) must be stripped")
	// Ordinary ASCII space and printable chars are preserved.
	assert.Equal(t, "a b.proto", sanitizeComment("a b.proto"))
}

// TestGenerator_Generate_IdenticalDescriptorsDedup verifies that two endpoints
// carrying the same filename with identical bytes do not trigger a conflict —
// the generator deduplicates them and produces valid output.
func TestGenerator_Generate_IdenticalDescriptorsDedup(t *testing.T) {
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
	assert.Contains(t, string(out), "service UserService")
}
