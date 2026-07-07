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

// TestGenerator_Generate_IdenticalDescriptorsDedup verifies that two endpoints
// carrying the same filename with identical bytes do not trigger a conflict —
// the generator deduplicates them and produces valid output.
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
