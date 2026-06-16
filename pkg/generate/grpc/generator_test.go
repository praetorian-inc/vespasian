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
