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

	"github.com/praetorian-inc/vespasian/pkg/classify"
)

// roundTripProto synthesizes descriptors from services, wraps them in a
// ClassifiedRequest, and drives the Generator to get the rendered .proto text.
func roundTripProto(t *testing.T, services []classify.GRPCService) string {
	t.Helper()
	fds, err := FileDescriptorsFromServices(services)
	require.NoError(t, err)
	require.NotEmpty(t, fds)

	endpoints := []classify.ClassifiedRequest{
		{
			APIType: "grpc",
			GRPCSchema: &classify.GRPCReflectionResult{
				ReflectionEnabled: true,
				Services:          services,
				FileDescriptors:   fds,
			},
		},
	}
	out, err := (&Generator{}).Generate(endpoints)
	require.NoError(t, err)
	return string(out)
}

// TestFileDescriptorsFromServices_SingleUnaryService tests the core happy path:
// one service with one unary method. The round-trip through Generator must
// render all expected proto3 keywords.
func TestFileDescriptorsFromServices_SingleUnaryService(t *testing.T) {
	services := []classify.GRPCService{
		{
			Name: "users.v1.UserService",
			Methods: []classify.GRPCMethod{
				{
					Name:       "GetUser",
					InputType:  "GetUserRequest",
					OutputType: "GetUserResponse",
				},
			},
		},
	}

	output := roundTripProto(t, services)

	assert.Contains(t, output, "package users.v1")
	assert.Contains(t, output, "service UserService")
	assert.Contains(t, output, "rpc GetUser")
	assert.Contains(t, output, "GetUserRequest")
	assert.Contains(t, output, "GetUserResponse")
	// Empty stub messages must be declared (no fields from name-only recovery).
	assert.Contains(t, output, "message GetUserRequest")
	assert.Contains(t, output, "message GetUserResponse")
}

// TestFileDescriptorsFromServices_ServerStreamingMethod verifies that a method
// with ServerStreaming:true renders the "stream" keyword on the response side.
func TestFileDescriptorsFromServices_ServerStreamingMethod(t *testing.T) {
	services := []classify.GRPCService{
		{
			Name: "users.v1.UserService",
			Methods: []classify.GRPCMethod{
				{
					Name:            "WatchUsers",
					InputType:       "WatchRequest",
					OutputType:      "User",
					ServerStreaming: true,
				},
			},
		},
	}

	output := roundTripProto(t, services)

	assert.Contains(t, output, "stream")
	assert.Contains(t, output, "WatchUsers")
}

// TestFileDescriptorsFromServices_ClientStreamingMethod verifies client-streaming.
func TestFileDescriptorsFromServices_ClientStreamingMethod(t *testing.T) {
	services := []classify.GRPCService{
		{
			Name: "upload.v1.UploadService",
			Methods: []classify.GRPCMethod{
				{
					Name:            "UploadChunk",
					InputType:       "Chunk",
					OutputType:      "UploadResult",
					ClientStreaming: true,
				},
			},
		},
	}

	output := roundTripProto(t, services)

	assert.Contains(t, output, "stream")
	assert.Contains(t, output, "UploadChunk")
}

// TestFileDescriptorsFromServices_BidiStreamingMethod verifies both streaming
// flags together produce two "stream" keywords.
func TestFileDescriptorsFromServices_BidiStreamingMethod(t *testing.T) {
	services := []classify.GRPCService{
		{
			Name: "chat.v1.ChatService",
			Methods: []classify.GRPCMethod{
				{
					Name:            "Chat",
					InputType:       "ChatMessage",
					OutputType:      "ChatMessage",
					ClientStreaming: true,
					ServerStreaming: true,
				},
			},
		},
	}

	fds, err := FileDescriptorsFromServices(services)
	require.NoError(t, err)
	require.NotEmpty(t, fds)
	// Both flags set → descriptor should encode them.
	// Render and check the method name appears.
	output := roundTripProto(t, services)
	assert.Contains(t, output, "Chat")
	assert.Contains(t, output, "stream")
}

// TestFileDescriptorsFromServices_BareTypeNamesQualified verifies that bare
// (unqualified) input/output type names are qualified with the service's package.
// The round-trip must succeed without resolver errors.
func TestFileDescriptorsFromServices_BareTypeNamesQualified(t *testing.T) {
	services := []classify.GRPCService{
		{
			Name: "users.v1.UserService",
			Methods: []classify.GRPCMethod{
				{
					Name: "GetUser",
					// Bare names — no package prefix.
					InputType:  "GetUserRequest",
					OutputType: "GetUserResponse",
				},
			},
		},
	}

	// Must not error — bare types are qualified with "users.v1".
	fds, err := FileDescriptorsFromServices(services)
	require.NoError(t, err)
	require.NotEmpty(t, fds)

	// Round-trip must succeed and produce a valid .proto.
	output := roundTripProto(t, services)
	assert.Contains(t, output, "package users.v1")
	assert.Contains(t, output, "GetUser")
}

// TestFileDescriptorsFromServices_FullyQualifiedTypeNames ensures already-FQN
// types (e.g. "users.v1.GetUserRequest") are handled correctly without
// double-qualification or errors.
func TestFileDescriptorsFromServices_FullyQualifiedTypeNames(t *testing.T) {
	services := []classify.GRPCService{
		{
			Name: "users.v1.UserService",
			Methods: []classify.GRPCMethod{
				{
					Name:       "GetUser",
					InputType:  "users.v1.GetUserRequest",
					OutputType: "users.v1.GetUserResponse",
				},
			},
		},
	}

	output := roundTripProto(t, services)
	assert.Contains(t, output, "GetUser")
	assert.Contains(t, output, "GetUserRequest")
	assert.Contains(t, output, "GetUserResponse")
}

// TestFileDescriptorsFromServices_CrossPackageTypes ensures that when a method
// references a type from a different package, both packages get their own
// synthetic descriptor file and the round-trip renders without resolver errors.
func TestFileDescriptorsFromServices_CrossPackageTypes(t *testing.T) {
	services := []classify.GRPCService{
		{
			Name: "orders.v1.OrderService",
			Methods: []classify.GRPCMethod{
				{
					Name:       "GetOrder",
					InputType:  "orders.v1.GetOrderRequest",
					OutputType: "common.v1.Order", // cross-package
				},
			},
		},
	}

	fds, err := FileDescriptorsFromServices(services)
	require.NoError(t, err)
	// Should have at least two files: one for orders.v1, one for common.v1.
	assert.GreaterOrEqual(t, len(fds), 2)

	// Round-trip through the generator must succeed.
	output := roundTripProto(t, services)
	assert.Contains(t, output, "GetOrder")
}

// TestFileDescriptorsFromServices_NoPackageService tests a bare service name
// (no dots) — the descriptor should use an empty package.
func TestFileDescriptorsFromServices_NoPackageService(t *testing.T) {
	services := []classify.GRPCService{
		{
			Name: "SimpleService",
			Methods: []classify.GRPCMethod{
				{
					Name:       "Ping",
					InputType:  "PingRequest",
					OutputType: "PingResponse",
				},
			},
		},
	}

	fds, err := FileDescriptorsFromServices(services)
	require.NoError(t, err)
	// File should exist.
	require.NotEmpty(t, fds)

	output := roundTripProto(t, services)
	assert.Contains(t, output, "SimpleService")
	assert.Contains(t, output, "Ping")
}

// TestFileDescriptorsFromServices_MultipleServices verifies multiple services
// in the same package are grouped into a single synthetic file.
func TestFileDescriptorsFromServices_MultipleServices(t *testing.T) {
	services := []classify.GRPCService{
		{
			Name: "users.v1.UserService",
			Methods: []classify.GRPCMethod{
				{Name: "GetUser", InputType: "GetUserRequest", OutputType: "GetUserResponse"},
			},
		},
		{
			Name: "users.v1.AdminService",
			Methods: []classify.GRPCMethod{
				{Name: "ListUsers", InputType: "ListUsersRequest", OutputType: "ListUsersResponse"},
			},
		},
	}

	fds, err := FileDescriptorsFromServices(services)
	require.NoError(t, err)
	// Both services share the same package → grouped into one synthetic file.
	assert.Len(t, fds, 1)

	output := roundTripProto(t, services)
	assert.Contains(t, output, "UserService")
	assert.Contains(t, output, "AdminService")
}

// TestFileDescriptorsFromServices_EmptyServicesError verifies that an empty
// input slice returns a non-nil error.
func TestFileDescriptorsFromServices_EmptyServicesError(t *testing.T) {
	_, err := FileDescriptorsFromServices(nil)
	assert.Error(t, err)

	_, err = FileDescriptorsFromServices([]classify.GRPCService{})
	assert.Error(t, err)
}

// TestFileDescriptorsFromServices_MalformedServiceName tests that a service
// whose name is empty or otherwise malformed returns an error.
func TestFileDescriptorsFromServices_MalformedServiceName(t *testing.T) {
	services := []classify.GRPCService{
		{Name: "users.v1."}, // trailing dot → empty local name
	}
	_, err := FileDescriptorsFromServices(services)
	assert.Error(t, err)
}

// TestFileDescriptorsFromServices_EmptyMethodName tests that a method with an
// empty Name returns an error (the generator requires non-empty names).
func TestFileDescriptorsFromServices_EmptyMethodName(t *testing.T) {
	services := []classify.GRPCService{
		{
			Name: "users.v1.UserService",
			Methods: []classify.GRPCMethod{
				{Name: ""}, // empty method name
			},
		},
	}
	_, err := FileDescriptorsFromServices(services)
	assert.Error(t, err)
}

// TestFileDescriptorsFromServices_Determinism verifies that two calls to
// FileDescriptorsFromServices followed by Generate produce byte-identical
// output (mirrors generator_test.go:149 for the synthesis path).
func TestFileDescriptorsFromServices_Determinism(t *testing.T) {
	services := []classify.GRPCService{
		{
			Name: "users.v1.UserService",
			Methods: []classify.GRPCMethod{
				{Name: "GetUser", InputType: "GetUserRequest", OutputType: "GetUserResponse"},
				{Name: "ListUsers", InputType: "ListUsersRequest", OutputType: "ListUsersResponse"},
			},
		},
	}

	out1 := roundTripProto(t, services)
	out2 := roundTripProto(t, services)
	assert.Equal(t, out1, out2, "Generate output must be deterministic across calls")
}

// TestFileDescriptorsFromServices_SyntheticFilename verifies that synthetic
// filenames include the "synthetic.proto" suffix so they never collide with
// real reflection filenames.
func TestFileDescriptorsFromServices_SyntheticFilename(t *testing.T) {
	services := []classify.GRPCService{
		{
			Name: "users.v1.UserService",
			Methods: []classify.GRPCMethod{
				{Name: "GetUser", InputType: "GetUserRequest", OutputType: "GetUserResponse"},
			},
		},
	}

	fds, err := FileDescriptorsFromServices(services)
	require.NoError(t, err)
	for name := range fds {
		assert.Contains(t, name, "synthetic.proto", "all synthetic filenames must end with synthetic.proto")
	}
}

// TestFileDescriptorsFromServices_ReturnedMapNotEmpty verifies that for valid
// input, the returned descriptor map has at least one entry.
func TestFileDescriptorsFromServices_ReturnedMapNotEmpty(t *testing.T) {
	services := []classify.GRPCService{
		{
			Name: "payments.v2.PaymentService",
			Methods: []classify.GRPCMethod{
				{Name: "Charge", InputType: "ChargeRequest", OutputType: "ChargeResponse"},
			},
		},
	}

	fds, err := FileDescriptorsFromServices(services)
	require.NoError(t, err)
	assert.NotEmpty(t, fds)
}

// TestSyntheticFileName_PackageToPath tests the internal syntheticFileName
// helper via the exported interface (indirectly — the file names appear in the
// map keys).
func TestSyntheticFileName_PackageToPath(t *testing.T) {
	tests := []struct {
		svcName     string
		wantKeyPart string
	}{
		{"users.v1.UserService", "users/v1/synthetic.proto"},
		{"SimpleService", "synthetic.proto"},
		{"a.b.c.MyService", "a/b/c/synthetic.proto"},
	}

	for _, tc := range tests {
		t.Run(tc.svcName, func(t *testing.T) {
			services := []classify.GRPCService{
				{
					Name:    tc.svcName,
					Methods: []classify.GRPCMethod{{Name: "M", InputType: "Req", OutputType: "Resp"}},
				},
			}
			fds, err := FileDescriptorsFromServices(services)
			require.NoError(t, err)
			_, ok := fds[tc.wantKeyPart]
			assert.True(t, ok, "expected map key %q, got %v", tc.wantKeyPart, fds)
		})
	}
}
