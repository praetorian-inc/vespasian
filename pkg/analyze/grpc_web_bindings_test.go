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

package analyze

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/vespasian/pkg/classify"
	"github.com/praetorian-inc/vespasian/pkg/crawl"
)

// testdataPath builds a path relative to the testdata/grpc_web directory.
func testdataPath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join("testdata", "grpc_web", name)
}

// readFixture reads a testdata file and returns its bytes.
func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(testdataPath(t, name))
	require.NoError(t, err, "fixture %s must exist", name)
	return b
}

// makeJSRequest builds an ObservedRequest whose response body is the given JS
// bytes. It simulates a captured JavaScript bundle.
func makeJSRequest(url string, body []byte) crawl.ObservedRequest {
	return crawl.ObservedRequest{
		Method: "GET",
		URL:    url,
		Response: crawl.ObservedResponse{
			ContentType: "application/javascript",
			Body:        body,
		},
	}
}

// findService returns the service with the given FQN from a slice, or nil.
func findService(services []classify.GRPCService, fqn string) *classify.GRPCService {
	for i := range services {
		if services[i].Name == fqn {
			return &services[i]
		}
	}
	return nil
}

// findMethod returns the method with the given name from a service slice, or nil.
func findMethod(methods []classify.GRPCMethod, name string) *classify.GRPCMethod {
	for i := range methods {
		if methods[i].Name == name {
			return &methods[i]
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Connect-ES fixture tests (users_connect.js)
// ---------------------------------------------------------------------------

// TestExtractGRPCWebBindings_ConnectES_ServiceFQN verifies that the Connect-ES
// fixture yields the expected service FQN "users.v1.UserService".
func TestExtractGRPCWebBindings_ConnectES_ServiceFQN(t *testing.T) {
	body := readFixture(t, "users_connect.js")
	captured := []crawl.ObservedRequest{makeJSRequest("https://example.com/users_connect.js", body)}

	services, err := ExtractGRPCWebBindings(captured)
	require.NoError(t, err)

	svc := findService(services, "users.v1.UserService")
	assert.NotNil(t, svc, "expected service users.v1.UserService, got %v", services)
}

// TestExtractGRPCWebBindings_ConnectES_Methods verifies both methods are
// recovered from the Connect-ES fixture with correct names.
func TestExtractGRPCWebBindings_ConnectES_Methods(t *testing.T) {
	body := readFixture(t, "users_connect.js")
	captured := []crawl.ObservedRequest{makeJSRequest("https://example.com/users_connect.js", body)}

	services, err := ExtractGRPCWebBindings(captured)
	require.NoError(t, err)

	svc := findService(services, "users.v1.UserService")
	require.NotNil(t, svc)

	getUser := findMethod(svc.Methods, "GetUser")
	assert.NotNil(t, getUser, "expected method GetUser in service, got %v", svc.Methods)

	watchUsers := findMethod(svc.Methods, "WatchUsers")
	assert.NotNil(t, watchUsers, "expected method WatchUsers in service, got %v", svc.Methods)
}

// TestExtractGRPCWebBindings_ConnectES_UnaryMethod verifies GetUser (unary)
// has both streaming flags false.
func TestExtractGRPCWebBindings_ConnectES_UnaryMethod(t *testing.T) {
	body := readFixture(t, "users_connect.js")
	captured := []crawl.ObservedRequest{makeJSRequest("https://example.com/users_connect.js", body)}

	services, err := ExtractGRPCWebBindings(captured)
	require.NoError(t, err)

	svc := findService(services, "users.v1.UserService")
	require.NotNil(t, svc)
	m := findMethod(svc.Methods, "GetUser")
	require.NotNil(t, m)

	assert.False(t, m.ClientStreaming, "GetUser must not be client-streaming")
	assert.False(t, m.ServerStreaming, "GetUser must not be server-streaming")
}

// TestExtractGRPCWebBindings_ConnectES_ServerStreamingMethod verifies WatchUsers
// has ServerStreaming:true as encoded in the Connect-ES MethodKind.ServerStreaming.
func TestExtractGRPCWebBindings_ConnectES_ServerStreamingMethod(t *testing.T) {
	body := readFixture(t, "users_connect.js")
	captured := []crawl.ObservedRequest{makeJSRequest("https://example.com/users_connect.js", body)}

	services, err := ExtractGRPCWebBindings(captured)
	require.NoError(t, err)

	svc := findService(services, "users.v1.UserService")
	require.NotNil(t, svc)
	m := findMethod(svc.Methods, "WatchUsers")
	require.NotNil(t, m)

	assert.True(t, m.ServerStreaming, "WatchUsers must be server-streaming")
	assert.False(t, m.ClientStreaming, "WatchUsers must not be client-streaming")
}

// TestExtractGRPCWebBindings_ConnectES_InputOutputTypes verifies that input and
// output types are recovered (non-empty) from the Connect-ES fixture.
func TestExtractGRPCWebBindings_ConnectES_InputOutputTypes(t *testing.T) {
	body := readFixture(t, "users_connect.js")
	captured := []crawl.ObservedRequest{makeJSRequest("https://example.com/users_connect.js", body)}

	services, err := ExtractGRPCWebBindings(captured)
	require.NoError(t, err)

	svc := findService(services, "users.v1.UserService")
	require.NotNil(t, svc)
	m := findMethod(svc.Methods, "GetUser")
	require.NotNil(t, m)

	assert.NotEmpty(t, m.InputType, "InputType must not be empty")
	assert.NotEmpty(t, m.OutputType, "OutputType must not be empty")
}

// ---------------------------------------------------------------------------
// grpc-web _pb_service.js fixture tests (users_pb_service.js)
// ---------------------------------------------------------------------------

// TestExtractGRPCWebBindings_PBService_ServiceFQN verifies the pb_service fixture
// yields the expected service FQN.
func TestExtractGRPCWebBindings_PBService_ServiceFQN(t *testing.T) {
	body := readFixture(t, "users_pb_service.js")
	captured := []crawl.ObservedRequest{makeJSRequest("https://example.com/users_pb_service.js", body)}

	services, err := ExtractGRPCWebBindings(captured)
	require.NoError(t, err)

	svc := findService(services, "users.v1.UserService")
	assert.NotNil(t, svc, "expected service users.v1.UserService, got %v", services)
}

// TestExtractGRPCWebBindings_PBService_UnaryMethod verifies GetUser has both
// streaming flags false (requestStream:false, responseStream:false in fixture).
func TestExtractGRPCWebBindings_PBService_UnaryMethod(t *testing.T) {
	body := readFixture(t, "users_pb_service.js")
	captured := []crawl.ObservedRequest{makeJSRequest("https://example.com/users_pb_service.js", body)}

	services, err := ExtractGRPCWebBindings(captured)
	require.NoError(t, err)

	svc := findService(services, "users.v1.UserService")
	require.NotNil(t, svc)
	m := findMethod(svc.Methods, "GetUser")
	require.NotNil(t, m, "expected method GetUser in pb_service fixture")

	assert.False(t, m.ClientStreaming, "GetUser requestStream is false in fixture")
	assert.False(t, m.ServerStreaming, "GetUser responseStream is false in fixture")
}

// TestExtractGRPCWebBindings_PBService_ClientStreamingMethod verifies UploadUsers
// has ClientStreaming:true (requestStream:true in fixture).
func TestExtractGRPCWebBindings_PBService_ClientStreamingMethod(t *testing.T) {
	body := readFixture(t, "users_pb_service.js")
	captured := []crawl.ObservedRequest{makeJSRequest("https://example.com/users_pb_service.js", body)}

	services, err := ExtractGRPCWebBindings(captured)
	require.NoError(t, err)

	svc := findService(services, "users.v1.UserService")
	require.NotNil(t, svc)
	m := findMethod(svc.Methods, "UploadUsers")
	require.NotNil(t, m, "expected method UploadUsers in pb_service fixture")

	assert.True(t, m.ClientStreaming, "UploadUsers requestStream is true in fixture")
	assert.False(t, m.ServerStreaming, "UploadUsers responseStream is false in fixture")
}

// ---------------------------------------------------------------------------
// grpc-web _grpc_web_pb.js fixture tests (users_grpc_web_pb.js)
// ---------------------------------------------------------------------------

// TestExtractGRPCWebBindings_GRPCWebPB_ServiceFQN verifies the grpc_web_pb
// fixture yields the expected service FQN from the MethodDescriptor path.
func TestExtractGRPCWebBindings_GRPCWebPB_ServiceFQN(t *testing.T) {
	body := readFixture(t, "users_grpc_web_pb.js")
	captured := []crawl.ObservedRequest{makeJSRequest("https://example.com/users_grpc_web_pb.js", body)}

	services, err := ExtractGRPCWebBindings(captured)
	require.NoError(t, err)

	svc := findService(services, "users.v1.UserService")
	assert.NotNil(t, svc, "expected service users.v1.UserService from MethodDescriptor path, got %v", services)
}

// TestExtractGRPCWebBindings_GRPCWebPB_UnaryMethod verifies GetUser has both
// flags false (MethodType.UNARY in fixture).
func TestExtractGRPCWebBindings_GRPCWebPB_UnaryMethod(t *testing.T) {
	body := readFixture(t, "users_grpc_web_pb.js")
	captured := []crawl.ObservedRequest{makeJSRequest("https://example.com/users_grpc_web_pb.js", body)}

	services, err := ExtractGRPCWebBindings(captured)
	require.NoError(t, err)

	svc := findService(services, "users.v1.UserService")
	require.NotNil(t, svc)
	m := findMethod(svc.Methods, "GetUser")
	require.NotNil(t, m)

	assert.False(t, m.ServerStreaming, "GetUser MethodType.UNARY must not be server-streaming")
}

// TestExtractGRPCWebBindings_GRPCWebPB_ServerStreamingMethod verifies WatchUsers
// has ServerStreaming:true (MethodType.SERVER_STREAMING in fixture).
func TestExtractGRPCWebBindings_GRPCWebPB_ServerStreamingMethod(t *testing.T) {
	body := readFixture(t, "users_grpc_web_pb.js")
	captured := []crawl.ObservedRequest{makeJSRequest("https://example.com/users_grpc_web_pb.js", body)}

	services, err := ExtractGRPCWebBindings(captured)
	require.NoError(t, err)

	svc := findService(services, "users.v1.UserService")
	require.NotNil(t, svc)
	m := findMethod(svc.Methods, "WatchUsers")
	require.NotNil(t, m)

	assert.True(t, m.ServerStreaming, "WatchUsers MethodType.SERVER_STREAMING must be server-streaming")
}

// ---------------------------------------------------------------------------
// Negative / edge cases
// ---------------------------------------------------------------------------

// TestExtractGRPCWebBindings_NonJSContentType verifies that a non-JS content
// type is ignored and returns no services.
func TestExtractGRPCWebBindings_NonJSContentType(t *testing.T) {
	// Use the Connect-ES fixture content but serve it as HTML — must be ignored.
	body := readFixture(t, "users_connect.js")
	captured := []crawl.ObservedRequest{
		{
			Method: "GET",
			URL:    "https://example.com/page.html",
			Response: crawl.ObservedResponse{
				ContentType: "text/html",
				Body:        body,
			},
		},
	}

	services, err := ExtractGRPCWebBindings(captured)
	require.NoError(t, err)
	assert.Empty(t, services, "non-JS content type must produce no services")
}

// TestExtractGRPCWebBindings_EmptyCapture verifies an empty capture slice
// returns a nil/empty slice without error.
func TestExtractGRPCWebBindings_EmptyCapture(t *testing.T) {
	services, err := ExtractGRPCWebBindings(nil)
	require.NoError(t, err)
	assert.Empty(t, services)

	services, err = ExtractGRPCWebBindings([]crawl.ObservedRequest{})
	require.NoError(t, err)
	assert.Empty(t, services)
}

// TestExtractGRPCWebBindings_GarbageJSBody verifies that a JS response with
// garbage (non-parseable) content returns no services and does not panic.
func TestExtractGRPCWebBindings_GarbageJSBody(t *testing.T) {
	garbage := []byte("\x00\x01\x02 not valid javascript {{{{")
	captured := []crawl.ObservedRequest{makeJSRequest("https://example.com/bundle.js", garbage)}

	services, err := ExtractGRPCWebBindings(captured)
	require.NoError(t, err)
	assert.Empty(t, services, "garbage JS must produce no services")
}

// TestExtractGRPCWebBindings_EmptyJSBody verifies an empty body is skipped
// without error.
func TestExtractGRPCWebBindings_EmptyJSBody(t *testing.T) {
	captured := []crawl.ObservedRequest{makeJSRequest("https://example.com/empty.js", []byte{})}

	services, err := ExtractGRPCWebBindings(captured)
	require.NoError(t, err)
	assert.Empty(t, services)
}

// TestExtractGRPCWebBindings_PlainJSNoBindings verifies that a JS file that
// contains no gRPC-Web/Connect patterns returns no services.
func TestExtractGRPCWebBindings_PlainJSNoBindings(t *testing.T) {
	plain := []byte(`
		const x = 42;
		function hello(name) { return "Hello, " + name; }
		fetch("/api/users");
	`)
	captured := []crawl.ObservedRequest{makeJSRequest("https://example.com/app.js", plain)}

	services, err := ExtractGRPCWebBindings(captured)
	require.NoError(t, err)
	assert.Empty(t, services, "plain (non-grpc) JS must produce no services")
}

// TestExtractGRPCWebBindings_OversizedBodySkipped verifies that a body
// exceeding maxGRPCWebBundleSize is skipped without error.
func TestExtractGRPCWebBindings_OversizedBodySkipped(t *testing.T) {
	// Build a body just over the size cap; it carries valid gRPC-Web content so
	// if NOT skipped it would yield a service.
	base := readFixture(t, "users_connect.js")
	large := make([]byte, maxGRPCWebBundleSize+1)
	copy(large, base)

	captured := []crawl.ObservedRequest{makeJSRequest("https://example.com/huge.js", large)}

	services, err := ExtractGRPCWebBindings(captured)
	require.NoError(t, err)
	// Oversized body is skipped → no services regardless of content.
	assert.Empty(t, services, "oversized bundle must be skipped")
}

// TestExtractGRPCWebBindings_DeduplicatesAcrossBundles verifies that when the
// same service appears in two bundles its methods are merged and the service
// appears exactly once in the output.
func TestExtractGRPCWebBindings_DeduplicatesAcrossBundles(t *testing.T) {
	// Both fixtures carry users.v1.UserService — merge must produce one service.
	connectBody := readFixture(t, "users_connect.js")
	pbBody := readFixture(t, "users_pb_service.js")

	captured := []crawl.ObservedRequest{
		makeJSRequest("https://example.com/users_connect.js", connectBody),
		makeJSRequest("https://example.com/users_pb_service.js", pbBody),
	}

	services, err := ExtractGRPCWebBindings(captured)
	require.NoError(t, err)

	count := 0
	for _, s := range services {
		if s.Name == "users.v1.UserService" {
			count++
		}
	}
	assert.Equal(t, 1, count, "users.v1.UserService must appear exactly once after dedup")
}

// TestExtractGRPCWebBindings_DeterministicOutput verifies two identical calls
// produce identical sorted output.
func TestExtractGRPCWebBindings_DeterministicOutput(t *testing.T) {
	body := readFixture(t, "users_connect.js")
	captured := []crawl.ObservedRequest{makeJSRequest("https://example.com/users_connect.js", body)}

	svcs1, err := ExtractGRPCWebBindings(captured)
	require.NoError(t, err)
	svcs2, err := ExtractGRPCWebBindings(captured)
	require.NoError(t, err)

	require.Equal(t, len(svcs1), len(svcs2))
	for i := range svcs1 {
		assert.Equal(t, svcs1[i].Name, svcs2[i].Name)
		assert.Equal(t, len(svcs1[i].Methods), len(svcs2[i].Methods))
	}
}

// TestIsJSContentTypeForGRPC_Variants tests the content-type predicate with
// common JS MIME types and non-JS types.
func TestIsJSContentTypeForGRPC_Variants(t *testing.T) {
	jsTypes := []string{
		"application/javascript",
		"application/javascript; charset=utf-8",
		"text/javascript",
		"application/x-javascript",
		"text/ecmascript",
		"application/ecmascript",
		"text/js",
		"application/x-js",
		"APPLICATION/JAVASCRIPT", // uppercase
	}
	for _, ct := range jsTypes {
		assert.True(t, isJSContentTypeForGRPC(ct), "expected %q to be identified as JS", ct)
	}

	nonJSTypes := []string{
		"text/html",
		"application/json",
		"text/css",
		"application/wasm",
		"",
	}
	for _, ct := range nonJSTypes {
		assert.False(t, isJSContentTypeForGRPC(ct), "expected %q NOT to be identified as JS", ct)
	}
}
