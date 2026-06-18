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

package probe_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/vespasian/pkg/classify"
	"github.com/praetorian-inc/vespasian/pkg/crawl"
	"github.com/praetorian-inc/vespasian/pkg/probe"
)

// loopbackConfig returns a probe.Config suitable for httptest servers: it
// bypasses SSRF URL validation and uses the test server's own client so TLS
// handling works correctly.
func loopbackConfig(srv *httptest.Server) probe.Config {
	return probe.Config{
		Client:       srv.Client(),
		Timeout:      5 * time.Second,
		URLValidator: func(string) error { return nil },
		MaxEndpoints: 100,
	}
}

// grpcEndpoint builds a classified gRPC endpoint pointing to the given rawURL.
func grpcEndpoint(rawURL string) classify.ClassifiedRequest {
	return classify.ClassifiedRequest{
		ObservedRequest: crawl.ObservedRequest{
			Method: "POST",
			URL:    rawURL,
		},
		IsAPI:   true,
		APIType: "grpc",
	}
}

// readTestdata reads a fixture under pkg/probe/testdata/grpc_gateway/.
func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "grpc_gateway", name)) // #nosec G304 -- test reads fixed local testdata fixtures
	require.NoError(t, err)
	return b
}

// serveSingle builds an httptest server that serves body at exactPath and
// returns 404 for all other paths.
func serveSingle(body []byte, exactPath string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == exactPath {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write(body) //nolint:gosec // test handler
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
}

// ---------------------------------------------------------------------------
// Name / constructor
// ---------------------------------------------------------------------------

// TestGRPCGatewayProbe_Name verifies the probe reports the expected strategy name.
func TestGRPCGatewayProbe_Name(t *testing.T) {
	p := probe.NewGRPCGatewayProbe(probe.DefaultConfig())
	assert.Equal(t, "grpc-gateway", p.Name())
}

// TestGRPCGatewayProbe_ImplementsProbeStrategy is a compile-time check that
// GRPCGatewayProbe implements ProbeStrategy.
func TestGRPCGatewayProbe_ImplementsProbeStrategy(t *testing.T) {
	var _ probe.ProbeStrategy = probe.NewGRPCGatewayProbe(probe.DefaultConfig())
}

// ---------------------------------------------------------------------------
// Positive detection: grpc-gateway swagger.json
// ---------------------------------------------------------------------------

// TestGRPCGatewayProbe_PositiveDetection verifies that serving a protoc-gen-
// openapiv2-style swagger.json at /swagger.json enriches the gRPC endpoint with
// a non-nil GRPCSchema containing at least one service.
func TestGRPCGatewayProbe_PositiveDetection(t *testing.T) {
	body := readTestdata(t, "swagger.json")
	srv := serveSingle(body, "/swagger.json")
	defer srv.Close()

	p := probe.NewGRPCGatewayProbe(loopbackConfig(srv))
	endpoints := []classify.ClassifiedRequest{grpcEndpoint(srv.URL + "/grpc")}

	result, err := p.Probe(context.Background(), endpoints)
	require.NoError(t, err)
	require.Len(t, result, 1)

	schema := result[0].GRPCSchema
	require.NotNil(t, schema, "GRPCSchema must be set after positive detection")
	assert.True(t, schema.ReflectionEnabled, "ReflectionEnabled must be true for synthesized descriptors")
	assert.NotEmpty(t, schema.Services, "at least one service must be recovered")
	assert.NotEmpty(t, schema.FileDescriptors, "FileDescriptors must be synthesized")
}

// TestGRPCGatewayProbe_RecoveredServiceFQN verifies the recovered service name
// matches the FQN in the swagger fixture (UserService).
func TestGRPCGatewayProbe_RecoveredServiceFQN(t *testing.T) {
	body := readTestdata(t, "swagger.json")
	srv := serveSingle(body, "/swagger.json")
	defer srv.Close()

	p := probe.NewGRPCGatewayProbe(loopbackConfig(srv))
	endpoints := []classify.ClassifiedRequest{grpcEndpoint(srv.URL + "/grpc")}

	result, err := p.Probe(context.Background(), endpoints)
	require.NoError(t, err)

	schema := result[0].GRPCSchema
	require.NotNil(t, schema)
	require.NotEmpty(t, schema.Services)

	var svcNames []string
	for _, s := range schema.Services {
		svcNames = append(svcNames, s.Name)
	}
	assert.Contains(t, svcNames, "UserService", "UserService must be among recovered services; got %v", svcNames)
}

// TestGRPCGatewayProbe_RecoveredMethods verifies that the operationId suffixes
// from the swagger fixture are recovered as method names (GetUser, CreateUser).
func TestGRPCGatewayProbe_RecoveredMethods(t *testing.T) {
	body := readTestdata(t, "swagger.json")
	srv := serveSingle(body, "/swagger.json")
	defer srv.Close()

	p := probe.NewGRPCGatewayProbe(loopbackConfig(srv))
	endpoints := []classify.ClassifiedRequest{grpcEndpoint(srv.URL + "/grpc")}

	result, err := p.Probe(context.Background(), endpoints)
	require.NoError(t, err)

	schema := result[0].GRPCSchema
	require.NotNil(t, schema)
	require.NotEmpty(t, schema.Services)

	// Collect all method names across all services.
	var methodNames []string
	for _, svc := range schema.Services {
		for _, m := range svc.Methods {
			methodNames = append(methodNames, m.Name)
		}
	}
	assert.Contains(t, methodNames, "GetUser", "GetUser operationId must be recovered")
	assert.Contains(t, methodNames, "CreateUser", "CreateUser operationId must be recovered")
}

// TestGRPCGatewayProbe_AlternativePath verifies detection when the document is
// at /swagger/v1/swagger.json (second in the well-known path list) instead of
// the primary /swagger.json path.
func TestGRPCGatewayProbe_AlternativePath(t *testing.T) {
	body := readTestdata(t, "swagger.json")
	srv := serveSingle(body, "/swagger/v1/swagger.json")
	defer srv.Close()

	p := probe.NewGRPCGatewayProbe(loopbackConfig(srv))
	endpoints := []classify.ClassifiedRequest{grpcEndpoint(srv.URL + "/grpc")}

	result, err := p.Probe(context.Background(), endpoints)
	require.NoError(t, err)

	schema := result[0].GRPCSchema
	assert.NotNil(t, schema, "GRPCSchema must be set when document is at /swagger/v1/swagger.json")
	if schema != nil {
		assert.NotEmpty(t, schema.Services)
	}
}

// ---------------------------------------------------------------------------
// Negative detection: plain REST swagger (no false positive)
// ---------------------------------------------------------------------------

// TestGRPCGatewayProbe_PlainRESTNoFalsePositive verifies that a plain (non-
// grpc-gateway) swagger document does NOT produce a GRPCSchema.
func TestGRPCGatewayProbe_PlainRESTNoFalsePositive(t *testing.T) {
	body := readTestdata(t, "plain_rest.json")
	srv := serveSingle(body, "/swagger.json")
	defer srv.Close()

	p := probe.NewGRPCGatewayProbe(loopbackConfig(srv))
	endpoints := []classify.ClassifiedRequest{grpcEndpoint(srv.URL + "/grpc")}

	result, err := p.Probe(context.Background(), endpoints)
	require.NoError(t, err)
	require.Len(t, result, 1)

	assert.Nil(t, result[0].GRPCSchema, "plain REST doc must NOT produce a GRPCSchema (false positive)")
}

// ---------------------------------------------------------------------------
// 404 / all-paths-miss case
// ---------------------------------------------------------------------------

// TestGRPCGatewayProbe_AllPathsMiss verifies that when all well-known paths
// return 404, no GRPCSchema is set and the probe returns no error.
func TestGRPCGatewayProbe_AllPathsMiss(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	p := probe.NewGRPCGatewayProbe(loopbackConfig(srv))
	endpoints := []classify.ClassifiedRequest{grpcEndpoint(srv.URL + "/grpc")}

	result, err := p.Probe(context.Background(), endpoints)
	require.NoError(t, err, "404 responses must not cause an error (non-fatal)")
	require.Len(t, result, 1)

	assert.Nil(t, result[0].GRPCSchema, "404 on all paths must not set GRPCSchema")
}

// TestGRPCGatewayProbe_ServerError500 verifies that a 500 response on all paths
// does not set a GRPCSchema and is treated as a non-fatal failure.
func TestGRPCGatewayProbe_ServerError500(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	p := probe.NewGRPCGatewayProbe(loopbackConfig(srv))
	endpoints := []classify.ClassifiedRequest{grpcEndpoint(srv.URL + "/grpc")}

	result, err := p.Probe(context.Background(), endpoints)
	require.NoError(t, err)
	assert.Nil(t, result[0].GRPCSchema)
}

// ---------------------------------------------------------------------------
// SSRF gating
// ---------------------------------------------------------------------------

// TestGRPCGatewayProbe_URLValidatorRejection verifies that when URLValidator
// returns an error, the host is skipped without producing a GRPCSchema and
// without propagating the validation error to the caller.
func TestGRPCGatewayProbe_URLValidatorRejection(t *testing.T) {
	// Use the full swagger fixture so it would be detected IF the request reached the server.
	body := readTestdata(t, "swagger.json")
	srv := serveSingle(body, "/swagger.json")
	defer srv.Close()

	// Validator that always rejects.
	rejecting := func(string) error { return errors.New("SSRF block: private address") }

	cfg := probe.Config{
		Client:       srv.Client(),
		Timeout:      5 * time.Second,
		URLValidator: rejecting,
		MaxEndpoints: 100,
	}
	p := probe.NewGRPCGatewayProbe(cfg)
	endpoints := []classify.ClassifiedRequest{grpcEndpoint(srv.URL + "/grpc")}

	result, err := p.Probe(context.Background(), endpoints)
	// Non-fatal: error must not be propagated.
	require.NoError(t, err, "URLValidator rejection must be non-fatal")
	require.Len(t, result, 1)

	assert.Nil(t, result[0].GRPCSchema, "rejected URL must not produce a GRPCSchema")
}

// TestGRPCGatewayProbe_DefaultConfigSSRFBlocksLoopback verifies that with the
// default (real SSRF-protection) config, a 127.0.0.1 URL is blocked and
// produces no GRPCSchema without an error. This exercises the SSRF-gating path
// without needing the allow-private flag.
func TestGRPCGatewayProbe_DefaultConfigSSRFBlocksLoopback(t *testing.T) {
	p := probe.NewGRPCGatewayProbe(probe.DefaultConfig())
	// Point at localhost — will be rejected by the default URLValidator.
	endpoints := []classify.ClassifiedRequest{grpcEndpoint("http://127.0.0.1:1/grpc")}

	result, err := p.Probe(context.Background(), endpoints)
	require.NoError(t, err, "SSRF block must not propagate an error")
	require.Len(t, result, 1)
	assert.Nil(t, result[0].GRPCSchema, "SSRF-blocked URL must not produce a GRPCSchema")
}

// ---------------------------------------------------------------------------
// Non-gRPC endpoint passthrough
// ---------------------------------------------------------------------------

// TestGRPCGatewayProbe_NonGRPCEndpointsUnchanged verifies that endpoints with
// APIType != "grpc" are passed through unchanged.
func TestGRPCGatewayProbe_NonGRPCEndpointsUnchanged(t *testing.T) {
	body := readTestdata(t, "swagger.json")
	srv := serveSingle(body, "/swagger.json")
	defer srv.Close()

	p := probe.NewGRPCGatewayProbe(loopbackConfig(srv))
	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{Method: "POST", URL: srv.URL + "/graphql"},
			APIType:         "graphql",
		},
		{
			ObservedRequest: crawl.ObservedRequest{Method: "GET", URL: srv.URL + "/api/users"},
			APIType:         "rest",
		},
	}

	result, err := p.Probe(context.Background(), endpoints)
	require.NoError(t, err)
	require.Len(t, result, 2)

	for _, ep := range result {
		assert.Nil(t, ep.GRPCSchema, "non-gRPC endpoint must not get a GRPCSchema, APIType=%s", ep.APIType)
	}
}

// ---------------------------------------------------------------------------
// Reflection precedence (do not overwrite real reflection result)
// ---------------------------------------------------------------------------

// TestGRPCGatewayProbe_DoesNotOverwriteReflectionResult verifies that when an
// endpoint already has GRPCSchema with ReflectionEnabled and FileDescriptors
// set (a real reflection result), the probe does NOT overwrite it even when a
// gateway document is available.
func TestGRPCGatewayProbe_DoesNotOverwriteReflectionResult(t *testing.T) {
	body := readTestdata(t, "swagger.json")
	srv := serveSingle(body, "/swagger.json")
	defer srv.Close()

	existingSchema := &classify.GRPCReflectionResult{
		ReflectionEnabled: true,
		Services: []classify.GRPCService{
			{
				Name: "real.ReflectionService",
				Methods: []classify.GRPCMethod{
					{Name: "RealMethod", InputType: "RealReq", OutputType: "RealResp"},
				},
			},
		},
		FileDescriptors: map[string][]byte{
			"real.proto": {0x01, 0x02, 0x03}, // synthetic non-empty value
		},
	}

	p := probe.NewGRPCGatewayProbe(loopbackConfig(srv))
	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{Method: "POST", URL: srv.URL + "/grpc"},
			APIType:         "grpc",
			GRPCSchema:      existingSchema,
		},
	}

	result, err := p.Probe(context.Background(), endpoints)
	require.NoError(t, err)
	require.Len(t, result, 1)

	// The existing schema must not have been replaced.
	assert.Equal(t, existingSchema, result[0].GRPCSchema,
		"existing reflection GRPCSchema must not be overwritten by gateway probe")
	// Specifically, the real service must still be present.
	require.NotEmpty(t, result[0].GRPCSchema.Services)
	assert.Equal(t, "real.ReflectionService", result[0].GRPCSchema.Services[0].Name)
}

// ---------------------------------------------------------------------------
// Empty endpoints / edge cases
// ---------------------------------------------------------------------------

// TestGRPCGatewayProbe_EmptyEndpoints verifies that an empty input slice
// returns an empty output without error.
func TestGRPCGatewayProbe_EmptyEndpoints(t *testing.T) {
	p := probe.NewGRPCGatewayProbe(probe.DefaultConfig())
	result, err := p.Probe(context.Background(), nil)
	require.NoError(t, err)
	assert.Empty(t, result)

	result, err = p.Probe(context.Background(), []classify.ClassifiedRequest{})
	require.NoError(t, err)
	assert.Empty(t, result)
}

// TestGRPCGatewayProbe_InvalidURLSkipped verifies that an unparseable gRPC
// endpoint URL is skipped without propagating an error.
func TestGRPCGatewayProbe_InvalidURLSkipped(t *testing.T) {
	p := probe.NewGRPCGatewayProbe(probe.Config{
		Client:       http.DefaultClient,
		Timeout:      2 * time.Second,
		URLValidator: func(string) error { return nil },
		MaxEndpoints: 10,
	})
	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{URL: "://invalid-url"},
			APIType:         "grpc",
		},
	}

	result, err := p.Probe(context.Background(), endpoints)
	require.NoError(t, err)
	require.Len(t, result, 1)
	assert.Nil(t, result[0].GRPCSchema, "invalid URL must be skipped without GRPCSchema")
}

// TestGRPCGatewayProbe_DeduplicatesHosts verifies that two gRPC endpoints on
// the same host trigger only one swagger fetch sequence (deduplicated by host).
func TestGRPCGatewayProbe_DeduplicatesHosts(t *testing.T) {
	body := readTestdata(t, "swagger.json")
	fetchCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/swagger.json" {
			fetchCount++
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write(body) //nolint:gosec // test handler
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	p := probe.NewGRPCGatewayProbe(loopbackConfig(srv))
	endpoints := []classify.ClassifiedRequest{
		grpcEndpoint(srv.URL + "/grpc/users"),
		grpcEndpoint(srv.URL + "/grpc/orders"),
	}

	result, err := p.Probe(context.Background(), endpoints)
	require.NoError(t, err)
	require.Len(t, result, 2)

	// Both endpoints get enriched with the same schema.
	assert.NotNil(t, result[0].GRPCSchema)
	assert.NotNil(t, result[1].GRPCSchema)

	// Only one host → fetched only once (one successful hit stops the path loop).
	assert.Equal(t, 1, fetchCount, "swagger.json must be fetched only once per host")
}

// TestGRPCGatewayProbe_MalformedJSONBody verifies that a malformed JSON body at
// a well-known path does not set a GRPCSchema and does not propagate an error.
func TestGRPCGatewayProbe_MalformedJSONBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/swagger.json" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("not json {{{")) //nolint:gosec // test handler
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	p := probe.NewGRPCGatewayProbe(loopbackConfig(srv))
	endpoints := []classify.ClassifiedRequest{grpcEndpoint(srv.URL + "/grpc")}

	result, err := p.Probe(context.Background(), endpoints)
	require.NoError(t, err)
	assert.Nil(t, result[0].GRPCSchema, "malformed JSON must not produce a GRPCSchema")
}
