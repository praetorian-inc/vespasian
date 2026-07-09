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

package pipeline_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	"github.com/praetorian-inc/vespasian/internal/pipeline"
	"github.com/praetorian-inc/vespasian/pkg/crawl"
)

// ---------------------------------------------------------------------------
// TEST-003: Options.Status writer — pin the io.Writer seam
// ---------------------------------------------------------------------------

// restRequests returns a minimal slice of REST-like requests suitable for
// feeding ClassifyProbeGenerate in REST mode.
func restRequests() []crawl.ObservedRequest {
	return []crawl.ObservedRequest{
		{
			Method:  "GET",
			URL:     "https://x.com/api/v1/users",
			Headers: map[string]string{"Content-Type": "application/json"},
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "application/json",
				Headers:     map[string]string{"Content-Type": "application/json"},
				Body:        []byte(`[{"id":1}]`),
			},
		},
	}
}

func TestClassifyProbeGenerate_StatusWriterNil(t *testing.T) {
	// Status=nil must not panic and must produce no unexpected output.
	_, err := pipeline.ClassifyProbeGenerate(context.Background(), restRequests(), pipeline.Options{
		APIType:    pipeline.APITypeREST,
		Confidence: 0.5,
		Probe:      false,
		Status:     nil,
	})
	require.NoError(t, err)
}

func TestClassifyProbeGenerate_StatusWriterCaptures(t *testing.T) {
	// Status=&bytes.Buffer{} must capture the "classified N API requests" line.
	var buf bytes.Buffer
	_, err := pipeline.ClassifyProbeGenerate(context.Background(), restRequests(), pipeline.Options{
		APIType:    pipeline.APITypeREST,
		Confidence: 0.5,
		Probe:      false,
		Status:     &buf,
	})
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "classified")
	assert.Contains(t, buf.String(), "API requests")
}

// ---------------------------------------------------------------------------
// TEST-004: happy-path test for ClassifyProbeGenerate
// ---------------------------------------------------------------------------

func TestClassifyProbeGenerate_RESTHappyPath(t *testing.T) {
	spec, err := pipeline.ClassifyProbeGenerate(context.Background(), restRequests(), pipeline.Options{
		APIType:     pipeline.APITypeREST,
		Confidence:  0.5,
		Probe:       false,
		Deduplicate: true,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, spec, "expected non-empty OpenAPI spec for REST requests")
}

func TestClassifyProbeGenerate_EmptyRequestsReturnsSpec(t *testing.T) {
	// An empty requests slice is not an error; the generator produces a minimal
	// (possibly empty) spec.
	spec, err := pipeline.ClassifyProbeGenerate(context.Background(), nil, pipeline.Options{
		APIType:    pipeline.APITypeREST,
		Confidence: 0.5,
	})
	// ClassifyProbeGenerate should not error on empty input for known api types.
	require.NoError(t, err)
	// spec may be empty but the call must not panic.
	_ = spec
}

func TestClassifyProbeGenerate_UnknownTypeErrors(t *testing.T) {
	_, err := pipeline.ClassifyProbeGenerate(context.Background(), restRequests(), pipeline.Options{
		APIType:    "unknown",
		Confidence: 0.5,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported API type")
}

// ---------------------------------------------------------------------------
// TEST-002: Probe-enabled path — pin that the AllowPrivate http.Client
// construction and strategies execution run end-to-end without error and
// still produce a spec. OptionsProbe and SchemaProbe swallow individual
// request failures internally and never surface to probeErrs, so the
// "probe warning:" forwarding loop in pipeline.go is unreachable for REST
// mode and is intentionally not exercised here.
// ---------------------------------------------------------------------------

func TestClassifyProbeGenerate_ProbeEnabledEmitsSpec(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(ts.Close)

	requests := []crawl.ObservedRequest{
		{
			Method:  "GET",
			URL:     ts.URL + "/api/v1/users",
			Headers: map[string]string{"Content-Type": "application/json"},
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "application/json",
				Headers:     map[string]string{"Content-Type": "application/json"},
				Body:        []byte(`[{"id":1}]`),
			},
		},
	}
	spec, err := pipeline.ClassifyProbeGenerate(context.Background(), requests, pipeline.Options{
		APIType:      pipeline.APITypeREST,
		Confidence:   0.5,
		Probe:        true,
		AllowPrivate: true,
		Deduplicate:  true,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, spec, "expected non-empty OpenAPI spec when Probe=true")
}

// slugRequests returns two REST requests to sibling slug paths under the same
// collection (/api/posts/a and /api/posts/b), enough distinct values to trip
// slug merging at threshold 2.
func slugRequests() []crawl.ObservedRequest {
	req := func(url string) crawl.ObservedRequest {
		return crawl.ObservedRequest{
			Method:  "GET",
			URL:     url,
			Headers: map[string]string{"Content-Type": "application/json"},
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "application/json",
				Headers:     map[string]string{"Content-Type": "application/json"},
				Body:        []byte(`{"id":1}`),
			},
		}
	}
	return []crawl.ObservedRequest{
		req("https://x.com/api/posts/a"),
		req("https://x.com/api/posts/b"),
	}
}

// TestClassifyProbeGenerate_MergeSlugsPassThrough pins that Options.MergeSlugs
// and Options.SlugThreshold reach generate.GetWithOptions: with MergeSlugs set,
// two sibling slug paths collapse into one templated path in the emitted spec,
// whereas leaving MergeSlugs unset keeps them literal. Without this, a regressed
// pass-through at this layer would go undetected (it is otherwise only exercised
// via the CLI and pkg/generate).
func TestClassifyProbeGenerate_MergeSlugsPassThrough(t *testing.T) {
	merged, err := pipeline.ClassifyProbeGenerate(context.Background(), slugRequests(), pipeline.Options{
		APIType:       pipeline.APITypeREST,
		Confidence:    0.5,
		Probe:         false,
		Deduplicate:   true,
		MergeSlugs:    true,
		SlugThreshold: 2,
	})
	require.NoError(t, err)
	assert.Contains(t, string(merged), "/api/posts/{postSlug}", "MergeSlugs=true must collapse siblings into a templated path")
	assert.NotContains(t, string(merged), "/api/posts/a", "merged spec must not retain the literal slug path")

	// Control: without MergeSlugs the same input keeps the literal paths, proving
	// the collapse above is driven by the flag pass-through, not the fixture.
	literal, err := pipeline.ClassifyProbeGenerate(context.Background(), slugRequests(), pipeline.Options{
		APIType:     pipeline.APITypeREST,
		Confidence:  0.5,
		Probe:       false,
		Deduplicate: true,
	})
	require.NoError(t, err)
	assert.Contains(t, string(literal), "/api/posts/a", "MergeSlugs unset must keep the literal slug path")
	assert.NotContains(t, string(literal), "{postSlug}", "MergeSlugs unset must not template the slug position")
}

// ---------------------------------------------------------------------------
// TEST-002 (SEC-BE follow-up): GRPCInsecureSkipVerify threads through the
// pipeline into probe.Config and the gRPC reflection probe. The probe's own
// package tests (pkg/probe/grpc_test.go) prove the flag toggles TLS trust-chain
// verification; this test proves the pipeline Options field actually reaches it.
//
// The TLS+reflection server below is reimplemented here because the probe test
// helpers are unexported (package probe) and cannot be shared with this
// external test package.
// ---------------------------------------------------------------------------

// grpcSelfSignedTLSConfig builds a *tls.Config carrying a freshly generated,
// in-memory self-signed certificate valid for 127.0.0.1 (mirrors
// pkg/probe/grpc_test.go: selfSignedTLSConfig).
func grpcSelfSignedTLSConfig(t *testing.T) *tls.Config {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	require.NoError(t, err)

	cert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}} //nolint:gosec // test server cert
}

// startTestGRPCReflectionServerTLS brings up an in-process gRPC server on
// 127.0.0.1:0 served over TLS with a self-signed certificate, with the health
// service and reflection registered (mirrors pkg/probe/grpc_test.go:
// startTestGRPCServerTLS). Returns the listener address and a cleanup function.
func startTestGRPCReflectionServerTLS(t *testing.T) (string, func()) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	s := grpc.NewServer(grpc.Creds(credentials.NewTLS(grpcSelfSignedTLSConfig(t))))
	healthpb.RegisterHealthServer(s, health.NewServer())
	reflection.Register(s)

	go func() {
		_ = s.Serve(lis)
	}()

	cleanup := func() {
		s.GracefulStop()
	}
	return lis.Addr().String(), cleanup
}

// TestClassifyProbeGenerate_GRPCInsecureSkipVerify proves that
// Options.GRPCInsecureSkipVerify is threaded from the pipeline Options through
// probe.Config to the gRPC reflection probe, end-to-end.
//
// The gRPC classifier returns 0.99 confidence when a request carries an
// application/grpc content-type AND a grpc-status trailer (the HTTP/2 gRPC
// fingerprint per pkg/classify/grpc.go), so Classify(req) succeeds at the 0.5
// threshold used here. The target is the in-process self-signed TLS reflection
// server; AllowPrivate=true installs the pipeline's permissive dialer so the
// loopback (private) address is not rejected by SSRF SafeDialContext.
func TestClassifyProbeGenerate_GRPCInsecureSkipVerify(t *testing.T) {
	addr, stop := startTestGRPCReflectionServerTLS(t)
	t.Cleanup(stop)

	req := crawl.ObservedRequest{
		Method:  "POST",
		URL:     "https://" + addr + "/grpc.health.v1.Health/Check",
		Headers: map[string]string{"Content-Type": "application/grpc"},
		Response: crawl.ObservedResponse{
			StatusCode:  200,
			ContentType: "application/grpc",
			Headers:     map[string]string{"grpc-status": "0"},
		},
	}

	t.Run("insecure_skip_verify_true", func(t *testing.T) {
		spec, err := pipeline.ClassifyProbeGenerate(context.Background(), []crawl.ObservedRequest{req}, pipeline.Options{
			APIType:                pipeline.APITypeGRPC,
			Confidence:             0.5,
			Probe:                  true,
			AllowPrivate:           true,
			GRPCInsecureSkipVerify: true,
		})
		require.NoError(t, err)
		require.NotEmpty(t, spec, "reflection over self-signed TLS with skip-verify must yield a .proto spec")
		assert.Contains(t, string(spec), "service", "generated .proto must declare a gRPC service")
	})

	t.Run("verify_by_default", func(t *testing.T) {
		// Self-signed cert fails verification → reflection never runs → no
		// FileDescriptors → the gRPC generator returns its "requires server
		// reflection" error. This is the negative half proving the flag actually
		// changes behavior through the pipeline.
		spec, err := pipeline.ClassifyProbeGenerate(context.Background(), []crawl.ObservedRequest{req}, pipeline.Options{
			APIType:                pipeline.APITypeGRPC,
			Confidence:             0.5,
			Probe:                  true,
			AllowPrivate:           true,
			GRPCInsecureSkipVerify: false,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "reflection",
			"verify-by-default must fail because reflection never ran (no descriptors), not some unrelated error")
		assert.Empty(t, spec)
	})
}
