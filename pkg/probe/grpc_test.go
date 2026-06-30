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

package probe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	grpccodes "google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/praetorian-inc/vespasian/pkg/classify"
)

// startTestGRPCServer brings up an in-process gRPC server on 127.0.0.1:0
// with the health service and reflection registered. Returns the address
// and a cleanup function.
func startTestGRPCServer(t *testing.T) (string, func()) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	s := grpc.NewServer()
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

// startTestGRPCServerNoReflection brings up an in-process gRPC server with
// the health service registered but reflection deliberately omitted. Used
// to exercise the "reflection unavailable" probe outcome.
func startTestGRPCServerNoReflection(t *testing.T) (string, func()) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	s := grpc.NewServer()
	healthpb.RegisterHealthServer(s, health.NewServer())
	// reflection.Register(s) intentionally omitted

	go func() {
		_ = s.Serve(lis)
	}()

	cleanup := func() {
		s.GracefulStop()
	}
	return lis.Addr().String(), cleanup
}

// selfSignedTLSConfig builds a *tls.Config carrying a freshly generated,
// in-memory self-signed certificate valid for 127.0.0.1. It mirrors the kind
// of certificate an internal/self-hosted gRPC service typically presents.
func selfSignedTLSConfig(t *testing.T) *tls.Config {
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

// startTestGRPCServerTLS brings up an in-process gRPC server on 127.0.0.1:0
// served over TLS with a self-signed certificate, with the health service and
// reflection registered. Returns the address and a cleanup function.
func startTestGRPCServerTLS(t *testing.T) (string, func()) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	s := grpc.NewServer(grpc.Creds(credentials.NewTLS(selfSignedTLSConfig(t))))
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

func TestGRPCProbe_Name(t *testing.T) {
	p := NewGRPCProbe(Config{})
	assert.Equal(t, "grpc-reflection", p.Name())
}

func TestGRPCProbe_Probe_DiscoversHealthService(t *testing.T) {
	addr, stop := startTestGRPCServer(t)
	defer stop()

	cfg := Config{
		Timeout:      5 * time.Second,
		URLValidator: func(string) error { return nil }, // no-op for loopback
		Dialer:       loopbackDialer,                    // bypass SSRF dialer for 127.0.0.1
	}
	probe := NewGRPCProbe(cfg)

	endpoints := []classify.ClassifiedRequest{
		{
			APIType: "grpc",
		},
	}
	// Set URL on the embedded ObservedRequest
	endpoints[0].URL = "http://" + addr + "/grpc.health.v1.Health/Check"

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := probe.Probe(ctx, endpoints)
	require.NoError(t, err)
	require.Len(t, result, 1)

	schema := result[0].GRPCSchema
	require.NotNil(t, schema, "GRPCSchema should be populated")
	assert.True(t, schema.ReflectionEnabled)

	var found bool
	var checkMethod *classify.GRPCMethod
	for _, svc := range schema.Services {
		if svc.Name == "grpc.health.v1.Health" {
			found = true
			for i, m := range svc.Methods {
				if m.Name == "Check" {
					checkMethod = &svc.Methods[i]
				}
			}
		}
	}
	assert.True(t, found, "expected grpc.health.v1.Health service in discovered services")
	require.NotNil(t, checkMethod, "expected Check method on Health service")
	assert.Equal(t, "grpc.health.v1.HealthCheckRequest", checkMethod.InputType)
	assert.Equal(t, "grpc.health.v1.HealthCheckResponse", checkMethod.OutputType)
	assert.False(t, checkMethod.ClientStreaming)
	assert.False(t, checkMethod.ServerStreaming)

	// FileDescriptors should be populated with at least the health proto.
	assert.NotEmpty(t, schema.FileDescriptors, "expected FileDescriptors to be populated")
}

// TestGRPCProbe_Probe_SelfSignedTLS proves that a gRPC server presenting a
// self-signed certificate is still enumerated: the probe disables trust-chain
// verification (SSRF is handled separately by the Dialer), so the self-signed
// cert must NOT block reflection.
func TestGRPCProbe_Probe_SelfSignedTLS(t *testing.T) {
	addr, stop := startTestGRPCServerTLS(t)
	defer stop()

	cfg := Config{
		Timeout:                5 * time.Second,
		URLValidator:           func(string) error { return nil },
		Dialer:                 loopbackDialer,
		GRPCInsecureSkipVerify: true, // self-signed cert: opt in to skip trust-chain verification
	}
	probe := NewGRPCProbe(cfg)

	endpoints := []classify.ClassifiedRequest{
		{APIType: "grpc"},
	}
	endpoints[0].URL = "https://" + addr + "/grpc.health.v1.Health/Check"

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := probe.Probe(ctx, endpoints)
	require.NoError(t, err)
	require.Len(t, result, 1)

	schema := result[0].GRPCSchema
	require.NotNil(t, schema, "GRPCSchema should be populated despite the self-signed certificate")
	assert.True(t, schema.ReflectionEnabled, "self-signed cert must not block enumeration")
}

func TestGRPCProbe_Probe_FiltersReflectionServiceItself(t *testing.T) {
	addr, stop := startTestGRPCServer(t)
	defer stop()

	cfg := Config{
		Timeout:      5 * time.Second,
		URLValidator: func(string) error { return nil },
		Dialer:       loopbackDialer,
	}
	probe := NewGRPCProbe(cfg)

	endpoints := []classify.ClassifiedRequest{
		{APIType: "grpc"},
	}
	endpoints[0].URL = "http://" + addr + "/grpc.health.v1.Health/Check"

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := probe.Probe(ctx, endpoints)
	require.NoError(t, err)

	schema := result[0].GRPCSchema
	require.NotNil(t, schema)
	for _, svc := range schema.Services {
		assert.NotEqual(t, "grpc.reflection.v1alpha.ServerReflection", svc.Name)
		assert.NotEqual(t, "grpc.reflection.v1.ServerReflection", svc.Name)
	}
}

// loopbackDialer is a plain TCP dialer used by tests that target 127.0.0.1.
// The default SSRF-safe dialer would reject loopback addresses.
func loopbackDialer(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

func TestGRPCProbe_Probe_ReflectionUnavailable(t *testing.T) {
	// Server reachable, but reflection NOT registered: the probe should
	// return a structured GRPCSchema with ReflectionEnabled=false rather
	// than nil (which would mean "didn't probe at all").
	addr, stop := startTestGRPCServerNoReflection(t)
	defer stop()

	cfg := Config{
		Timeout:      5 * time.Second,
		URLValidator: func(string) error { return nil },
		Dialer:       loopbackDialer,
	}
	probe := NewGRPCProbe(cfg)

	endpoints := []classify.ClassifiedRequest{
		{APIType: "grpc"},
	}
	endpoints[0].URL = "http://" + addr + "/grpc.health.v1.Health/Check"

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := probe.Probe(ctx, endpoints)
	require.NoError(t, err)
	require.Len(t, result, 1)

	schema := result[0].GRPCSchema
	require.NotNil(t, schema, "GRPCSchema must be populated to signal 'probed but reflection disabled'")
	assert.False(t, schema.ReflectionEnabled, "ReflectionEnabled should be false when server has no reflection service")
	assert.Equal(t, "Unimplemented", schema.ReflectionUnavailableReason, "reason should reflect the gRPC status code")
	assert.Empty(t, schema.Services)
	assert.Empty(t, schema.FileDescriptors)
}

func TestReflectionUnavailableReason(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantReason string
		wantOK     bool
	}{
		{"unimplemented", grpcstatus.Error(grpccodes.Unimplemented, "no reflection"), "Unimplemented", true},
		{"unauthenticated", grpcstatus.Error(grpccodes.Unauthenticated, "need auth"), "Unauthenticated", true},
		{"permission denied", grpcstatus.Error(grpccodes.PermissionDenied, "nope"), "PermissionDenied", true},
		{"unavailable (ambiguous)", grpcstatus.Error(grpccodes.Unavailable, "down"), "", false},
		{"deadline exceeded (ambiguous)", grpcstatus.Error(grpccodes.DeadlineExceeded, "timeout"), "", false},
		{"internal (ambiguous)", grpcstatus.Error(grpccodes.Internal, "boom"), "", false},
		{"non-grpc error", errors.New("dial tcp: connection refused"), "", false},
		{"nil error", nil, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reason, ok := reflectionUnavailableReason(tt.err)
			assert.Equal(t, tt.wantReason, reason)
			assert.Equal(t, tt.wantOK, ok)
		})
	}
}

func TestGRPCProbe_Probe_SkipsNonGRPCEndpoints(t *testing.T) {
	probe := NewGRPCProbe(Config{
		URLValidator: func(string) error { return nil },
	})

	endpoints := []classify.ClassifiedRequest{
		{APIType: "rest"},
	}
	endpoints[0].URL = "http://127.0.0.1:1/api/users"

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	result, err := probe.Probe(ctx, endpoints)
	require.NoError(t, err)
	require.Len(t, result, 1)
	assert.Nil(t, result[0].GRPCSchema, "non-gRPC endpoints should not be probed")
}

func TestGRPCProbe_Probe_FailsClosedOnValidator(t *testing.T) {
	// Validator that always rejects — simulating SSRF blocklist.
	probe := NewGRPCProbe(Config{
		Timeout:      2 * time.Second,
		URLValidator: func(string) error { return assert.AnError },
	})

	endpoints := []classify.ClassifiedRequest{
		{APIType: "grpc"},
	}
	endpoints[0].URL = "http://10.0.0.1:50051/x/Y"

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	result, err := probe.Probe(ctx, endpoints)
	require.NoError(t, err)
	require.Len(t, result, 1)
	assert.Nil(t, result[0].GRPCSchema, "blocked target should not produce a schema")
}

// TestGRPCProbe_Probe_DedupsByTarget verifies that multiple endpoints sharing
// the same host:port produce a single reflection call and that all matching
// endpoints receive the SAME *classify.GRPCReflectionResult pointer (pointer
// identity proves reflection ran once per target and the result was fanned out).
func TestGRPCProbe_Probe_DedupsByTarget(t *testing.T) {
	addr, stop := startTestGRPCServer(t)
	defer stop()

	cfg := Config{
		Timeout:      5 * time.Second,
		URLValidator: func(string) error { return nil },
		Dialer:       loopbackDialer,
	}
	probe := NewGRPCProbe(cfg)

	// Two endpoints on the same host:port but different URL paths.
	endpoints := []classify.ClassifiedRequest{
		{APIType: "grpc"},
		{APIType: "grpc"},
	}
	endpoints[0].URL = "http://" + addr + "/lab.v1.UserService/GetUser"
	endpoints[1].URL = "http://" + addr + "/lab.v1.OrderService/GetOrder"

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := probe.Probe(ctx, endpoints)
	require.NoError(t, err)
	require.Len(t, result, 2)

	schema0 := result[0].GRPCSchema
	schema1 := result[1].GRPCSchema

	require.NotNil(t, schema0, "first endpoint must have a GRPCSchema")
	require.NotNil(t, schema1, "second endpoint must have a GRPCSchema")
	assert.True(t, schema0.ReflectionEnabled, "reflection must be enabled")
	assert.True(t, schema1.ReflectionEnabled, "reflection must be enabled")

	// Pointer identity: both endpoints share the exact same result object,
	// proving reflection ran once and the result was fanned out to all
	// endpoints matching that target.
	assert.Same(t, schema0, schema1, "both endpoints must share the same *GRPCReflectionResult pointer (reflection ran once)")
}

// TestGRPCProbe_Probe_TLSVerifiedByDefault verifies that a gRPC server
// presenting a self-signed certificate is NOT enumerated when
// GRPCInsecureSkipVerify is left at its default (false). The TLS handshake
// fails certificate verification and the endpoint's GRPCSchema remains nil.
// This is the secure-by-default complement to TestGRPCProbe_Probe_SelfSignedTLS.
func TestGRPCProbe_Probe_TLSVerifiedByDefault(t *testing.T) {
	addr, stop := startTestGRPCServerTLS(t)
	defer stop()

	// No GRPCInsecureSkipVerify set — defaults to false (verify certificate).
	cfg := Config{
		Timeout:      5 * time.Second,
		URLValidator: func(string) error { return nil },
		Dialer:       loopbackDialer,
	}
	probe := NewGRPCProbe(cfg)

	endpoints := []classify.ClassifiedRequest{
		{APIType: "grpc"},
	}
	endpoints[0].URL = "https://" + addr + "/grpc.health.v1.Health/Check"

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := probe.Probe(ctx, endpoints)
	require.NoError(t, err)
	require.Len(t, result, 1)

	// Self-signed cert fails verification: schema must be nil, documenting
	// that the server was not enumerated.
	assert.Nil(t, result[0].GRPCSchema, "self-signed cert must block enumeration when GRPCInsecureSkipVerify is false")
}

func TestGRPCTarget(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		wantHost string
		wantTLS  bool
		wantErr  bool
	}{
		{
			name:     "http default port",
			url:      "http://example.com/svc/Method",
			wantHost: "example.com:80",
			wantTLS:  false,
		},
		{
			name:     "https default port",
			url:      "https://example.com/svc/Method",
			wantHost: "example.com:443",
			wantTLS:  true,
		},
		{
			name:     "explicit port",
			url:      "http://example.com:50051/svc/Method",
			wantHost: "example.com:50051",
			wantTLS:  false,
		},
		{
			name:     "grpc scheme cleartext",
			url:      "grpc://example.com/svc/Method",
			wantHost: "example.com:80",
			wantTLS:  false,
		},
		{
			name:     "grpcs scheme TLS",
			url:      "grpcs://example.com/svc/Method",
			wantHost: "example.com:443",
			wantTLS:  true,
		},
		{
			name:    "no host",
			url:     "http:///path",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := grpcTarget(tt.url)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantHost, info.hostPort)
			assert.Equal(t, tt.wantTLS, info.useTLS)
		})
	}
}
