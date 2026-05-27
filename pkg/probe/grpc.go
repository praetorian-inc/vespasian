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
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/url"

	"github.com/jhump/protoreflect/desc" //nolint:staticcheck // SA1019: protoreflect/desc is the only API protoprint and grpcreflect.Client expose
	"github.com/jhump/protoreflect/grpcreflect"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/praetorian-inc/vespasian/pkg/classify"
)

// maxGRPCFileDescriptors caps the number of FileDescriptorProtos fetched per
// target. Defensive guard against pathological servers with cyclic or deeply
// nested import graphs.
const maxGRPCFileDescriptors = 1000

// reflectionServices are the gRPC reflection service names themselves; filtered
// out of the discovered service list since they describe the reflection API,
// not the user-facing services we want to enumerate.
var reflectionServices = map[string]bool{
	"grpc.reflection.v1alpha.ServerReflection": true,
	"grpc.reflection.v1.ServerReflection":      true,
}

// GRPCProbe enumerates gRPC services via the Server Reflection Protocol.
// Uses grpcreflect.NewClientAuto, which tries v1 first then falls back to
// v1alpha on Unimplemented.
type GRPCProbe struct {
	config Config
}

// NewGRPCProbe creates a GRPCProbe with the given configuration.
func NewGRPCProbe(cfg Config) *GRPCProbe {
	return &GRPCProbe{config: cfg.withDefaults()}
}

// Name returns the probe name.
func (p *GRPCProbe) Name() string {
	return "grpc-reflection"
}

// Probe enumerates gRPC services and methods via server reflection. Only
// endpoints with APIType=="grpc" are probed. Endpoints sharing a host:port
// are deduplicated — reflection is called once per server, and the resulting
// schema is applied to every endpoint matching that target.
func (p *GRPCProbe) Probe(ctx context.Context, endpoints []classify.ClassifiedRequest) ([]classify.ClassifiedRequest, error) {
	schemasByTarget := make(map[string]*classify.GRPCReflectionResult)
	seen := make(map[string]bool)

	for _, ep := range endpoints {
		if ep.APIType != "grpc" {
			continue
		}
		target, err := grpcTarget(ep.URL)
		if err != nil {
			slog.DebugContext(ctx, "grpc probe: target derivation failed", "url", ep.URL, "error", err)
			continue
		}
		if seen[target.hostPort] {
			continue
		}
		if len(seen) >= p.config.MaxEndpoints {
			break
		}
		seen[target.hostPort] = true

		schemasByTarget[target.hostPort] = p.probeTarget(ctx, target)
	}

	// Copy endpoints to avoid mutating the caller's slice.
	result := make([]classify.ClassifiedRequest, len(endpoints))
	copy(result, endpoints)

	for i := range result {
		if result[i].APIType != "grpc" {
			continue
		}
		target, err := grpcTarget(result[i].URL)
		if err != nil {
			continue
		}
		if schema, ok := schemasByTarget[target.hostPort]; ok && schema != nil {
			result[i].GRPCSchema = schema
		}
	}

	return result, nil
}

// grpcTargetInfo holds the host:port and TLS choice derived from a URL.
type grpcTargetInfo struct {
	hostPort string
	useTLS   bool
}

// grpcTarget derives the dial target from a URL. https/grpcs use TLS;
// http/grpc use cleartext. Default ports follow scheme convention.
func grpcTarget(rawURL string) (grpcTargetInfo, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return grpcTargetInfo{}, fmt.Errorf("parse URL: %w", err)
	}
	host := u.Hostname()
	if host == "" {
		return grpcTargetInfo{}, fmt.Errorf("empty host in URL %q", rawURL)
	}
	port := u.Port()
	var useTLS bool
	switch u.Scheme {
	case "https", "grpcs":
		useTLS = true
		if port == "" {
			port = "443"
		}
	default:
		if port == "" {
			port = "80"
		}
	}
	return grpcTargetInfo{hostPort: net.JoinHostPort(host, port), useTLS: useTLS}, nil
}

// reflectionUnavailableReason maps a gRPC error code to a structured
// "reflection unavailable" reason when the code carries useful information.
// Returns the reason name and true on a recognized code; empty + false
// otherwise. Used by probeTarget to distinguish actionable failures
// (reflection-off, auth-gated) from ambiguous network errors.
func reflectionUnavailableReason(err error) (string, bool) {
	switch status.Code(err) {
	case codes.Unimplemented:
		return "Unimplemented", true
	case codes.Unauthenticated:
		return "Unauthenticated", true
	case codes.PermissionDenied:
		return "PermissionDenied", true
	default:
		return "", false
	}
}

// probeTarget executes reflection against a single host:port. The return
// distinguishes three outcomes:
//
//   - nil: the target could not be probed at all (URL validator blocked it,
//     grpc.NewClient setup failed, or the network error gave no signal that
//     the target is actually a gRPC server).
//   - &GRPCReflectionResult{ReflectionEnabled: false, ReflectionUnavailableReason: ...}:
//     the server responded with a structured gRPC error that the reflection
//     service is unavailable. Recognized reasons: Unimplemented (not
//     registered), Unauthenticated and PermissionDenied (auth-gated).
//   - &GRPCReflectionResult{ReflectionEnabled: true, ...}: reflection
//     succeeded. Services may still be empty if the server only exposes the
//     reflection service itself.
func (p *GRPCProbe) probeTarget(ctx context.Context, t grpcTargetInfo) *classify.GRPCReflectionResult {
	// SSRF preflight using a synthesized http URL so the existing validator's
	// DNS lookup + private-IP blocklist applies to gRPC targets too.
	if err := p.config.URLValidator("http://" + t.hostPort); err != nil {
		slog.DebugContext(ctx, "grpc probe: URL validation failed", "target", t.hostPort, "error", err)
		return nil
	}

	var creds credentials.TransportCredentials
	if t.useTLS {
		creds = credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})
	} else {
		creds = insecure.NewCredentials()
	}

	// The configured Dialer re-resolves and re-checks IPs at connect time
	// (default: ssrfSafeDialContext), closing the TOCTOU window between the
	// URLValidator pre-flight and the actual TCP handshake.
	dialer := func(ctx context.Context, addr string) (net.Conn, error) {
		return p.config.Dialer(ctx, "tcp", addr)
	}

	reqCtx, cancel := context.WithTimeout(ctx, p.config.Timeout)
	defer cancel()

	conn, err := grpc.NewClient(t.hostPort,
		grpc.WithTransportCredentials(creds),
		grpc.WithContextDialer(dialer),
	)
	if err != nil {
		slog.DebugContext(ctx, "grpc probe: dial setup failed", "target", t.hostPort, "error", err)
		return nil
	}
	defer conn.Close() //nolint:errcheck // best-effort close

	client := grpcreflect.NewClientAuto(reqCtx, conn)
	defer client.Reset()

	services, err := client.ListServices()
	if err != nil {
		slog.DebugContext(ctx, "grpc probe: list services failed", "target", t.hostPort, "error", err)
		if reason, ok := reflectionUnavailableReason(err); ok {
			// Server responded with a structured gRPC error that tells us
			// why reflection isn't usable (not registered, auth-gated, etc).
			// Surface as a structured "reflection unavailable" finding.
			return &classify.GRPCReflectionResult{
				ReflectionEnabled:           false,
				ReflectionUnavailableReason: reason,
			}
		}
		return nil
	}

	result := &classify.GRPCReflectionResult{
		ReflectionEnabled: true,
		FileDescriptors:   map[string][]byte{},
	}
	fetched := map[string]bool{}

	for _, svcName := range services {
		if reflectionServices[svcName] {
			continue
		}
		fd, err := client.FileContainingSymbol(svcName)
		if err != nil {
			slog.DebugContext(ctx, "grpc probe: FileContainingSymbol failed", "service", svcName, "error", err)
			continue
		}
		walkFileDescriptors(fd, fetched, result.FileDescriptors)

		if gs, ok := extractService(fd, svcName); ok {
			result.Services = append(result.Services, gs)
		}
	}

	return result
}

// walkFileDescriptors recursively serializes fd and its transitive
// dependencies into the output map, keyed by .proto filename. Bounded by
// maxGRPCFileDescriptors.
func walkFileDescriptors(fd *desc.FileDescriptor, fetched map[string]bool, out map[string][]byte) {
	if fd == nil || len(fetched) >= maxGRPCFileDescriptors {
		return
	}
	name := fd.GetName()
	if fetched[name] {
		return
	}
	fetched[name] = true

	if raw, err := proto.Marshal(fd.AsFileDescriptorProto()); err == nil {
		out[name] = raw
	}

	for _, dep := range fd.GetDependencies() {
		walkFileDescriptors(dep, fetched, out)
	}
}

// extractService finds the named service in fd and returns its method
// signatures. Returns (zero, false) when the service is not declared in fd.
func extractService(fd *desc.FileDescriptor, fqn string) (classify.GRPCService, bool) {
	for _, svc := range fd.GetServices() {
		if svc.GetFullyQualifiedName() != fqn {
			continue
		}
		gs := classify.GRPCService{Name: fqn}
		for _, m := range svc.GetMethods() {
			gs.Methods = append(gs.Methods, classify.GRPCMethod{
				Name:            m.GetName(),
				InputType:       m.GetInputType().GetFullyQualifiedName(),
				OutputType:      m.GetOutputType().GetFullyQualifiedName(),
				ClientStreaming: m.IsClientStreaming(),
				ServerStreaming: m.IsServerStreaming(),
			})
		}
		return gs, true
	}
	return classify.GRPCService{}, false
}
