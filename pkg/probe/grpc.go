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

// maxReflectionRecvBytes caps a single reflection response message. Set
// explicitly (rather than relying on gRPC's 4 MiB default) so per-message
// memory from a hostile target is intentional and visible.
const maxReflectionRecvBytes = 4 << 20 // 4 MiB

// maxGRPCDescriptorBytes caps the aggregate serialized descriptor bytes
// retained per target, bounding total memory even when many files stay
// under the file-count cap. Guards against reflection memory-amplification.
const maxGRPCDescriptorBytes = 64 << 20 // 64 MiB

// reflectionServices are the gRPC reflection service names themselves; filtered
// out of the discovered service list since they describe the reflection API,
// not the user-facing services we want to enumerate.
var reflectionServices = map[string]bool{
	"grpc.reflection.v1alpha.ServerReflection": true,
	"grpc.reflection.v1.ServerReflection":      true,
}

// GRPCProbe enumerates gRPC services via the Server Reflection Protocol.
// Uses grpcreflect.NewClientAuto, which negotiates the reflection API
// version with the server (v1, with a library-internal fallback to the
// legacy v1alpha service). The fallback path is handled entirely inside
// grpcreflect and is not separately exercised by vespasian's tests.
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
	// Key by the full grpcTargetInfo (hostPort + useTLS), not hostPort alone:
	// http://h:443 and https://h:443 share a host:port but must not share a
	// reflection probe result.
	schemasByTarget := make(map[grpcTargetInfo]*classify.GRPCReflectionResult)
	seen := make(map[grpcTargetInfo]bool)

	for _, ep := range endpoints {
		if ep.APIType != "grpc" {
			continue
		}
		target, err := grpcTarget(ep.URL)
		if err != nil {
			slog.DebugContext(ctx, "grpc probe: target derivation failed", "url", ep.URL, "error", err)
			continue
		}
		if seen[target] {
			continue
		}
		if len(seen) >= p.config.MaxEndpoints {
			break
		}
		seen[target] = true

		schemasByTarget[target] = p.probeTarget(ctx, target)
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
		if schema, ok := schemasByTarget[target]; ok && schema != nil {
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
	explicitPort := port != ""
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
	if !explicitPort {
		slog.Debug("grpc target: no explicit port, assuming default", "scheme", u.Scheme, "port", port, "url", rawURL) // #nosec G706 -- debug diagnostic of capture-derived URL; not a security-sensitive sink
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

	reqCtx, cancel := context.WithTimeout(ctx, p.config.Timeout)
	defer cancel()

	conn, err := p.dialGRPC(t)
	if err != nil {
		slog.DebugContext(ctx, "grpc probe: dial setup failed", "target", t.hostPort, "error", err)
		return nil
	}
	defer conn.Close() //nolint:errcheck // best-effort close

	client := grpcreflect.NewClientAuto(reqCtx, conn)
	defer client.Reset()

	return runReflection(ctx, client, t)
}

// dialGRPC builds transport credentials (TLS honoring the configured
// GRPCInsecureSkipVerify, or cleartext) wrapped with the SSRF-safe Dialer, and
// returns a grpc.NewClient connection for the target.
func (p *GRPCProbe) dialGRPC(t grpcTargetInfo) (*grpc.ClientConn, error) {
	var creds credentials.TransportCredentials
	if t.useTLS {
		creds = credentials.NewTLS(&tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: p.config.GRPCInsecureSkipVerify, // #nosec G402 -- opt-in only (default verifies); SSRF is enforced by the Dialer
		})
	} else {
		creds = insecure.NewCredentials()
	}

	// The configured Dialer re-resolves and re-checks IPs at connect time
	// (default: ssrfSafeDialContext), closing the TOCTOU window between the
	// URLValidator pre-flight and the actual TCP handshake.
	dialer := func(ctx context.Context, addr string) (net.Conn, error) {
		return p.config.Dialer(ctx, "tcp", addr)
	}

	return grpc.NewClient(t.hostPort,
		grpc.WithTransportCredentials(creds),
		grpc.WithContextDialer(dialer),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxReflectionRecvBytes)),
	)
}

// runReflection lists the target's services and walks each one's file
// descriptors. It preserves probeTarget's three-outcome contract: nil (no gRPC
// signal), ReflectionEnabled=false with a reason (structured unavailable), or
// ReflectionEnabled=true with the discovered services and descriptors.
func runReflection(ctx context.Context, client *grpcreflect.Client, t grpcTargetInfo) *classify.GRPCReflectionResult {
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
	totalBytes := 0

	for _, svcName := range services {
		if reflectionServices[svcName] {
			continue
		}
		fd, err := client.FileContainingSymbol(svcName)
		if err != nil {
			slog.DebugContext(ctx, "grpc probe: FileContainingSymbol failed", "service", svcName, "error", err)
			continue
		}
		walkFileDescriptors(fd, fetched, result.FileDescriptors, &totalBytes)

		if gs, ok := extractService(fd, svcName); ok {
			result.Services = append(result.Services, gs)
		}
	}

	return result
}

// walkFileDescriptors recursively serializes fd and its transitive
// dependencies into out, keyed by .proto filename. Bounded by both
// maxGRPCFileDescriptors (count) and maxGRPCDescriptorBytes (aggregate
// serialized bytes) to cap memory from hostile reflection responses.
func walkFileDescriptors(fd *desc.FileDescriptor, fetched map[string]bool, out map[string][]byte, totalBytes *int) {
	if fd == nil || len(fetched) >= maxGRPCFileDescriptors || *totalBytes >= maxGRPCDescriptorBytes {
		return
	}
	name := fd.GetName()
	if fetched[name] {
		return
	}
	fetched[name] = true

	// QUAL-002: a marshal failure intentionally omits this one descriptor
	// (non-fatal — buildDescriptorGraph degrades downstream); log so the
	// root cause isn't invisible.
	if raw, err := proto.Marshal(fd.AsFileDescriptorProto()); err != nil {
		slog.Debug("grpc probe: marshal file descriptor failed; omitting", "file", name, "error", err)
	} else {
		out[name] = raw
		*totalBytes += len(raw)
	}

	for _, dep := range fd.GetDependencies() {
		walkFileDescriptors(dep, fetched, out, totalBytes)
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
