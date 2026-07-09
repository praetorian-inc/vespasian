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
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/praetorian-inc/vespasian/pkg/classify"
)

// maxOpenAPIBodySize limits the response body read for grpc-gateway OpenAPI
// documents, mirroring the GraphQL probe's introspection cap.
const maxOpenAPIBodySize = 5 << 20 // 5 MB

// grpcGatewayOpenAPIPaths are the well-known OpenAPI/swagger document locations
// tried per host, in order; the first valid grpc-gateway document wins.
//
// protoc-gen-openapiv2 commonly writes per-service files under
// /openapiv2/<path>.swagger.json. A glob is not directly fetchable and we do
// not attempt directory listing — only a common literal fallback is tried.
var grpcGatewayOpenAPIPaths = []string{
	"/swagger.json",
	"/swagger/v1/swagger.json",
	"/openapi.json",
	"/api/swagger.json",
	"/openapiv2/service.swagger.json",
}

// serviceFQNPattern matches a protobuf service FQN shape, e.g.
// "users.v1.UserService" or "UserService".
var serviceFQNPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)*Service$`)

// versionSegmentPattern matches a ".vN." version segment in a dotted name.
var versionSegmentPattern = regexp.MustCompile(`\.v[0-9]+\.`)

// operationIDPattern matches a grpc-gateway operationId of the form
// "<Service>_<Method>".
var operationIDPattern = regexp.MustCompile(`^([A-Za-z0-9_.]+)_([A-Za-z0-9]+)$`)

// GRPCGatewayProbe recovers gRPC service/method names from a grpc-gateway or
// Envoy OpenAPI document exposed alongside the HTTP/JSON transcoding gateway.
// It records recovered service names on matching gRPC endpoints; descriptor
// synthesis is centralized in the generator.
type GRPCGatewayProbe struct {
	config Config
}

// NewGRPCGatewayProbe creates a GRPCGatewayProbe with the given configuration.
func NewGRPCGatewayProbe(cfg Config) *GRPCGatewayProbe {
	return &GRPCGatewayProbe{config: cfg.withDefaults()}
}

// Name returns the probe name.
func (p *GRPCGatewayProbe) Name() string { return "grpc-gateway" }

// Probe attempts well-known OpenAPI paths for each unique grpc endpoint host
// and, on finding a grpc-gateway swagger document, records the recovered
// service names on the matching endpoints' GRPCSchema.Services (with
// ReflectionEnabled=false). Only endpoints with APIType=="grpc" are probed.
// Deduplicated by host (one swagger fetch sequence per host). Failures are
// non-fatal: returns (endpoints, nil) even when nothing is found, so
// RunStrategies isolation is preserved.
func (p *GRPCGatewayProbe) Probe(ctx context.Context, endpoints []classify.ClassifiedRequest) ([]classify.ClassifiedRequest, error) {
	// Map probed host base URL → recovered services (nil when nothing found).
	servicesByHost := make(map[string][]classify.GRPCService)
	seen := make(map[string]bool)

	for _, ep := range endpoints {
		if ep.APIType != "grpc" {
			continue
		}
		base := openAPIBaseURL(ep.URL)
		if base == "" {
			continue
		}
		if seen[base] {
			continue
		}
		if len(seen) >= p.config.MaxEndpoints {
			break
		}
		seen[base] = true

		servicesByHost[base] = p.probeHost(ctx, base)
	}

	// Copy endpoints to avoid mutating the caller's slice.
	result := make([]classify.ClassifiedRequest, len(endpoints))
	copy(result, endpoints)

	for i := range result {
		if result[i].APIType != "grpc" {
			continue
		}
		// Precedence: never overwrite a reflection result that already carries
		// real FileDescriptors (reflection wins — it has true message fields).
		// Keyed on descriptor presence, not ReflectionEnabled, since name-only
		// techniques set ReflectionEnabled=false but never carry descriptors.
		if existing := result[i].GRPCSchema; existing != nil && len(existing.FileDescriptors) > 0 {
			continue
		}
		base := openAPIBaseURL(result[i].URL)
		svcs := servicesByHost[base]
		if len(svcs) == 0 {
			continue
		}
		// Store recovered service names only. Descriptor synthesis is
		// centralized in the generator (generate/grpc.Generate), which unions
		// services across techniques and synthesizes once. ReflectionEnabled is
		// false: the gateway document is not a reflection response.
		result[i].GRPCSchema = &classify.GRPCReflectionResult{
			ReflectionEnabled: false,
			Services:          svcs,
		}
	}

	return result, nil
}

// probeHost tries each well-known OpenAPI path against base and returns the
// services recovered from the first recognized grpc-gateway document. Returns
// nil when no document is found or none is a grpc-gateway document.
func (p *GRPCGatewayProbe) probeHost(ctx context.Context, base string) []classify.GRPCService {
	if err := p.config.URLValidator(base); err != nil {
		slog.DebugContext(ctx, "grpc-gateway probe: URL validation failed", "url", base, "error", err)
		return nil
	}

	for _, path := range grpcGatewayOpenAPIPaths {
		body := p.fetch(ctx, base+path)
		if body == nil {
			continue
		}
		svcs := servicesFromOpenAPI(body)
		if len(svcs) > 0 {
			slog.DebugContext(ctx, "grpc-gateway probe: recovered services", "url", base+path, "services", len(svcs))
			return svcs
		}
	}
	return nil
}

// fetch issues a single bounded GET and returns the response body, or nil on
// any failure (validation, transport, non-success status).
func (p *GRPCGatewayProbe) fetch(ctx context.Context, targetURL string) []byte {
	if err := p.config.URLValidator(targetURL); err != nil {
		slog.DebugContext(ctx, "grpc-gateway probe: URL validation failed", "url", targetURL, "error", err)
		return nil
	}

	reqCtx, cancel := context.WithTimeout(ctx, p.config.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil
	}
	for k, v := range p.config.AuthHeaders {
		req.Header.Set(k, v)
	}

	resp, err := p.config.Client.Do(req) //nolint:gosec // G704: intentional outbound probe with SSRF protection
	if err != nil {
		slog.DebugContext(ctx, "grpc-gateway probe: request failed", "url", targetURL, "error", err)
		return nil
	}
	defer func() {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)) //nolint:errcheck,gosec // best-effort drain
		resp.Body.Close()                                    //nolint:errcheck,gosec // best-effort close
	}()

	if resp.StatusCode >= 400 {
		slog.DebugContext(ctx, "grpc-gateway probe: non-success status", "url", targetURL, "status", resp.StatusCode)
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxOpenAPIBodySize))
	if err != nil {
		return nil
	}
	return body
}

// openAPIDoc captures the swagger/OpenAPI fields needed to recognize a
// grpc-gateway document and recover service/method names. It is parsed as
// plain JSON (no protobuf google.api.http annotation decoding).
type openAPIDoc struct {
	Info struct {
		Title string `json:"title"`
	} `json:"info"`
	Tags []struct {
		Name string `json:"name"`
	} `json:"tags"`
	Paths map[string]map[string]struct {
		OperationID string   `json:"operationId"`
		Tags        []string `json:"tags"`
	} `json:"paths"`
}

// servicesFromOpenAPI parses an OpenAPI/swagger document and, when it is
// recognized as a grpc-gateway document, returns the recovered services. A
// non-grpc-gateway (plain REST) document yields nil (no false positive).
func servicesFromOpenAPI(body []byte) []classify.GRPCService {
	var doc openAPIDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil
	}
	if !isGRPCGatewayDoc(&doc) {
		return nil
	}

	// Accumulate methods per service FQN.
	byService := map[string]map[string]bool{}
	addMethod := func(svc, method string) {
		if svc == "" || method == "" {
			return
		}
		methods, ok := byService[svc]
		if !ok {
			methods = map[string]bool{}
			byService[svc] = methods
		}
		methods[method] = true
	}

	for _, ops := range doc.Paths {
		for _, op := range ops {
			// Extract only operations that satisfy the same strict predicate the
			// doc-recognition gate uses (both segments Upper-initial). A
			// recognized doc can still carry lowercase/camel operationIds (e.g.
			// list_users) that must not be turned into a junk service/method.
			// Evaluate operationIDPattern once and reuse the captures.
			m := operationIDPattern.FindStringSubmatch(op.OperationID)
			if m == nil || !isUpperInitial(m[1]) || !isUpperInitial(m[2]) {
				continue
			}
			method := m[2]
			svc := serviceFromOperation(op.Tags, doc.Info.Title, m[1])
			addMethod(svc, method)
		}
	}

	return buildGatewayServices(byService)
}

// serviceFromOperation resolves the service FQN for an operation: the first
// tag matching the FQN shape, else info.title if it matches, else the
// operationId prefix.
func serviceFromOperation(tags []string, title, opIDPrefix string) string {
	for _, t := range tags {
		if looksLikeServiceFQN(t) {
			return t
		}
	}
	if looksLikeServiceFQN(title) {
		return title
	}
	return opIDPrefix
}

// buildGatewayServices flattens the per-service method set into a sorted slice
// of GRPCService. Streaming is not recoverable from OpenAPI (HTTP/JSON
// transcoding flattens it) so all methods are unary. Input/output type names
// are not reliably recoverable so placeholders are used.
func buildGatewayServices(byService map[string]map[string]bool) []classify.GRPCService {
	if len(byService) == 0 {
		return nil
	}
	names := make([]string, 0, len(byService))
	for name := range byService {
		names = append(names, name)
	}
	sort.Strings(names)

	services := make([]classify.GRPCService, 0, len(names))
	for _, name := range names {
		methodSet := byService[name]
		methodNames := make([]string, 0, len(methodSet))
		for mn := range methodSet {
			methodNames = append(methodNames, mn)
		}
		sort.Strings(methodNames)

		svc := classify.GRPCService{Name: name}
		for _, mn := range methodNames {
			svc.Methods = append(svc.Methods, classify.GRPCMethod{
				Name:       mn,
				InputType:  mn + "Request",
				OutputType: mn + "Response",
			})
		}
		services = append(services, svc)
	}
	return services
}

// isGRPCGatewayDoc reports whether the parsed document looks like a
// grpc-gateway/protoc-gen-openapiv2 document rather than a hand-written or
// generic REST swagger document.
func isGRPCGatewayDoc(doc *openAPIDoc) bool {
	// Strong signal: an FQN-shaped service title or tag.
	if looksLikeServiceFQN(doc.Info.Title) {
		return true
	}
	for _, t := range doc.Tags {
		if looksLikeServiceFQN(t.Name) {
			return true
		}
	}
	// Primary signal: any operationId with the grpc-gateway <Service>_<Method>
	// shape (both Upper-initial). This distinguishes Greeter_SayHello (accept)
	// from plain REST swagger such as listUsers or user_list (reject), without
	// requiring an accompanying FQN-shaped tag.
	for _, ops := range doc.Paths {
		for _, op := range ops {
			if looksLikeServiceMethodOpID(op.OperationID) {
				return true
			}
		}
	}
	return false
}

// looksLikeServiceMethodOpID reports whether opID has the grpc-gateway
// <Service>_<Method> shape where both Service and Method are Upper-initial.
// This rejects camelCase REST operationIds (listUsers) and lowercase-method
// forms (user_list, orders_v1_create).
func looksLikeServiceMethodOpID(opID string) bool {
	m := operationIDPattern.FindStringSubmatch(opID)
	if m == nil {
		return false
	}
	return isUpperInitial(m[1]) && isUpperInitial(m[2])
}

// isUpperInitial reports whether s begins with an ASCII uppercase letter.
func isUpperInitial(s string) bool {
	return s != "" && s[0] >= 'A' && s[0] <= 'Z'
}

// looksLikeServiceFQN reports whether s has a protobuf service FQN shape: it
// matches the *Service suffix pattern, or carries a ".vN." version segment
// (a strong grpc-gateway signal even without the Service suffix). The version
// branch additionally requires s to be a valid dotted proto identifier so a
// matching string can never carry control chars, newlines, or braces that
// would later be treated as a service name.
func looksLikeServiceFQN(s string) bool {
	if s == "" {
		return false
	}
	if serviceFQNPattern.MatchString(s) {
		return true
	}
	return versionSegmentPattern.MatchString(s) && isDottedProtoIdent(s)
}

// protoIdentSegmentPattern matches a single proto identifier segment.
var protoIdentSegmentPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// isDottedProtoIdent reports whether s is a dotted proto identifier: every
// '.'-separated segment matches [A-Za-z_][A-Za-z0-9_]*. Empty is invalid. This
// rejects strings carrying control chars, newlines, braces, or other injected
// content that would be unsafe to treat as a service name.
func isDottedProtoIdent(s string) bool {
	if s == "" {
		return false
	}
	for _, seg := range strings.Split(s, ".") {
		if !protoIdentSegmentPattern.MatchString(seg) {
			return false
		}
	}
	return true
}

// openAPIBaseURL derives the scheme://host[:port] base used to fetch OpenAPI
// documents from a gRPC endpoint URL. grpc/grpcs schemes are mapped to
// http/https since the gateway exposes HTTP. Returns "" on parse failure or
// when no host is present.
func openAPIBaseURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return ""
	}
	switch u.Scheme {
	case "grpc", "http":
		u.Scheme = "http"
	case "grpcs", "https":
		u.Scheme = "https"
	default:
		u.Scheme = "https"
	}
	return u.Scheme + "://" + u.Host
}
