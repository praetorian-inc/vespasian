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

// package pipeline (not pipeline_test): these tests exercise
// seedGRPCHostEndpoints, enrichGRPCFromBindings, filterUncoveredServices, and
// grpcHostKey directly, all unexported. They moved here from
// cmd/vespasian/main_test.go when the gRPC enrichment/seeding logic they cover
// was relocated from cmd/vespasian/main.go into internal/pipeline/grpc_enrich.go.
package pipeline

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/praetorian-inc/vespasian/pkg/classify"
	"github.com/praetorian-inc/vespasian/pkg/crawl"
	"github.com/praetorian-inc/vespasian/pkg/generate"
)

// ---------------------------------------------------------------------------
// T3 — enrichGRPCFromBindings: driven with a real gRPC-Web JS bundle so
// ExtractGRPCWebBindings actually recovers a non-empty service set (the
// previous versions of these tests passed an empty []crawl.ObservedRequest{},
// so ExtractGRPCWebBindings returned nothing and enrichGRPCFromBindings
// returned early before exercising the append/fill/drop logic at all).
// ---------------------------------------------------------------------------

// grpcClassifiedRequest is a helper to build a gRPC ClassifiedRequest with
// optional schema.
func grpcClassifiedRequest(schema *classify.GRPCReflectionResult) classify.ClassifiedRequest {
	return classify.ClassifiedRequest{
		ObservedRequest: crawl.ObservedRequest{Method: "POST", URL: "https://example.com/grpc"},
		APIType:         APITypeGRPC,
		GRPCSchema:      schema,
	}
}

// grpcWebJSRequest builds an ObservedRequest whose response body is the real
// Connect-ES gRPC-Web JS bundle fixture shared with pkg/analyze's own tests
// (pkg/analyze/testdata/grpc_web/users_connect.js, service
// "users.v1.UserService"). Reusing the real fixture — rather than a
// hand-rolled snippet — exercises the same jsluice detection path
// ExtractGRPCWebBindings uses in production.
func grpcWebJSRequest(t *testing.T) crawl.ObservedRequest {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("..", "..", "pkg", "analyze", "testdata", "grpc_web", "users_connect.js"))
	if err != nil {
		t.Fatalf("read users_connect.js fixture: %v", err)
	}
	return crawl.ObservedRequest{
		Method: "GET",
		URL:    "https://example.com/users_connect.js",
		Response: crawl.ObservedResponse{
			ContentType: "application/javascript",
			Body:        body,
		},
	}
}

// grpcServiceNames extracts the service names carried by a
// GRPCReflectionResult, in schema.Services order, or nil when schema is nil.
func grpcServiceNames(schema *classify.GRPCReflectionResult) []string {
	if schema == nil {
		return nil
	}
	names := make([]string, 0, len(schema.Services))
	for _, s := range schema.Services {
		names = append(names, s.Name)
	}
	return names
}

// TestEnrichGRPCFromBindings_AppendsSyntheticEndpointWhenNoGRPCEndpoints
// (T3 Case B, real bindings): enriched has zero grpc endpoints; the real
// users_connect.js bundle recovers users.v1.UserService, so exactly one
// synthetic grpc endpoint must be appended carrying that service.
func TestEnrichGRPCFromBindings_AppendsSyntheticEndpointWhenNoGRPCEndpoints(t *testing.T) {
	requests := []crawl.ObservedRequest{grpcWebJSRequest(t)}
	enriched := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{Method: "GET", URL: "https://example.com/api"},
			APIType:         "rest",
		},
	}

	result := enrichGRPCFromBindings(requests, enriched, io.Discard)

	var grpcEPs []classify.ClassifiedRequest
	for _, ep := range result {
		if ep.APIType == APITypeGRPC {
			grpcEPs = append(grpcEPs, ep)
		}
	}
	if len(grpcEPs) != 1 {
		t.Fatalf("enrichGRPCFromBindings: got %d synthetic grpc endpoints, want exactly 1", len(grpcEPs))
	}
	names := grpcServiceNames(grpcEPs[0].GRPCSchema)
	if len(names) == 0 || names[0] != "users.v1.UserService" {
		t.Errorf("enrichGRPCFromBindings: synthetic endpoint services = %v, want [users.v1.UserService]", names)
	}
}

// TestEnrichGRPCFromBindings_FillsBareEndpointInPlace (T3 Case C): a bare grpc
// endpoint (nil GRPCSchema) is present alongside the real users_connect.js
// bundle. The uncovered recovered service must be filled onto the existing
// endpoint, and no endpoint must be appended.
func TestEnrichGRPCFromBindings_FillsBareEndpointInPlace(t *testing.T) {
	requests := []crawl.ObservedRequest{grpcWebJSRequest(t)}
	enriched := []classify.ClassifiedRequest{grpcClassifiedRequest(nil)}

	result := enrichGRPCFromBindings(requests, enriched, io.Discard)

	if len(result) != 1 {
		t.Fatalf("enrichGRPCFromBindings: got %d endpoints, want 1 (fill in place, no append)", len(result))
	}
	names := grpcServiceNames(result[0].GRPCSchema)
	if len(names) == 0 || names[0] != "users.v1.UserService" {
		t.Errorf("enrichGRPCFromBindings: bare endpoint services after fill = %v, want [users.v1.UserService]", names)
	}
}

// TestEnrichGRPCFromBindings_DropsAlreadyCoveredFQN (T3 Case A, real
// bindings): enriched has one grpc endpoint that already carries the same
// service FQN (users.v1.UserService) recovered by the real bindings bundle,
// via reflection/gateway. This pins the "no re-attachment" outcome: no
// endpoint is appended and the existing GRPCSchema pointer is left untouched
// (not replaced, not duplicated) when a grpc endpoint already covers the
// recovered FQN.
//
// Note: this single-endpoint scenario does not, by itself, isolate WHICH
// guard produces that outcome — filterUncoveredServices dropping the FQN
// (triggering enrichGRPCFromBindings' early "len(filtered) == 0" return) and
// the hasCoverage skip-fill branch in the fill loop would both leave this
// endpoint's schema pointer unchanged, since the endpoint's Services is
// already non-empty either way. See
// TestEnrichGRPCFromBindings_FilterDropsRecoveredFQNLeavesBareEndpointUnfilled
// below for a variant where filtering — not hasCoverage — is the sole reason
// no fill occurs, using a second, bare endpoint that hasCoverage would
// otherwise fill.
func TestEnrichGRPCFromBindings_DropsAlreadyCoveredFQN(t *testing.T) {
	requests := []crawl.ObservedRequest{grpcWebJSRequest(t)}

	existingSchema := &classify.GRPCReflectionResult{
		ReflectionEnabled: true,
		Services: []classify.GRPCService{
			{Name: "users.v1.UserService", Methods: []classify.GRPCMethod{{Name: "GetUser"}}},
		},
	}
	enriched := []classify.ClassifiedRequest{grpcClassifiedRequest(existingSchema)}

	result := enrichGRPCFromBindings(requests, enriched, io.Discard)

	if len(result) != 1 {
		t.Fatalf("enrichGRPCFromBindings: got %d endpoints, want 1 (no append when FQN already covered)", len(result))
	}
	if result[0].GRPCSchema != existingSchema {
		t.Error("enrichGRPCFromBindings: existing schema must be left untouched when its FQN is already covered")
	}
	count := 0
	for _, s := range result[0].GRPCSchema.Services {
		if s.Name == "users.v1.UserService" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("enrichGRPCFromBindings: users.v1.UserService count = %d, want 1 (not re-attached)", count)
	}
}

// TestEnrichGRPCFromBindings_FilterDropsRecoveredFQNLeavesBareEndpointUnfilled
// isolates filterUncoveredServices as the sole reason no fill occurs (TEST-001
// fix): a bare grpc endpoint (nil GRPCSchema, hasCoverage false — the fill
// loop would fill it if it ever ran with a non-empty recovered set) sits
// alongside a second endpoint that already covers the bindings-recovered FQN
// (users.v1.UserService). filterUncoveredServices must remove that FQN as the
// only recovered service, so enrichGRPCFromBindings returns early before the
// fill loop runs at all — leaving the bare endpoint's schema nil and
// appending no endpoint. Unlike TestEnrichGRPCFromBindings_DropsAlreadyCoveredFQN,
// the bare endpoint here has hasCoverage == false, so if filtering did NOT
// drop the FQN, this endpoint would be filled — proving filtering, not
// hasCoverage, is what leaves it untouched.
func TestEnrichGRPCFromBindings_FilterDropsRecoveredFQNLeavesBareEndpointUnfilled(t *testing.T) {
	requests := []crawl.ObservedRequest{grpcWebJSRequest(t)}

	coveredEP := grpcClassifiedRequest(&classify.GRPCReflectionResult{
		ReflectionEnabled: true,
		Services: []classify.GRPCService{
			{Name: "users.v1.UserService", Methods: []classify.GRPCMethod{{Name: "GetUser"}}},
		},
	})
	bareEP := grpcClassifiedRequest(nil)

	result := enrichGRPCFromBindings(requests, []classify.ClassifiedRequest{coveredEP, bareEP}, io.Discard)

	if len(result) != 2 {
		t.Fatalf("enrichGRPCFromBindings: got %d endpoints, want 2 (no append when filtering removes the only recovered service)", len(result))
	}
	if result[1].GRPCSchema != nil {
		t.Errorf("enrichGRPCFromBindings: bare endpoint schema = %+v, want nil (filterUncoveredServices must remove the only recovered FQN before the fill loop runs)", result[1].GRPCSchema)
	}
}

// ---------------------------------------------------------------------------
// LAB-3864 regression — enrichGRPCFromBindings must run even with Probe=false
// ---------------------------------------------------------------------------

// TestClassifyProbeGenerate_GRPCBindingsEnrichmentRunsWithoutProbe pins the
// fix that moved the enrichGRPCFromBindings call in ClassifyProbeGenerate
// outside the `if opts.Probe` block (still gated on
// opts.APIType == APITypeGRPC): gRPC-Web JS binding recovery must run whether
// or not active probing is enabled. The GET request carrying the
// users_connect.js bundle scores 0 on classify.GRPCClassifier (no gRPC
// content-type, trailer, or POST+path-shape signal), so with Probe: false the
// classified set reaching enrichGRPCFromBindings is empty — the only way
// users.v1.UserService reaches the generated .proto is via the bindings
// recovery path. If enrichGRPCFromBindings is moved back inside the
// `if opts.Probe` block, classified stays empty and
// generate/grpc.Generator.Generate returns "no endpoints provided",
// failing this test.
func TestClassifyProbeGenerate_GRPCBindingsEnrichmentRunsWithoutProbe(t *testing.T) {
	requests := []crawl.ObservedRequest{grpcWebJSRequest(t)}

	spec, err := ClassifyProbeGenerate(context.Background(), requests, Options{
		APIType:    APITypeGRPC,
		Confidence: 0.5,
		Probe:      false,
	})
	if err != nil {
		t.Fatalf("ClassifyProbeGenerate(Probe=false) returned an error: %v", err)
	}
	if len(spec) == 0 {
		t.Fatal("ClassifyProbeGenerate(Probe=false) returned an empty .proto")
	}
	if !strings.Contains(string(spec), "UserService") {
		t.Errorf("expected generated .proto to contain UserService (recovered via gRPC-Web bindings despite Probe=false), got:\n%s", spec)
	}
}

// ---------------------------------------------------------------------------
// TEST-001 E2E — pipeline glue: enrichGRPCFromBindings feeding Generate
// ---------------------------------------------------------------------------

// TestEnrichGRPCFromBindings_PipelineGlueNoCollisionWithGateway pins the
// multi-technique collision scenario (LAB-3864 review bug) at the pipeline
// boundary ClassifyProbeGenerate's grpc path drives: a grpc-gateway-derived
// endpoint (greet.v1.Greeter, already covered — as GRPCGatewayProbe would
// leave it) sits alongside a second, still-bare grpc endpoint; a captured
// gRPC-Web JS bundle recovers greet.v1.Farewell — same package, different
// service — via gRPC-Web bindings. enrichGRPCFromBindings must fill only the
// bare endpoint, and feeding the combined result into the exact Generate call
// ClassifyProbeGenerate uses (generate.Get("grpc").Generate) must produce
// neither a "conflicting file descriptors" nor a duplicate-symbol error, and a
// non-empty .proto. The generator-level collision tests in
// pkg/generate/grpc/generator_test.go cover Generate in isolation with
// hand-built ClassifiedRequests; this test additionally exercises the
// enrichGRPCFromBindings glue that produces that input in the real pipeline.
func TestEnrichGRPCFromBindings_PipelineGlueNoCollisionWithGateway(t *testing.T) {
	farewellJS := []byte(`
		export const Farewell = {
		  typeName: "greet.v1.Farewell",
		  methods: {
		    sayBye: {
		      name: "SayBye",
		      I: ByeRequest,
		      O: ByeResponse,
		      kind: MethodKind.Unary,
		    },
		  },
		};
	`)
	requests := []crawl.ObservedRequest{
		{
			Method: "GET",
			URL:    "https://example.com/farewell_connect.js",
			Response: crawl.ObservedResponse{
				ContentType: "application/javascript",
				Body:        farewellJS,
			},
		},
	}

	// Endpoint A: already covered — as the grpc-gateway probe would leave it
	// after recovering greet.v1.Greeter from an OpenAPI document.
	gatewayEP := grpcClassifiedRequest(&classify.GRPCReflectionResult{
		ReflectionEnabled: false,
		Services: []classify.GRPCService{
			{Name: "greet.v1.Greeter", Methods: []classify.GRPCMethod{
				{Name: "SayHello", InputType: "HelloRequest", OutputType: "HelloResponse"},
			}},
		},
	})
	// Endpoint B: a second grpc endpoint with no coverage yet — e.g. a host
	// the gateway probe found no OpenAPI document for.
	bareEP := grpcClassifiedRequest(nil)

	enriched := enrichGRPCFromBindings(requests, []classify.ClassifiedRequest{gatewayEP, bareEP}, io.Discard)

	if len(enriched) != 2 {
		t.Fatalf("enrichGRPCFromBindings: got %d endpoints, want 2 (fill bare endpoint in place, no append)", len(enriched))
	}
	if names := grpcServiceNames(enriched[1].GRPCSchema); len(names) == 0 || names[0] != "greet.v1.Farewell" {
		t.Fatalf("enrichGRPCFromBindings: bare endpoint services = %v, want [greet.v1.Farewell]", names)
	}

	// Feed the combined result through the exact Generate call
	// ClassifyProbeGenerate's grpc path uses.
	gen, err := generate.Get(APITypeGRPC)
	if err != nil {
		t.Fatalf("generate.Get(%q): %v", APITypeGRPC, err)
	}
	spec, err := gen.Generate(enriched)
	if err != nil {
		t.Fatalf("Generate must not return a conflicting file descriptors or duplicate symbol error: %v", err)
	}
	if len(spec) == 0 {
		t.Fatal("Generate returned an empty .proto for a valid gateway+bindings capture")
	}

	specStr := string(spec)
	if !strings.Contains(specStr, "service Greeter") {
		t.Errorf("expected .proto to contain service Greeter, got:\n%s", specStr)
	}
	if !strings.Contains(specStr, "service Farewell") {
		t.Errorf("expected .proto to contain service Farewell, got:\n%s", specStr)
	}
}

// ---------------------------------------------------------------------------
// QUAL-001 regression — single-host gateway-covered + streaming-only bindings
// must not be dropped
// ---------------------------------------------------------------------------

// TestEnrichGRPCFromBindings_SingleHostGatewayCoveredPlusStreamingOnlyBindingsSurvives
// pins the QUAL-001 fix on the real single-host shape: exactly ONE grpc
// endpoint exists and it is already fully covered by the grpc-gateway probe
// (GRPCSchema.ReflectionEnabled=false, Services=[greet.v1.Greeter] — as
// GRPCGatewayProbe leaves a seeded single endpoint after recovering an
// OpenAPI document). A captured gRPC-Web JS bundle recovers both
// greet.v1.Greeter (already covered) and greet.v1.Farewell, a streaming-only
// service the OpenAPI/JSON-transcoding gateway cannot expose at all.
//
// Before the fix: the fill loop's `grpcEndpointExists` flag was set for any
// grpc endpoint regardless of coverage, so the append branch's
// `if !grpcEndpointExists` never fired here (one grpc endpoint exists), and
// the fill loop itself skipped the covered endpoint (hasCoverage == true) —
// greet.v1.Farewell was recovered by ExtractGRPCWebBindings and then silently
// discarded. This test's load-bearing assertion (foundFarewell) fails against
// that old behavior; see the `attached` fix in enrichGRPCFromBindings, which
// appends a synthetic endpoint whenever no existing endpoint was actually
// attached to (as opposed to merely "exists").
func TestEnrichGRPCFromBindings_SingleHostGatewayCoveredPlusStreamingOnlyBindingsSurvives(t *testing.T) {
	// Real Connect-ES gRPC-Web bundle recovering two services in the same
	// package: Greeter (unary, overlaps the gateway-covered name) and
	// Farewell (server-streaming, invisible to the OpenAPI/JSON-transcoding
	// gateway and therefore uncovered).
	bindingsJS := []byte(`
		export const Greeter = {
		  typeName: "greet.v1.Greeter",
		  methods: {
		    sayHello: {
		      name: "SayHello",
		      I: HelloRequest,
		      O: HelloResponse,
		      kind: MethodKind.Unary,
		    },
		  },
		};

		export const Farewell = {
		  typeName: "greet.v1.Farewell",
		  methods: {
		    sayBye: {
		      name: "SayBye",
		      I: ByeRequest,
		      O: ByeResponse,
		      kind: MethodKind.ServerStreaming,
		    },
		  },
		};
	`)
	requests := []crawl.ObservedRequest{
		{
			Method: "GET",
			URL:    "https://example.com/greet_connect.js",
			Response: crawl.ObservedResponse{
				ContentType: "application/javascript",
				Body:        bindingsJS,
			},
		},
	}

	// The single grpc endpoint, already fully covered by the gateway probe.
	gatewaySchema := &classify.GRPCReflectionResult{
		ReflectionEnabled: false,
		Services: []classify.GRPCService{
			{Name: "greet.v1.Greeter", Methods: []classify.GRPCMethod{
				{Name: "SayHello", InputType: "HelloRequest", OutputType: "HelloResponse"},
			}},
		},
	}
	enriched := []classify.ClassifiedRequest{grpcClassifiedRequest(gatewaySchema)}

	result := enrichGRPCFromBindings(requests, enriched, io.Discard)

	if len(result) != 2 {
		t.Fatalf("enrichGRPCFromBindings: got %d endpoints, want 2 (gateway-covered endpoint preserved + a synthetic endpoint appended carrying the uncovered streaming-only service)", len(result))
	}

	// Reflection/gateway precedence: the covered endpoint's schema pointer and
	// Services must be left completely untouched.
	if result[0].GRPCSchema != gatewaySchema {
		t.Error("enrichGRPCFromBindings: gateway-covered endpoint's GRPCSchema pointer must be left untouched (reflection/gateway > bindings precedence)")
	}
	if names := grpcServiceNames(result[0].GRPCSchema); len(names) != 1 || names[0] != "greet.v1.Greeter" {
		t.Errorf("enrichGRPCFromBindings: gateway-covered endpoint services = %v, want [greet.v1.Greeter]", names)
	}

	// Load-bearing assertion: greet.v1.Farewell must appear somewhere in the
	// result. Fails against the pre-fix behavior, which dropped it entirely.
	var foundFarewell bool
	for _, ep := range result {
		for _, name := range grpcServiceNames(ep.GRPCSchema) {
			if name == "greet.v1.Farewell" {
				foundFarewell = true
			}
		}
	}
	if !foundFarewell {
		t.Fatal("enrichGRPCFromBindings: greet.v1.Farewell (uncovered, streaming-only) must not be dropped when the only grpc endpoint is already gateway-covered")
	}
}

// ---------------------------------------------------------------------------
// T4 — filterUncoveredServices: dedupes bindings services against recovered
// ---------------------------------------------------------------------------

// TestFilterUncoveredServices_DropsAlreadyCoveredFQNs (T4):
// enriched grpc endpoint has gateway Services [Greeter]; bindings recover
// [Greeter, Farewell]. Only Farewell should be returned.
func TestFilterUncoveredServices_DropsAlreadyCoveredFQNs(t *testing.T) {
	enriched := []classify.ClassifiedRequest{
		grpcClassifiedRequest(&classify.GRPCReflectionResult{
			Services: []classify.GRPCService{
				{Name: "Greeter"},
			},
		}),
	}
	bindingsSvcs := []classify.GRPCService{
		{Name: "Greeter"},  // already covered
		{Name: "Farewell"}, // new
	}

	filtered := filterUncoveredServices(bindingsSvcs, enriched)
	if len(filtered) != 1 {
		t.Fatalf("filterUncoveredServices: got %d services, want 1", len(filtered))
	}
	if filtered[0].Name != "Farewell" {
		t.Errorf("filterUncoveredServices: got %q, want Farewell", filtered[0].Name)
	}
}

// TestFilterUncoveredServices_LeadingDotStripped verifies that ".pkg.S" and
// "pkg.S" are considered the same FQN (leading dot stripped).
func TestFilterUncoveredServices_LeadingDotStripped(t *testing.T) {
	enriched := []classify.ClassifiedRequest{
		grpcClassifiedRequest(&classify.GRPCReflectionResult{
			Services: []classify.GRPCService{
				{Name: "pkg.S"}, // without leading dot
			},
		}),
	}
	bindingsSvcs := []classify.GRPCService{
		{Name: ".pkg.S"}, // with leading dot — same FQN
	}

	filtered := filterUncoveredServices(bindingsSvcs, enriched)
	if len(filtered) != 0 {
		t.Errorf("filterUncoveredServices: expected 0 uncovered services (leading dot stripped), got %d: %v", len(filtered), filtered)
	}
}

// TestFilterUncoveredServices_AllNew verifies all services are returned when
// none overlap with already-covered FQNs.
func TestFilterUncoveredServices_AllNew(t *testing.T) {
	enriched := []classify.ClassifiedRequest{
		grpcClassifiedRequest(&classify.GRPCReflectionResult{
			Services: []classify.GRPCService{{Name: "OtherService"}},
		}),
	}
	bindingsSvcs := []classify.GRPCService{
		{Name: "Alpha"},
		{Name: "Beta"},
	}

	filtered := filterUncoveredServices(bindingsSvcs, enriched)
	if len(filtered) != 2 {
		t.Errorf("filterUncoveredServices: got %d, want 2", len(filtered))
	}
}

// TestFilterUncoveredServices_EmptyEnriched verifies all services are returned
// when no endpoints exist.
func TestFilterUncoveredServices_EmptyEnriched(t *testing.T) {
	bindingsSvcs := []classify.GRPCService{
		{Name: "Alpha"},
	}
	filtered := filterUncoveredServices(bindingsSvcs, nil)
	if len(filtered) != 1 {
		t.Errorf("filterUncoveredServices with nil enriched: got %d, want 1", len(filtered))
	}
}

// ---------------------------------------------------------------------------
// T5 — seedGRPCHostEndpoints: host dedup, ordering, cap, excludes existing
// ---------------------------------------------------------------------------

// TestSeedGRPCHostEndpoints_DeduplicatesAndOrders (T5 core):
// REST requests across 2 distinct hosts + many paths → exactly 2 synthetic
// grpc endpoints, deterministic (sorted) order.
func TestSeedGRPCHostEndpoints_DeduplicatesAndOrders(t *testing.T) {
	// 50 paths across 2 hosts: host A and host B.
	requests := make([]crawl.ObservedRequest, 0, 50)
	for i := 0; i < 25; i++ {
		requests = append(requests, crawl.ObservedRequest{
			Method: "GET",
			URL:    fmt.Sprintf("https://alpha.example.com/api/path%d", i),
		})
		requests = append(requests, crawl.ObservedRequest{
			Method: "GET",
			URL:    fmt.Sprintf("https://beta.example.com/api/path%d", i),
		})
	}

	classified := []classify.ClassifiedRequest{} // no pre-existing grpc endpoints
	result := seedGRPCHostEndpoints(requests, classified, 500)

	// Should have exactly 2 synthetic grpc endpoints.
	var grpcEPs []classify.ClassifiedRequest
	for _, ep := range result {
		if ep.APIType == APITypeGRPC {
			grpcEPs = append(grpcEPs, ep)
		}
	}
	if len(grpcEPs) != 2 {
		t.Fatalf("seedGRPCHostEndpoints: got %d grpc endpoints, want 2", len(grpcEPs))
	}

	// Deterministic order: alpha before beta.
	if grpcEPs[0].URL != "https://alpha.example.com" {
		t.Errorf("first synthetic endpoint URL = %q, want %q", grpcEPs[0].URL, "https://alpha.example.com")
	}
	if grpcEPs[1].URL != "https://beta.example.com" {
		t.Errorf("second synthetic endpoint URL = %q, want %q", grpcEPs[1].URL, "https://beta.example.com")
	}
}

// TestSeedGRPCHostEndpoints_ExcludesExistingGRPCHosts verifies that hosts
// already covered by classified grpc endpoints are not re-seeded.
func TestSeedGRPCHostEndpoints_ExcludesExistingGRPCHosts(t *testing.T) {
	requests := []crawl.ObservedRequest{
		{Method: "GET", URL: "https://api.example.com/v1/users"},
		{Method: "GET", URL: "https://grpc.example.com/SomeService/Method"},
	}
	classified := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{URL: "https://grpc.example.com/SomeService/Method"},
			APIType:         APITypeGRPC,
		},
	}

	result := seedGRPCHostEndpoints(requests, classified, 500)

	// grpc.example.com is already present; only api.example.com should be seeded.
	var newEPs []classify.ClassifiedRequest
	for _, ep := range result {
		if ep.APIType == APITypeGRPC && ep.URL != "https://grpc.example.com/SomeService/Method" {
			newEPs = append(newEPs, ep)
		}
	}
	if len(newEPs) != 1 {
		t.Fatalf("seedGRPCHostEndpoints: got %d new grpc endpoints, want 1", len(newEPs))
	}
	if newEPs[0].URL != "https://api.example.com" {
		t.Errorf("new endpoint URL = %q, want %q", newEPs[0].URL, "https://api.example.com")
	}
}

// TestSeedGRPCHostEndpoints_RespectsMaxHostsCap verifies the cap is honored.
func TestSeedGRPCHostEndpoints_RespectsMaxHostsCap(t *testing.T) {
	requests := make([]crawl.ObservedRequest, 10)
	for i := range requests {
		requests[i] = crawl.ObservedRequest{
			Method: "GET",
			URL:    fmt.Sprintf("https://host%02d.example.com/api", i),
		}
	}
	const cap = 3
	result := seedGRPCHostEndpoints(requests, nil, cap)

	var grpcEPs []classify.ClassifiedRequest
	for _, ep := range result {
		if ep.APIType == APITypeGRPC {
			grpcEPs = append(grpcEPs, ep)
		}
	}
	if len(grpcEPs) != cap {
		t.Errorf("seedGRPCHostEndpoints with cap=%d: got %d grpc endpoints, want %d", cap, len(grpcEPs), cap)
	}
}

// TestSeedGRPCHostEndpoints_UnparsableURLsSkipped verifies that malformed URLs
// in requests do not panic and are simply skipped.
func TestSeedGRPCHostEndpoints_UnparsableURLsSkipped(t *testing.T) {
	requests := []crawl.ObservedRequest{
		{Method: "GET", URL: "://invalid"},
		{Method: "GET", URL: "https://valid.example.com/api"},
	}
	result := seedGRPCHostEndpoints(requests, nil, 500)

	var grpcEPs []classify.ClassifiedRequest
	for _, ep := range result {
		if ep.APIType == APITypeGRPC {
			grpcEPs = append(grpcEPs, ep)
		}
	}
	if len(grpcEPs) != 1 {
		t.Errorf("expected 1 grpc endpoint (invalid URL skipped), got %d", len(grpcEPs))
	}
}

// TestGRPCHostKey_Basic verifies grpcHostKey extracts scheme://host correctly.
func TestGRPCHostKey_Basic(t *testing.T) {
	tests := []struct {
		rawURL string
		want   string
	}{
		{"https://example.com/grpc/path", "https://example.com"},
		{"http://example.com:8080/api", "http://example.com:8080"},
		{"grpc://example.com:9090", "grpc://example.com:9090"},
		{"://invalid", ""},
		{"https://", ""}, // no host
	}
	for _, tt := range tests {
		got := grpcHostKey(tt.rawURL)
		if got != tt.want {
			t.Errorf("grpcHostKey(%q) = %q, want %q", tt.rawURL, got, tt.want)
		}
	}
}
