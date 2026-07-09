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

// Package probe — internal tests for unexported grpc-gateway detection helpers.
// Uses `package probe` (not probe_test) to access unexported functions.
package probe

import (
	"encoding/json"
	"testing"
)

// ---------------------------------------------------------------------------
// T6 — Loosened detection helpers: looksLikeServiceMethodOpID, isUpperInitial,
//
//	isGRPCGatewayDoc / servicesFromOpenAPI
//
// ---------------------------------------------------------------------------

// TestLooksLikeServiceMethodOpID_AcceptsUpperInitialBoth verifies that an
// operationId with both Service and Method starting with an uppercase letter is
// accepted as a grpc-gateway shape.
//
// Note: the Upper-initial check applies to the last dot-separated segment of
// the prefix (the service name), not the whole prefix. A package-qualified
// prefix like "greet.v1.Greeter" is therefore still accepted — its last
// segment "Greeter" is upper-initial — alongside the unqualified form used in
// practice by protoc-gen-openapiv2 (e.g. "Greeter_SayHello").
func TestLooksLikeServiceMethodOpID_AcceptsUpperInitialBoth(t *testing.T) {
	cases := []string{
		"Greeter_SayHello",
		"UserService_GetUser",
		"UserService_CreateUser",
		"Api_Create",
	}
	for _, opID := range cases {
		if !looksLikeServiceMethodOpID(opID) {
			t.Errorf("looksLikeServiceMethodOpID(%q) = false, want true", opID)
		}
	}
}

// TestLooksLikeServiceMethodOpID_RejectsPlainREST verifies that camelCase and
// lowercase-method REST operationIds are rejected.
func TestLooksLikeServiceMethodOpID_RejectsPlainREST(t *testing.T) {
	cases := []string{
		"listUsers",        // camelCase, no underscore
		"user_list",        // lowercase method
		"get_users",        // lowercase method
		"orders_v1_create", // lowercase method
		"createPet",        // camelCase, no underscore
		"",                 // empty
	}
	for _, opID := range cases {
		if looksLikeServiceMethodOpID(opID) {
			t.Errorf("looksLikeServiceMethodOpID(%q) = true, want false (plain REST shape)", opID)
		}
	}
}

// TestIsUpperInitial_AcceptsUppercaseLetter verifies isUpperInitial reports
// true for strings starting with A-Z.
func TestIsUpperInitial_AcceptsUppercaseLetter(t *testing.T) {
	for _, s := range []string{"Greeter", "UserService", "A", "Z", "MyMethod"} {
		if !isUpperInitial(s) {
			t.Errorf("isUpperInitial(%q) = false, want true", s)
		}
	}
}

// TestIsUpperInitial_RejectsLowercaseOrEmpty verifies isUpperInitial returns
// false for empty strings and strings starting with a lowercase letter.
func TestIsUpperInitial_RejectsLowercaseOrEmpty(t *testing.T) {
	for _, s := range []string{"", "greeter", "user", "1Service"} {
		if isUpperInitial(s) {
			t.Errorf("isUpperInitial(%q) = true, want false", s)
		}
	}
}

// TestServicesFromOpenAPI_GreeterSayHello (T6 core — LAB-3864):
// A doc with info.title="Greeter", no FQN tags, and
// operationId:"Greeter_SayHello" must be recognized as a grpc-gateway doc
// and recover service "Greeter" with method "SayHello".
func TestServicesFromOpenAPI_GreeterSayHello(t *testing.T) {
	body := []byte(`{
		"swagger": "2.0",
		"info": {"title": "Greeter", "version": "1.0"},
		"paths": {
			"/v1/hello": {
				"post": {
					"operationId": "Greeter_SayHello",
					"responses": {"200": {"description": "OK"}}
				}
			}
		}
	}`)

	svcs := servicesFromOpenAPI(body)
	if len(svcs) == 0 {
		t.Fatal("servicesFromOpenAPI: expected at least one service from Greeter_SayHello, got none")
	}

	var found bool
	for _, s := range svcs {
		if s.Name == "Greeter" {
			found = true
			var methods []string
			for _, m := range s.Methods {
				methods = append(methods, m.Name)
			}
			// Verify SayHello is recovered.
			hasMethod := false
			for _, mn := range methods {
				if mn == "SayHello" {
					hasMethod = true
				}
			}
			if !hasMethod {
				t.Errorf("service Greeter: SayHello not found among methods %v", methods)
			}
		}
	}
	if !found {
		var names []string
		for _, s := range svcs {
			names = append(names, s.Name)
		}
		t.Errorf("service Greeter not found in recovered services %v", names)
	}
}

// TestServicesFromOpenAPI_PlainRESTReturnsNil (T6 negative):
// A plain REST swagger with lowercase camelCase operationIds must return nil
// (not recognized as grpc-gateway).
func TestServicesFromOpenAPI_PlainRESTReturnsNil(t *testing.T) {
	body := []byte(`{
		"swagger": "2.0",
		"info": {"title": "Pet Store API", "version": "1.0"},
		"tags": [{"name": "pets"}],
		"paths": {
			"/pets": {
				"get": {
					"operationId": "listPets",
					"tags": ["pets"]
				}
			}
		}
	}`)

	svcs := servicesFromOpenAPI(body)
	if svcs != nil {
		t.Errorf("servicesFromOpenAPI returned non-nil for plain REST: %v", svcs)
	}
}

// TestServicesFromOpenAPI_UserListRejected verifies "user_list" style
// (lowercase method) is not accepted as grpc-gateway.
func TestServicesFromOpenAPI_UserListRejected(t *testing.T) {
	body := []byte(`{
		"swagger": "2.0",
		"info": {"title": "Users API"},
		"paths": {
			"/users": {
				"get": {"operationId": "user_list"}
			}
		}
	}`)
	svcs := servicesFromOpenAPI(body)
	if svcs != nil {
		t.Errorf("servicesFromOpenAPI returned non-nil for user_list operationId: %v", svcs)
	}
}

// TestIsGRPCGatewayDoc_FQNShapedTitle verifies the strong-signal FQN-shaped
// title path still works after the detection change (existing behavior retained).
func TestIsGRPCGatewayDoc_FQNShapedTitle(t *testing.T) {
	doc := &openAPIDoc{}
	doc.Info.Title = "users.v1.UserService"
	if !isGRPCGatewayDoc(doc) {
		t.Error("isGRPCGatewayDoc: FQN-shaped title should be accepted")
	}
}

// TestIsGRPCGatewayDoc_VersionSegmentWithoutServiceSuffix verifies the ".vN."
// version-segment branch of looksLikeServiceFQN: a title that does not end in
// "Service" but carries a ".vN." segment (e.g. "orders.v1.Fetcher") is still
// accepted as a grpc-gateway doc.
func TestIsGRPCGatewayDoc_VersionSegmentWithoutServiceSuffix(t *testing.T) {
	doc := &openAPIDoc{}
	doc.Info.Title = "orders.v1.Fetcher"
	if !isGRPCGatewayDoc(doc) {
		t.Error("isGRPCGatewayDoc: version-segment title without Service suffix (orders.v1.Fetcher) should be accepted")
	}
}

// TestLooksLikeServiceFQN_RejectsVersionSegmentWithInjectedContent pins the
// SEC-BE-001 injection guard on the ".vN." version-segment branch of
// looksLikeServiceFQN: a string that satisfies versionSegmentPattern (it
// contains ".v1.") but is NOT a valid dotted proto identifier — here because
// a segment carries a newline and braces — must be rejected. If the
// "&& isDottedProtoIdent(s)" anchor were removed from looksLikeServiceFQN,
// versionSegmentPattern alone would match this string and the test would
// fail.
func TestLooksLikeServiceFQN_RejectsVersionSegmentWithInjectedContent(t *testing.T) {
	malformed := "orders.v1.Fetcher\n{injected}"
	if looksLikeServiceFQN(malformed) {
		t.Errorf("looksLikeServiceFQN(%q) = true, want false: version-segment match without a valid dotted proto identifier must be rejected (SEC-BE-001 guard)", malformed)
	}
}

// TestServicesFromOpenAPI_RejectsInjectedTagAsServiceName pins the
// SEC-BE-001 guard end-to-end through the public entry point servicesFromOpenAPI:
// an operation tag that matches versionSegmentPattern but carries injected
// content (newline + braces) must never be emitted as the recovered
// GRPCService.Name. serviceFromOperation must fall through to the
// operationId prefix instead. If the isDottedProtoIdent anchor were removed,
// the malformed tag would satisfy looksLikeServiceFQN and be returned
// verbatim as the service name.
func TestServicesFromOpenAPI_RejectsInjectedTagAsServiceName(t *testing.T) {
	doc := openAPIDoc{}
	doc.Info.Title = "Orders"
	doc.Paths = map[string]map[string]struct {
		OperationID string   `json:"operationId"`
		Tags        []string `json:"tags"`
	}{
		"/v1/orders": {
			"get": {OperationID: "Orders_Fetch", Tags: []string{"orders.v1.Fetcher\n{injected}"}},
		},
	}
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal doc: %v", err)
	}

	svcs := servicesFromOpenAPI(body)

	if len(svcs) != 1 {
		t.Fatalf("servicesFromOpenAPI: got %d services, want 1: %v", len(svcs), svcs)
	}
	if svcs[0].Name == "orders.v1.Fetcher\n{injected}" {
		t.Errorf("servicesFromOpenAPI: recovered malformed tag %q as service name (SEC-BE-001 guard bypassed)", svcs[0].Name)
	}
	if svcs[0].Name != "Orders" {
		t.Errorf("servicesFromOpenAPI: service name = %q, want %q (operationId prefix fallback)", svcs[0].Name, "Orders")
	}
}

// TestIsGRPCGatewayDoc_UpperInitialOperationID verifies that a doc with no
// FQN-shaped title or tags but an Upper-initial operationId is now accepted.
func TestIsGRPCGatewayDoc_UpperInitialOperationID(t *testing.T) {
	doc := &openAPIDoc{
		Paths: map[string]map[string]struct {
			OperationID string   `json:"operationId"`
			Tags        []string `json:"tags"`
		}{
			"/v1/hello": {
				"post": {OperationID: "Greeter_SayHello"},
			},
		},
	}
	doc.Info.Title = "Greeter" // plain title, not FQN-shaped
	if !isGRPCGatewayDoc(doc) {
		t.Error("isGRPCGatewayDoc: Upper-initial operationId Greeter_SayHello must be accepted")
	}
}

// TestIsGRPCGatewayDoc_LowercaseMethodRejected verifies a lowercase-method
// operationId does not trigger false-positive acceptance.
func TestIsGRPCGatewayDoc_LowercaseMethodRejected(t *testing.T) {
	doc := &openAPIDoc{
		Paths: map[string]map[string]struct {
			OperationID string   `json:"operationId"`
			Tags        []string `json:"tags"`
		}{
			"/users": {
				"get": {OperationID: "user_list"},
			},
		},
	}
	doc.Info.Title = "Users API"
	if isGRPCGatewayDoc(doc) {
		t.Error("isGRPCGatewayDoc: lowercase-method operationId user_list must not be accepted")
	}
}

// ---------------------------------------------------------------------------
// QUAL-002 regression — fqn-naming-strategy operationId recovery
// (serviceSegment)
// ---------------------------------------------------------------------------

// TestServicesFromOpenAPI_FQNNamingStrategyOperationIDRecoversFullServiceName
// pins the QUAL-002 fix: protoc-gen-openapiv2's fqn naming strategy emits
// operationIds of the shape "<package>.<Service>_<Method>" (e.g.
// "greet.v1.Greeter_SayHello", prefix "greet.v1.Greeter"), where the prefix as
// a whole starts with a lowercase package segment ("greet"). Before the fix,
// the service-name check applied isUpperInitial to the whole prefix, so this
// operationId shape was rejected outright — the fqn-naming-strategy
// combination never recovered a service. serviceSegment now extracts the last
// dot-segment ("Greeter") for the Upper-initial check, while the recovered
// service name returned to the caller stays the FULL FQN ("greet.v1.Greeter"),
// not just "Greeter".
func TestServicesFromOpenAPI_FQNNamingStrategyOperationIDRecoversFullServiceName(t *testing.T) {
	// info.title is itself FQN-shaped (carries a ".vN." version segment), so
	// isGRPCGatewayDoc also recognizes this document via the strong-signal
	// title/tag branch, not only via the operationId primary signal.
	body := []byte(`{
		"swagger": "2.0",
		"info": {"title": "greet.v1.Greeter", "version": "1.0"},
		"paths": {
			"/v1/greet": {
				"post": {
					"operationId": "greet.v1.Greeter_SayHello",
					"responses": {"200": {"description": "OK"}}
				}
			}
		}
	}`)

	svcs := servicesFromOpenAPI(body)
	if len(svcs) == 0 {
		t.Fatal("servicesFromOpenAPI: expected at least one service from the fqn-naming-strategy operationId greet.v1.Greeter_SayHello, got none")
	}

	var found bool
	for _, s := range svcs {
		if s.Name != "greet.v1.Greeter" {
			continue
		}
		found = true
		var hasMethod bool
		for _, m := range s.Methods {
			if m.Name == "SayHello" {
				hasMethod = true
			}
		}
		if !hasMethod {
			t.Errorf("service greet.v1.Greeter: SayHello not found among methods %+v", s.Methods)
		}
	}
	if !found {
		var names []string
		for _, s := range svcs {
			names = append(names, s.Name)
		}
		t.Errorf("servicesFromOpenAPI: full FQN service name %q not found in recovered services %v (got just the last segment, or nothing)", "greet.v1.Greeter", names)
	}
}

// TestIsGRPCGatewayDoc_FQNLowercaseLastSegmentRejected verifies the
// serviceSegment fix does not over-loosen detection: an operationId prefix
// whose LAST dot-segment is lowercase (e.g. "foo.bar.widget_List", last
// segment "widget") must still be rejected, matching the existing
// unqualified-name rule that "widget" is not a service name.
func TestIsGRPCGatewayDoc_FQNLowercaseLastSegmentRejected(t *testing.T) {
	doc := &openAPIDoc{
		Paths: map[string]map[string]struct {
			OperationID string   `json:"operationId"`
			Tags        []string `json:"tags"`
		}{
			"/v1/widgets": {
				"get": {OperationID: "foo.bar.widget_List"},
			},
		},
	}
	// Plain title, not FQN-shaped (no ".vN." segment, no *Service suffix), so
	// only the operationId signal is in play.
	doc.Info.Title = "Widgets API"
	if isGRPCGatewayDoc(doc) {
		t.Error("isGRPCGatewayDoc: fqn-style operationId with lowercase last segment (foo.bar.widget_List) must not be accepted")
	}

	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal doc: %v", err)
	}
	if svcs := servicesFromOpenAPI(body); svcs != nil {
		t.Errorf("servicesFromOpenAPI: expected nil for foo.bar.widget_List (lowercase last segment), got %v", svcs)
	}
}
