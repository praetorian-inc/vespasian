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
// Note: the prefix must start with an uppercase letter. A fully-qualified
// prefix like "greet.v1.Greeter" starts with lowercase 'g' and is therefore
// rejected — the operationId pattern used in practice by protoc-gen-openapiv2
// uses just the service name (e.g. "Greeter_SayHello"), not the full FQN.
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
