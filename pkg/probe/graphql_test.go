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
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/praetorian-inc/vespasian/pkg/classify"
	"github.com/praetorian-inc/vespasian/pkg/crawl"
	"github.com/praetorian-inc/vespasian/pkg/probe"
)

const validIntrospectionResponse = `{
  "data": {
    "__schema": {
      "types": [
        {
          "name": "Query",
          "kind": "OBJECT",
          "fields": [
            {
              "name": "user",
              "type": { "name": "User", "kind": "OBJECT", "ofType": null }
            },
            {
              "name": "users",
              "type": { "name": null, "kind": "LIST", "ofType": { "name": "User" } }
            }
          ]
        },
        {
          "name": "User",
          "kind": "OBJECT",
          "fields": [
            {
              "name": "id",
              "type": { "name": "ID", "kind": "SCALAR", "ofType": null }
            },
            {
              "name": "name",
              "type": { "name": "String", "kind": "SCALAR", "ofType": null }
            }
          ]
        }
      ]
    }
  }
}`

func TestGraphQLProbe_Name(t *testing.T) {
	p := probe.NewGraphQLProbe(probe.DefaultConfig())
	if p.Name() != "graphql" {
		t.Errorf("Name() = %q, want %q", p.Name(), "graphql")
	}
}

func TestGraphQLProbe_SuccessfulIntrospection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(validIntrospectionResponse)) //nolint:gosec // test handler
	}))
	defer srv.Close()

	cfg := probe.Config{Client: srv.Client(), Timeout: 5 * time.Second, URLValidator: func(string) error { return nil }}
	p := probe.NewGraphQLProbe(cfg)

	endpoints := []classify.ClassifiedRequest{{
		ObservedRequest: crawl.ObservedRequest{
			Method: "POST",
			URL:    srv.URL + "/graphql",
		},
		IsAPI:   true,
		APIType: "graphql",
	}}

	result, err := p.Probe(context.Background(), endpoints)
	if err != nil {
		t.Fatalf("Probe() error: %v", err)
	}

	schema := result[0].GraphQLSchema
	if schema == nil {
		t.Fatal("GraphQLSchema should not be nil")
	}
	if !schema.IntrospectionEnabled {
		t.Error("IntrospectionEnabled should be true")
	}
	if len(schema.Types) != 2 {
		t.Fatalf("expected 2 types, got %d", len(schema.Types))
	}
	if schema.Types[0].Name != "Query" {
		t.Errorf("first type name = %q, want %q", schema.Types[0].Name, "Query")
	}
	if len(schema.Types[0].Fields) != 2 {
		t.Errorf("Query type should have 2 fields, got %d", len(schema.Types[0].Fields))
	}
	if schema.RawResponse == nil {
		t.Error("RawResponse should not be nil")
	}
	// Check ofType parsing
	usersField := schema.Types[0].Fields[1]
	if usersField.Type.OfType == nil {
		t.Fatal("users field ofType should not be nil")
	}
	if usersField.Type.OfType.Name == nil || *usersField.Type.OfType.Name != "User" {
		t.Error("users field ofType.Name should be 'User'")
	}
}

func TestGraphQLProbe_IntrospectionDisabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"errors":[{"message":"introspection is disabled"}]}`)) //nolint:gosec // test handler
	}))
	defer srv.Close()

	cfg := probe.Config{Client: srv.Client(), Timeout: 5 * time.Second, URLValidator: func(string) error { return nil }}
	p := probe.NewGraphQLProbe(cfg)

	endpoints := []classify.ClassifiedRequest{{
		ObservedRequest: crawl.ObservedRequest{Method: "POST", URL: srv.URL + "/graphql"},
		IsAPI:           true,
		APIType:         "graphql",
	}}

	result, err := p.Probe(context.Background(), endpoints)
	if err != nil {
		t.Fatalf("Probe() error: %v", err)
	}

	schema := result[0].GraphQLSchema
	if schema == nil {
		t.Fatal("GraphQLSchema should not be nil when introspection is disabled")
	}
	if schema.IntrospectionEnabled {
		t.Error("IntrospectionEnabled should be false")
	}
}

func TestGraphQLProbe_404Response(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	cfg := probe.Config{Client: srv.Client(), Timeout: 5 * time.Second, URLValidator: func(string) error { return nil }}
	p := probe.NewGraphQLProbe(cfg)

	endpoints := []classify.ClassifiedRequest{{
		ObservedRequest: crawl.ObservedRequest{Method: "POST", URL: srv.URL + "/graphql"},
		IsAPI:           true,
		APIType:         "graphql",
	}}

	result, err := p.Probe(context.Background(), endpoints)
	if err != nil {
		t.Fatalf("Probe() error: %v", err)
	}

	if result[0].GraphQLSchema != nil {
		t.Error("expected nil GraphQLSchema for 404 response")
	}
}

func TestGraphQLProbe_SkipsNonGraphQL(t *testing.T) {
	var requestCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := probe.Config{Client: srv.Client(), Timeout: 5 * time.Second, URLValidator: func(string) error { return nil }}
	p := probe.NewGraphQLProbe(cfg)

	endpoints := []classify.ClassifiedRequest{{
		ObservedRequest: crawl.ObservedRequest{Method: "GET", URL: srv.URL + "/api/users"},
		IsAPI:           true,
		APIType:         "rest",
	}}

	_, err := p.Probe(context.Background(), endpoints)
	if err != nil {
		t.Fatalf("Probe() error: %v", err)
	}

	if requestCount.Load() != 0 {
		t.Errorf("expected 0 requests for non-GraphQL endpoint, got %d", requestCount.Load())
	}
}

func TestGraphQLProbe_DeduplicatesByURL(t *testing.T) {
	var requestCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(validIntrospectionResponse)) //nolint:gosec // test handler
	}))
	defer srv.Close()

	cfg := probe.Config{Client: srv.Client(), Timeout: 5 * time.Second, URLValidator: func(string) error { return nil }}
	p := probe.NewGraphQLProbe(cfg)

	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{Method: "POST", URL: srv.URL + "/graphql"},
			IsAPI:           true, APIType: "graphql",
		},
		{
			ObservedRequest: crawl.ObservedRequest{Method: "POST", URL: srv.URL + "/graphql"},
			IsAPI:           true, APIType: "graphql",
		},
	}

	result, err := p.Probe(context.Background(), endpoints)
	if err != nil {
		t.Fatalf("Probe() error: %v", err)
	}

	if requestCount.Load() != 1 {
		t.Errorf("expected 1 request (deduplicated by URL), got %d", requestCount.Load())
	}
	if result[0].GraphQLSchema == nil {
		t.Error("result[0].GraphQLSchema should not be nil")
	}
	if result[1].GraphQLSchema == nil {
		t.Error("result[1].GraphQLSchema should not be nil")
	}
}

func TestGraphQLProbe_MaxEndpointsRespected(t *testing.T) {
	var requestCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(validIntrospectionResponse)) //nolint:gosec // test handler
	}))
	defer srv.Close()

	cfg := probe.Config{
		Client:       srv.Client(),
		Timeout:      5 * time.Second,
		URLValidator: func(string) error { return nil },
		MaxEndpoints: 2,
	}
	p := probe.NewGraphQLProbe(cfg)

	endpoints := []classify.ClassifiedRequest{
		{ObservedRequest: crawl.ObservedRequest{Method: "POST", URL: srv.URL + "/graphql1"}, IsAPI: true, APIType: "graphql"},
		{ObservedRequest: crawl.ObservedRequest{Method: "POST", URL: srv.URL + "/graphql2"}, IsAPI: true, APIType: "graphql"},
		{ObservedRequest: crawl.ObservedRequest{Method: "POST", URL: srv.URL + "/graphql3"}, IsAPI: true, APIType: "graphql"},
	}

	_, err := p.Probe(context.Background(), endpoints)
	if err != nil {
		t.Fatalf("Probe() error: %v", err)
	}

	if requestCount.Load() > 2 {
		t.Errorf("expected at most 2 requests (MaxEndpoints=2), got %d", requestCount.Load())
	}
}

func TestGraphQLProbe_DoesNotMutateInput(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(validIntrospectionResponse)) //nolint:gosec // test handler
	}))
	defer srv.Close()

	cfg := probe.Config{Client: srv.Client(), Timeout: 5 * time.Second, URLValidator: func(string) error { return nil }}
	p := probe.NewGraphQLProbe(cfg)

	original := []classify.ClassifiedRequest{{
		ObservedRequest: crawl.ObservedRequest{Method: "POST", URL: srv.URL + "/graphql"},
		IsAPI:           true, APIType: "graphql",
	}}

	result, err := p.Probe(context.Background(), original)
	if err != nil {
		t.Fatalf("Probe() error: %v", err)
	}
	if original[0].GraphQLSchema != nil {
		t.Error("original slice should not be mutated")
	}
	if result[0].GraphQLSchema == nil {
		t.Error("result slice should have GraphQLSchema")
	}
}

func TestGraphQLProbe_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{not valid json`)) //nolint:gosec // test handler
	}))
	defer srv.Close()

	cfg := probe.Config{Client: srv.Client(), Timeout: 5 * time.Second, URLValidator: func(string) error { return nil }}
	p := probe.NewGraphQLProbe(cfg)

	endpoints := []classify.ClassifiedRequest{{
		ObservedRequest: crawl.ObservedRequest{Method: "POST", URL: srv.URL + "/graphql"},
		IsAPI:           true,
		APIType:         "graphql",
	}}

	result, err := p.Probe(context.Background(), endpoints)
	if err != nil {
		t.Fatalf("Probe() error: %v", err)
	}

	schema := result[0].GraphQLSchema
	if schema == nil {
		t.Fatal("GraphQLSchema should not be nil for malformed JSON")
	}
	if schema.IntrospectionEnabled {
		t.Error("IntrospectionEnabled should be false for malformed JSON")
	}
}

// fullIntrospectionResponse is a realistic introspection response with args,
// inputFields, enumValues, interfaces, possibleTypes, and root type names.
const fullIntrospectionResponse = `{
  "data": {
    "__schema": {
      "queryType": { "name": "Query" },
      "mutationType": { "name": "Mutation" },
      "subscriptionType": null,
      "types": [
        {
          "name": "Query",
          "kind": "OBJECT",
          "description": "Root query type",
          "fields": [
            {
              "name": "user",
              "description": "Fetch a user by ID",
              "args": [
                {
                  "name": "id",
                  "description": "The user ID",
                  "type": { "kind": "NON_NULL", "name": null, "ofType": { "kind": "SCALAR", "name": "ID", "ofType": null } },
                  "defaultValue": null
                }
              ],
              "type": { "name": "User", "kind": "OBJECT", "ofType": null },
              "isDeprecated": false,
              "deprecationReason": null
            },
            {
              "name": "users",
              "description": "",
              "args": [
                {
                  "name": "limit",
                  "description": "",
                  "type": { "kind": "SCALAR", "name": "Int", "ofType": null },
                  "defaultValue": "10"
                }
              ],
              "type": { "kind": "NON_NULL", "name": null, "ofType": { "kind": "LIST", "name": null, "ofType": { "kind": "NON_NULL", "name": null, "ofType": { "kind": "OBJECT", "name": "User", "ofType": null } } } },
              "isDeprecated": false,
              "deprecationReason": null
            },
            {
              "name": "search",
              "description": "",
              "args": [
                {
                  "name": "query",
                  "description": "",
                  "type": { "kind": "NON_NULL", "name": null, "ofType": { "kind": "SCALAR", "name": "String", "ofType": null } },
                  "defaultValue": null
                }
              ],
              "type": { "kind": "OBJECT", "name": "SearchResult", "ofType": null },
              "isDeprecated": false,
              "deprecationReason": null
            }
          ],
          "inputFields": null,
          "interfaces": [],
          "enumValues": null,
          "possibleTypes": null
        },
        {
          "name": "Mutation",
          "kind": "OBJECT",
          "description": "",
          "fields": [
            {
              "name": "createUser",
              "description": "",
              "args": [
                {
                  "name": "input",
                  "description": "",
                  "type": { "kind": "NON_NULL", "name": null, "ofType": { "kind": "INPUT_OBJECT", "name": "CreateUserInput", "ofType": null } },
                  "defaultValue": null
                }
              ],
              "type": { "kind": "OBJECT", "name": "User", "ofType": null },
              "isDeprecated": false,
              "deprecationReason": null
            }
          ],
          "inputFields": null,
          "interfaces": [],
          "enumValues": null,
          "possibleTypes": null
        },
        {
          "name": "User",
          "kind": "OBJECT",
          "description": "A user in the system",
          "fields": [
            {
              "name": "id",
              "description": "",
              "args": [],
              "type": { "kind": "NON_NULL", "name": null, "ofType": { "kind": "SCALAR", "name": "ID", "ofType": null } },
              "isDeprecated": false,
              "deprecationReason": null
            },
            {
              "name": "name",
              "description": "",
              "args": [],
              "type": { "kind": "SCALAR", "name": "String", "ofType": null },
              "isDeprecated": false,
              "deprecationReason": null
            },
            {
              "name": "role",
              "description": "",
              "args": [],
              "type": { "kind": "ENUM", "name": "Role", "ofType": null },
              "isDeprecated": false,
              "deprecationReason": null
            }
          ],
          "inputFields": null,
          "interfaces": [
            { "kind": "INTERFACE", "name": "Node", "ofType": null }
          ],
          "enumValues": null,
          "possibleTypes": null
        },
        {
          "name": "Node",
          "kind": "INTERFACE",
          "description": "",
          "fields": [
            {
              "name": "id",
              "description": "",
              "args": [],
              "type": { "kind": "NON_NULL", "name": null, "ofType": { "kind": "SCALAR", "name": "ID", "ofType": null } },
              "isDeprecated": false,
              "deprecationReason": null
            }
          ],
          "inputFields": null,
          "interfaces": null,
          "enumValues": null,
          "possibleTypes": [
            { "kind": "OBJECT", "name": "User", "ofType": null }
          ]
        },
        {
          "name": "Role",
          "kind": "ENUM",
          "description": "User roles",
          "fields": null,
          "inputFields": null,
          "interfaces": null,
          "enumValues": [
            { "name": "ADMIN", "description": "", "isDeprecated": false, "deprecationReason": null },
            { "name": "EDITOR", "description": "", "isDeprecated": false, "deprecationReason": null },
            { "name": "VIEWER", "description": "", "isDeprecated": true, "deprecationReason": "Use READER" }
          ],
          "possibleTypes": null
        },
        {
          "name": "CreateUserInput",
          "kind": "INPUT_OBJECT",
          "description": "",
          "fields": null,
          "inputFields": [
            {
              "name": "name",
              "description": "",
              "type": { "kind": "NON_NULL", "name": null, "ofType": { "kind": "SCALAR", "name": "String", "ofType": null } },
              "defaultValue": null
            },
            {
              "name": "email",
              "description": "",
              "type": { "kind": "NON_NULL", "name": null, "ofType": { "kind": "SCALAR", "name": "String", "ofType": null } },
              "defaultValue": null
            },
            {
              "name": "role",
              "description": "",
              "type": { "kind": "ENUM", "name": "Role", "ofType": null },
              "defaultValue": "\"VIEWER\""
            }
          ],
          "interfaces": null,
          "enumValues": null,
          "possibleTypes": null
        },
        {
          "name": "SearchResult",
          "kind": "UNION",
          "description": "",
          "fields": null,
          "inputFields": null,
          "interfaces": null,
          "enumValues": null,
          "possibleTypes": [
            { "kind": "OBJECT", "name": "User", "ofType": null },
            { "kind": "OBJECT", "name": "Post", "ofType": null }
          ]
        }
      ]
    }
  }
}`

func TestGraphQLProbe_FullIntrospectionParsing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(fullIntrospectionResponse)) //nolint:gosec // test handler
	}))
	defer srv.Close()

	cfg := probe.Config{Client: srv.Client(), Timeout: 5 * time.Second, URLValidator: func(string) error { return nil }}
	p := probe.NewGraphQLProbe(cfg)

	endpoints := []classify.ClassifiedRequest{{
		ObservedRequest: crawl.ObservedRequest{Method: "POST", URL: srv.URL + "/graphql"},
		IsAPI:           true, APIType: "graphql",
	}}

	result, err := p.Probe(context.Background(), endpoints)
	if err != nil {
		t.Fatalf("Probe() error: %v", err)
	}

	schema := result[0].GraphQLSchema
	if schema == nil {
		t.Fatal("GraphQLSchema should not be nil")
	}
	if !schema.IntrospectionEnabled {
		t.Fatal("IntrospectionEnabled should be true")
	}

	// Root type names
	if schema.QueryTypeName != "Query" {
		t.Errorf("QueryTypeName = %q, want %q", schema.QueryTypeName, "Query")
	}
	if schema.MutationTypeName != "Mutation" {
		t.Errorf("MutationTypeName = %q, want %q", schema.MutationTypeName, "Mutation")
	}
	if schema.SubscriptionTypeName != "" {
		t.Errorf("SubscriptionTypeName = %q, want empty", schema.SubscriptionTypeName)
	}

	// Find types by name for assertions
	typeMap := make(map[string]classify.GraphQLType)
	for _, tt := range schema.Types {
		typeMap[tt.Name] = tt
	}

	// Query.user should have args
	query := typeMap["Query"]
	if len(query.Fields) != 3 {
		t.Fatalf("Query should have 3 fields, got %d", len(query.Fields))
	}
	userField := query.Fields[0]
	if userField.Name != "user" {
		t.Fatalf("first Query field = %q, want %q", userField.Name, "user")
	}
	if len(userField.Args) != 1 {
		t.Fatalf("user field should have 1 arg, got %d", len(userField.Args))
	}
	if userField.Args[0].Name != "id" {
		t.Errorf("user arg name = %q, want %q", userField.Args[0].Name, "id")
	}
	if userField.Args[0].Type.Kind != "NON_NULL" {
		t.Errorf("user arg type kind = %q, want NON_NULL", userField.Args[0].Type.Kind)
	}

	// Role enum values
	roleType := typeMap["Role"]
	if len(roleType.EnumValues) != 3 {
		t.Fatalf("Role should have 3 enum values, got %d", len(roleType.EnumValues))
	}
	if roleType.EnumValues[0].Name != "ADMIN" {
		t.Errorf("first enum value = %q, want ADMIN", roleType.EnumValues[0].Name)
	}
	if !roleType.EnumValues[2].IsDeprecated {
		t.Error("VIEWER should be deprecated")
	}

	// CreateUserInput input fields
	inputType := typeMap["CreateUserInput"]
	if len(inputType.InputFields) != 3 {
		t.Fatalf("CreateUserInput should have 3 input fields, got %d", len(inputType.InputFields))
	}
	if inputType.InputFields[0].Name != "name" {
		t.Errorf("first input field = %q, want name", inputType.InputFields[0].Name)
	}

	// User implements Node
	userType := typeMap["User"]
	if len(userType.Interfaces) != 1 {
		t.Fatalf("User should implement 1 interface, got %d", len(userType.Interfaces))
	}
	if userType.Interfaces[0].Name == nil || *userType.Interfaces[0].Name != "Node" {
		t.Error("User should implement Node")
	}

	// SearchResult union possible types
	searchResult := typeMap["SearchResult"]
	if len(searchResult.PossibleTypes) != 2 {
		t.Fatalf("SearchResult should have 2 possible types, got %d", len(searchResult.PossibleTypes))
	}
}

func TestGraphQLProbe_TieredFallback(t *testing.T) {
	var requestCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := requestCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		// Reject first two tiers with errors, succeed on tier 3
		if count <= 2 {
			w.Write([]byte(`{"errors":[{"message":"query too complex"}]}`)) //nolint:gosec // test handler
			return
		}
		w.Write([]byte(validIntrospectionResponse)) //nolint:gosec // test handler
	}))
	defer srv.Close()

	cfg := probe.Config{Client: srv.Client(), Timeout: 5 * time.Second, URLValidator: func(string) error { return nil }}
	p := probe.NewGraphQLProbe(cfg)

	endpoints := []classify.ClassifiedRequest{{
		ObservedRequest: crawl.ObservedRequest{Method: "POST", URL: srv.URL + "/graphql"},
		IsAPI:           true, APIType: "graphql",
	}}

	result, err := p.Probe(context.Background(), endpoints)
	if err != nil {
		t.Fatalf("Probe() error: %v", err)
	}

	if requestCount.Load() != 3 {
		t.Errorf("expected 3 requests (fallback through tiers), got %d", requestCount.Load())
	}

	schema := result[0].GraphQLSchema
	if schema == nil {
		t.Fatal("GraphQLSchema should not be nil after tier 3 fallback")
	}
	if !schema.IntrospectionEnabled {
		t.Error("IntrospectionEnabled should be true after successful tier 3")
	}
}

func TestGraphQLProbe_Tier1SucceedsImmediately(t *testing.T) {
	var requestCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(fullIntrospectionResponse)) //nolint:gosec // test handler
	}))
	defer srv.Close()

	cfg := probe.Config{Client: srv.Client(), Timeout: 5 * time.Second, URLValidator: func(string) error { return nil }}
	p := probe.NewGraphQLProbe(cfg)

	endpoints := []classify.ClassifiedRequest{{
		ObservedRequest: crawl.ObservedRequest{Method: "POST", URL: srv.URL + "/graphql"},
		IsAPI:           true, APIType: "graphql",
	}}

	result, err := p.Probe(context.Background(), endpoints)
	if err != nil {
		t.Fatalf("Probe() error: %v", err)
	}

	// Should succeed on first attempt, no fallback needed
	if requestCount.Load() != 1 {
		t.Errorf("expected 1 request (tier 1 success), got %d", requestCount.Load())
	}

	schema := result[0].GraphQLSchema
	if schema == nil {
		t.Fatal("GraphQLSchema should not be nil")
	}
	if schema.QueryTypeName != "Query" {
		t.Errorf("QueryTypeName = %q, want %q", schema.QueryTypeName, "Query")
	}
}
