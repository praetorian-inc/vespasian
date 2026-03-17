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
		w.Write([]byte(validIntrospectionResponse))
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
		w.Write([]byte(`{"errors":[{"message":"introspection is disabled"}]}`))
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
		w.Write([]byte(validIntrospectionResponse))
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
		w.Write([]byte(validIntrospectionResponse))
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
		w.Write([]byte(validIntrospectionResponse))
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
		w.Write([]byte(`{not valid json`))
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
