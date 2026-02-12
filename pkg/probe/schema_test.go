package probe_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/praetorian-inc/vespasian/pkg/classify"
	"github.com/praetorian-inc/vespasian/pkg/crawl"
	"github.com/praetorian-inc/vespasian/pkg/probe"
)

func TestSchemaProbe_Name(t *testing.T) {
	p := probe.NewSchemaProbe(probe.DefaultConfig())
	if p.Name() != "schema" {
		t.Errorf("Name() = %q, want %q", p.Name(), "schema")
	}
}

func TestSchemaProbe_InfersObjectSchema(t *testing.T) {
	respBody := map[string]interface{}{
		"id":     1,
		"name":   "Alice",
		"active": true,
		"score":  3.14,
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(respBody); err != nil {
			t.Errorf("encode response: %v", err)
		}
	}))
	defer srv.Close()

	cfg := probe.Config{Client: srv.Client(), Timeout: 5 * time.Second}
	p := probe.NewSchemaProbe(cfg)

	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "GET",
				URL:    srv.URL + "/api/users/1",
				Response: crawl.ObservedResponse{
					ContentType: "application/json",
				},
			},
			IsAPI: true,
		},
	}

	result, err := p.Probe(context.Background(), endpoints)
	if err != nil {
		t.Fatalf("Probe() error: %v", err)
	}

	schema := result[0].ResponseSchema
	if schema == nil {
		t.Fatal("ResponseSchema is nil")
	}

	if schema["type"] != "object" {
		t.Errorf("schema type: got %v, want object", schema["type"])
	}

	props, ok := schema["properties"].(map[string]interface{})
	if !ok {
		t.Fatal("schema properties missing or wrong type")
	}

	checks := map[string]string{
		"id":     "number",
		"name":   "string",
		"active": "boolean",
		"score":  "number",
	}
	for field, wantType := range checks {
		prop, ok := props[field].(map[string]interface{})
		if !ok {
			t.Errorf("property %q missing", field)
			continue
		}
		if prop["type"] != wantType {
			t.Errorf("property %q type: got %v, want %v", field, prop["type"], wantType)
		}
	}
}

func TestSchemaProbe_InfersArraySchema(t *testing.T) {
	respBody := []map[string]interface{}{
		{"id": 1, "name": "Alice"},
		{"id": 2, "name": "Bob"},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(respBody); err != nil {
			t.Errorf("encode response: %v", err)
		}
	}))
	defer srv.Close()

	cfg := probe.Config{Client: srv.Client(), Timeout: 5 * time.Second}
	p := probe.NewSchemaProbe(cfg)

	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "GET",
				URL:    srv.URL + "/api/users",
				Response: crawl.ObservedResponse{
					ContentType: "application/json",
				},
			},
			IsAPI: true,
		},
	}

	result, err := p.Probe(context.Background(), endpoints)
	if err != nil {
		t.Fatalf("Probe() error: %v", err)
	}

	schema := result[0].ResponseSchema
	if schema["type"] != "array" {
		t.Errorf("schema type: got %v, want array", schema["type"])
	}

	items, ok := schema["items"].(map[string]interface{})
	if !ok {
		t.Fatal("schema items missing")
	}
	if items["type"] != "object" {
		t.Errorf("items type: got %v, want object", items["type"])
	}
}

func TestSchemaProbe_SkipsNonJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if _, err := w.Write([]byte("<html>not json</html>")); err != nil {
			t.Errorf("write response: %v", err)
		}
	}))
	defer srv.Close()

	cfg := probe.Config{Client: srv.Client(), Timeout: 5 * time.Second}
	p := probe.NewSchemaProbe(cfg)

	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "GET",
				URL:    srv.URL + "/page",
				Response: crawl.ObservedResponse{
					ContentType: "text/html",
				},
			},
			IsAPI: true,
		},
	}

	result, err := p.Probe(context.Background(), endpoints)
	if err != nil {
		t.Fatalf("Probe() error: %v", err)
	}

	if result[0].ResponseSchema != nil {
		t.Errorf("expected nil schema for non-JSON, got %v", result[0].ResponseSchema)
	}
}

func TestSchemaProbe_InjectsAuthHeaders(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]string{"status": "ok"}); err != nil {
			t.Errorf("encode response: %v", err)
		}
	}))
	defer srv.Close()

	cfg := probe.Config{
		Client:      srv.Client(),
		Timeout:     5 * time.Second,
		AuthHeaders: map[string]string{"Authorization": "Bearer schema-token"},
	}
	p := probe.NewSchemaProbe(cfg)

	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				URL:      srv.URL + "/api/status",
				Response: crawl.ObservedResponse{ContentType: "application/json"},
			},
			IsAPI: true,
		},
	}

	_, err := p.Probe(context.Background(), endpoints)
	if err != nil {
		t.Fatalf("Probe() error: %v", err)
	}

	if gotAuth != "Bearer schema-token" {
		t.Errorf("auth header: got %q, want %q", gotAuth, "Bearer schema-token")
	}
}

func TestSchemaProbe_HandlesNestedObjects(t *testing.T) {
	respBody := map[string]interface{}{
		"user": map[string]interface{}{
			"name":  "Alice",
			"email": "alice@example.com",
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(respBody); err != nil {
			t.Errorf("encode response: %v", err)
		}
	}))
	defer srv.Close()

	cfg := probe.Config{Client: srv.Client(), Timeout: 5 * time.Second}
	p := probe.NewSchemaProbe(cfg)

	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				URL:      srv.URL + "/api/profile",
				Response: crawl.ObservedResponse{ContentType: "application/json"},
			},
			IsAPI: true,
		},
	}

	result, err := p.Probe(context.Background(), endpoints)
	if err != nil {
		t.Fatalf("Probe() error: %v", err)
	}

	schema := result[0].ResponseSchema
	props := schema["properties"].(map[string]interface{})
	userProp := props["user"].(map[string]interface{})
	if userProp["type"] != "object" {
		t.Errorf("nested user type: got %v, want object", userProp["type"])
	}
}

func TestSchemaProbe_DeduplicatesByURL(t *testing.T) {
	var requestCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]string{"status": "ok"}); err != nil {
			t.Errorf("encode response: %v", err)
		}
	}))
	defer srv.Close()

	cfg := probe.Config{Client: srv.Client(), Timeout: 5 * time.Second}
	p := probe.NewSchemaProbe(cfg)

	endpoints := []classify.ClassifiedRequest{
		{ObservedRequest: crawl.ObservedRequest{Method: "GET", URL: srv.URL + "/api/users", Response: crawl.ObservedResponse{ContentType: "application/json"}}, IsAPI: true},
		{ObservedRequest: crawl.ObservedRequest{Method: "POST", URL: srv.URL + "/api/users", Response: crawl.ObservedResponse{ContentType: "application/json"}}, IsAPI: true},
	}

	result, err := p.Probe(context.Background(), endpoints)
	if err != nil {
		t.Fatalf("Probe() error: %v", err)
	}

	if requestCount.Load() != 1 {
		t.Errorf("expected 1 GET request (deduplicated), got %d", requestCount.Load())
	}

	for i, ep := range result {
		if ep.ResponseSchema == nil {
			t.Errorf("endpoint[%d].ResponseSchema: got nil, want non-nil", i)
		}
	}
}

func TestSchemaProbe_InferSchemaMaxDepth(t *testing.T) {
	// Build deeply nested JSON: {"a":{"a":{"a":...}}} to 100 levels
	var nested interface{} = map[string]interface{}{"leaf": "value"}
	for i := 0; i < 100; i++ {
		nested = map[string]interface{}{"a": nested}
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(nested); err != nil {
			t.Errorf("encode response: %v", err)
		}
	}))
	defer srv.Close()

	cfg := probe.Config{Client: srv.Client(), Timeout: 5 * time.Second}
	p := probe.NewSchemaProbe(cfg)

	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				URL:      srv.URL + "/api/deep",
				Response: crawl.ObservedResponse{ContentType: "application/json"},
			},
			IsAPI: true,
		},
	}

	// Should not panic or stack overflow - should complete gracefully
	result, err := p.Probe(context.Background(), endpoints)
	if err != nil {
		t.Fatalf("Probe() error: %v", err)
	}

	if result[0].ResponseSchema == nil {
		t.Fatal("ResponseSchema should not be nil for valid JSON")
	}

	// The schema should exist and have type "object" at the top level
	if result[0].ResponseSchema["type"] != "object" {
		t.Errorf("top-level type: got %v, want object", result[0].ResponseSchema["type"])
	}
}
