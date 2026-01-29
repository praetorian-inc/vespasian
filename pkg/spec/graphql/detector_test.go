package graphql

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDetector_FindEndpoints(t *testing.T) {
	// Mock GraphQL server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/graphql" && r.Method == "POST" {
			w.WriteHeader(http.StatusOK)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"data":{"__schema":{"queryType":{"name":"Query"}}}}`))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	detector := NewDetector(server.Client())
	endpoints, err := detector.FindEndpoints(server.URL)
	if err != nil {
		t.Fatalf("FindEndpoints() error = %v", err)
	}

	if len(endpoints) == 0 {
		t.Error("FindEndpoints() returned no endpoints")
	}

	// Check if /graphql was found
	found := false
	for _, ep := range endpoints {
		if ep == server.URL+"/graphql" {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("FindEndpoints() missing expected endpoint %s/graphql", server.URL)
	}
}

func TestDetector_IsGraphQLResponse(t *testing.T) {
	detector := NewDetector(&http.Client{})

	tests := []struct {
		name    string
		body    []byte
		want    bool
	}{
		{
			name:    "detects GraphQL schema response",
			body:    []byte(`{"data":{"__schema":{"queryType":{"name":"Query"}}}}`),
			want:    true,
		},
		{
			name:    "detects GraphQL error response",
			body:    []byte(`{"errors":[{"message":"Query error"}]}`),
			want:    true,
		},
		{
			name:    "rejects non-GraphQL JSON",
			body:    []byte(`{"api":"custom","version":"1.0"}`),
			want:    false,
		},
		{
			name:    "rejects invalid JSON",
			body:    []byte(`not json`),
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detector.isGraphQLResponse(tt.body)
			if got != tt.want {
				t.Errorf("isGraphQLResponse() = %v, want %v", got, tt.want)
			}
		})
	}
}
