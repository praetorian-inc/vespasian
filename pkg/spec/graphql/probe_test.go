package graphql

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/praetorian-inc/vespasian/pkg/probes"
)

func TestGraphQLProbe_Run(t *testing.T) {
	// Load introspection fixture
	introspectionData, err := os.ReadFile("../../../testdata/graphql/introspection-response.json")
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}

	// Mock GraphQL server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/graphql" && r.Method == "POST" {
			w.WriteHeader(http.StatusOK)
			w.Header().Set("Content-Type", "application/json")
			w.Write(introspectionData)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	probe := NewGraphQLProbe(server.Client())

	target := probes.Target{
		Host: server.URL,
		Port: 80,
	}

	result, err := probe.Run(context.Background(), target, probes.ProbeOptions{})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if !result.Success {
		t.Error("Run() success = false, want true")
	}

	if len(result.Endpoints) == 0 {
		t.Error("Run() returned no endpoints")
	}

	// Check for expected operations
	foundQuery := false
	foundMutation := false
	for _, ep := range result.Endpoints {
		if ep.Path == "query.user" || ep.Path == "query.users" {
			foundQuery = true
		}
		if ep.Path == "mutation.createUser" || ep.Path == "mutation.updateUser" {
			foundMutation = true
		}
	}

	if !foundQuery {
		t.Error("Run() missing expected query operations")
	}

	if !foundMutation {
		t.Error("Run() missing expected mutation operations")
	}
}

func TestGraphQLProbe_Name(t *testing.T) {
	probe := NewGraphQLProbe(&http.Client{})

	if probe.Name() != "graphql" {
		t.Errorf("Name() = %s, want graphql", probe.Name())
	}
}

func TestGraphQLProbe_Category(t *testing.T) {
	probe := NewGraphQLProbe(&http.Client{})

	if probe.Category() != probes.CategoryHTTP {
		t.Errorf("Category() = %s, want %s", probe.Category(), probes.CategoryHTTP)
	}
}

func TestGraphQLProbe_Priority(t *testing.T) {
	probe := NewGraphQLProbe(&http.Client{})

	if probe.Priority() != 45 {
		t.Errorf("Priority() = %d, want 45", probe.Priority())
	}
}

func TestGraphQLProbe_Accepts(t *testing.T) {
	probe := NewGraphQLProbe(&http.Client{})

	tests := []struct {
		name string
		port int
		want bool
	}{
		{
			name: "accepts port 80",
			port: 80,
			want: true,
		},
		{
			name: "accepts port 443",
			port: 443,
			want: true,
		},
		{
			name: "accepts port 4000",
			port: 4000,
			want: true,
		},
		{
			name: "rejects port 22",
			port: 22,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := probes.Target{Port: tt.port}
			if got := probe.Accepts(target); got != tt.want {
				t.Errorf("Accepts(%d) = %v, want %v", tt.port, got, tt.want)
			}
		})
	}
}
