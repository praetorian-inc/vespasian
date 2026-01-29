package openapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/praetorian-inc/vespasian/pkg/probes"
)

func TestOpenAPIProbe_Run(t *testing.T) {
	// Load test fixture
	swaggerData, err := os.ReadFile("../../../testdata/openapi/petstore-swagger2.json")
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}

	// Mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/swagger.json" {
			w.WriteHeader(http.StatusOK)
			w.Header().Set("Content-Type", "application/json")
			w.Write(swaggerData)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	probe := NewOpenAPIProbe(server.Client())

	// Create target from test server
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

	// Check for expected endpoint
	found := false
	for _, ep := range result.Endpoints {
		if ep.Path == "/pets" && ep.Method == "GET" {
			found = true
			break
		}
	}

	if !found {
		t.Error("Run() missing expected endpoint GET /pets")
	}
}

func TestOpenAPIProbe_Name(t *testing.T) {
	probe := NewOpenAPIProbe(&http.Client{})

	if probe.Name() != "openapi" {
		t.Errorf("Name() = %s, want openapi", probe.Name())
	}
}

func TestOpenAPIProbe_Category(t *testing.T) {
	probe := NewOpenAPIProbe(&http.Client{})

	if probe.Category() != probes.CategoryHTTP {
		t.Errorf("Category() = %s, want %s", probe.Category(), probes.CategoryHTTP)
	}
}

func TestOpenAPIProbe_Priority(t *testing.T) {
	probe := NewOpenAPIProbe(&http.Client{})

	if probe.Priority() != 50 {
		t.Errorf("Priority() = %d, want 50", probe.Priority())
	}
}

func TestOpenAPIProbe_Accepts(t *testing.T) {
	probe := NewOpenAPIProbe(&http.Client{})

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
			name: "accepts port 8080",
			port: 8080,
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
