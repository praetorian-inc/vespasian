package openapi

import (
	"os"
	"testing"
)

func TestParser_ParseSpec(t *testing.T) {
	tests := []struct {
		name         string
		fixture      string
		wantPaths    int
		wantEndpoint string
		wantMethod   string
	}{
		{
			name:         "parses swagger 2.0",
			fixture:      "../../../testdata/openapi/petstore-swagger2.json",
			wantPaths:    2,
			wantEndpoint: "/pets",
			wantMethod:   "GET",
		},
		{
			name:         "parses openapi 3.0",
			fixture:      "../../../testdata/openapi/petstore-openapi3.yaml",
			wantPaths:    2,
			wantEndpoint: "/pets",
			wantMethod:   "POST",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := os.ReadFile(tt.fixture)
			if err != nil {
				t.Fatalf("failed to read fixture: %v", err)
			}

			parser := NewParser()
			endpoints, err := parser.ParseSpec(data)
			if err != nil {
				t.Fatalf("ParseSpec() error = %v", err)
			}

			if len(endpoints) == 0 {
				t.Error("ParseSpec() returned no endpoints")
			}

			// Verify endpoint exists
			found := false
			for _, ep := range endpoints {
				if ep.Path == tt.wantEndpoint && ep.Method == tt.wantMethod {
					found = true
					break
				}
			}

			if !found {
				t.Errorf("ParseSpec() missing endpoint %s %s", tt.wantMethod, tt.wantEndpoint)
			}
		})
	}
}

func TestParser_ExtractEndpoints(t *testing.T) {
	tests := []struct {
		name      string
		fixture   string
		wantCount int
		wantPaths []string
	}{
		{
			name:      "extracts all endpoints from swagger 2.0",
			fixture:   "../../../testdata/openapi/petstore-swagger2.json",
			wantCount: 3, // GET /pets, POST /pets, GET /pets/{petId}
			wantPaths: []string{"/pets", "/pets", "/pets/{petId}"},
		},
		{
			name:      "extracts all endpoints from openapi 3.0",
			fixture:   "../../../testdata/openapi/petstore-openapi3.yaml",
			wantCount: 3,
			wantPaths: []string{"/pets", "/pets", "/pets/{petId}"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := os.ReadFile(tt.fixture)
			if err != nil {
				t.Fatalf("failed to read fixture: %v", err)
			}

			parser := NewParser()
			endpoints, err := parser.ParseSpec(data)
			if err != nil {
				t.Fatalf("ParseSpec() error = %v", err)
			}

			if len(endpoints) != tt.wantCount {
				t.Errorf("ParseSpec() returned %d endpoints, want %d", len(endpoints), tt.wantCount)
			}
		})
	}
}

func TestEndpoint_Parameters(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/openapi/petstore-swagger2.json")
	if err != nil {
		t.Fatalf("failed to read fixture: %v", err)
	}

	parser := NewParser()
	endpoints, err := parser.ParseSpec(data)
	if err != nil {
		t.Fatalf("ParseSpec() error = %v", err)
	}

	// Find GET /pets which has a limit parameter
	var getPets *APIEndpoint
	for i := range endpoints {
		if endpoints[i].Path == "/pets" && endpoints[i].Method == "GET" {
			getPets = &endpoints[i]
			break
		}
	}

	if getPets == nil {
		t.Fatal("GET /pets endpoint not found")
	}

	if len(getPets.Parameters) == 0 {
		t.Error("GET /pets should have parameters")
	}

	// Check for limit parameter
	hasLimit := false
	for _, param := range getPets.Parameters {
		if param.Name == "limit" {
			hasLimit = true
			if param.In != "query" {
				t.Errorf("limit parameter In = %s, want query", param.In)
			}
			break
		}
	}

	if !hasLimit {
		t.Error("GET /pets missing limit parameter")
	}
}
