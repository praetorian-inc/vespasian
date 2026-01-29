package openapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDetector_FindSpecLocations(t *testing.T) {
	tests := []struct {
		name     string
		baseURL  string
		mockPath string
		want     []string
	}{
		{
			name:     "finds swagger.json",
			baseURL:  "http://example.com",
			mockPath: "/swagger.json",
			want:     []string{"http://example.com/swagger.json"},
		},
		{
			name:     "finds openapi.json",
			baseURL:  "http://example.com",
			mockPath: "/openapi.json",
			want:     []string{"http://example.com/openapi.json"},
		},
		{
			name:     "finds api-docs",
			baseURL:  "http://example.com",
			mockPath: "/api-docs",
			want:     []string{"http://example.com/api-docs"},
		},
		{
			name:     "finds v2/api-docs",
			baseURL:  "http://example.com",
			mockPath: "/v2/api-docs",
			want:     []string{"http://example.com/v2/api-docs"},
		},
		{
			name:     "finds v3/api-docs",
			baseURL:  "http://example.com",
			mockPath: "/v3/api-docs",
			want:     []string{"http://example.com/v3/api-docs"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock server that returns 200 for the expected path
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == tt.mockPath {
					w.WriteHeader(http.StatusOK)
					w.Header().Set("Content-Type", "application/json")
					w.Write([]byte(`{"swagger": "2.0"}`))
				} else {
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()

			detector := NewDetector(server.Client())
			got, err := detector.FindSpecLocations(server.URL)
			if err != nil {
				t.Fatalf("FindSpecLocations() error = %v", err)
			}

			if len(got) == 0 {
				t.Errorf("FindSpecLocations() returned no locations")
			}

			// Check if expected path is in results
			found := false
			for _, loc := range got {
				if loc == server.URL+tt.mockPath {
					found = true
					break
				}
			}

			if !found {
				t.Errorf("FindSpecLocations() = %v, want to include %v", got, server.URL+tt.mockPath)
			}
		})
	}
}

func TestDetector_DetectByContent(t *testing.T) {
	tests := []struct {
		name    string
		content []byte
		want    bool
	}{
		{
			name:    "detects swagger 2.0",
			content: []byte(`{"swagger": "2.0", "info": {}}`),
			want:    true,
		},
		{
			name:    "detects openapi 3.0",
			content: []byte(`{"openapi": "3.0.0", "info": {}}`),
			want:    true,
		},
		{
			name:    "rejects non-openapi json",
			content: []byte(`{"api": "custom", "version": "1.0"}`),
			want:    false,
		},
		{
			name:    "rejects invalid json",
			content: []byte(`not json`),
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detector := NewDetector(&http.Client{})
			got := detector.DetectByContent(tt.content)
			if got != tt.want {
				t.Errorf("DetectByContent() = %v, want %v", got, tt.want)
			}
		})
	}
}
