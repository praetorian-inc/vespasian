package js

import (
	"testing"
)

// TestParser_ExtractEndpoints tests basic endpoint extraction from JavaScript
func TestParser_ExtractEndpoints(t *testing.T) {
	tests := []struct {
		name     string
		jsSource string
		want     []Endpoint
	}{
		{
			name:     "extract fetch with string literal",
			jsSource: `fetch('/api/users');`,
			want: []Endpoint{
				{
					URL:        "/api/users",
					Method:     "GET",
					Source:     "fetch",
					Confidence: "high",
				},
			},
		},
		{
			name:     "extract multiple fetch calls",
			jsSource: `fetch('/api/users'); fetch('/api/posts', {method: 'POST'});`,
			want: []Endpoint{
				{
					URL:        "/api/users",
					Method:     "GET",
					Source:     "fetch",
					Confidence: "high",
				},
				{
					URL:        "/api/posts",
					Method:     "POST",
					Source:     "fetch",
					Confidence: "high",
				},
			},
		},
		{
			name:     "extract XMLHttpRequest",
			jsSource: `var xhr = new XMLHttpRequest(); xhr.open('GET', '/api/data');`,
			want: []Endpoint{
				{
					URL:        "/api/data",
					Method:     "GET",
					Source:     "xhr",
					Confidence: "high",
				},
			},
		},
		{
			name:     "extract axios calls",
			jsSource: `axios.get('/api/endpoint'); axios.post('/api/submit', data);`,
			want: []Endpoint{
				{
					URL:        "/api/endpoint",
					Method:     "GET",
					Source:     "axios",
					Confidence: "high",
				},
				{
					URL:        "/api/submit",
					Method:     "POST",
					Source:     "axios",
					Confidence: "high",
				},
			},
		},
		{
			name:     "extract string literals with URL patterns",
			jsSource: `const API_BASE = '/api/v1'; const endpoint = '/api/users/list';`,
			want: []Endpoint{
				{
					URL:        "/api/v1",
					Method:     "",
					Source:     "string_literal",
					Confidence: "low",
				},
				{
					URL:        "/api/users/list",
					Method:     "",
					Source:     "string_literal",
					Confidence: "low",
				},
			},
		},
		{
			name:     "extract template literals",
			jsSource: "fetch(`/api/users/${id}`);",
			want: []Endpoint{
				{
					URL:        "/api/users/",
					Method:     "GET",
					Source:     "fetch",
					Confidence: "medium",
				},
			},
		},
		{
			name:     "no endpoints in plain JS",
			jsSource: `function add(a, b) { return a + b; }`,
			want:     []Endpoint{},
		},
	}

	parser := NewParser()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parser.ExtractEndpoints(tt.jsSource)

			if len(got) != len(tt.want) {
				t.Errorf("ExtractEndpoints() got %d endpoints, want %d", len(got), len(tt.want))
				return
			}

			for i := range got {
				if got[i].URL != tt.want[i].URL {
					t.Errorf("Endpoint[%d].URL = %q, want %q", i, got[i].URL, tt.want[i].URL)
				}
				if got[i].Method != tt.want[i].Method {
					t.Errorf("Endpoint[%d].Method = %q, want %q", i, got[i].Method, tt.want[i].Method)
				}
				if got[i].Source != tt.want[i].Source {
					t.Errorf("Endpoint[%d].Source = %q, want %q", i, got[i].Source, tt.want[i].Source)
				}
				if got[i].Confidence != tt.want[i].Confidence {
					t.Errorf("Endpoint[%d].Confidence = %q, want %q", i, got[i].Confidence, tt.want[i].Confidence)
				}
			}
		})
	}
}
