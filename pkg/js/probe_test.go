package js

import (
	"bytes"
	"io"
	"net/http"
	"testing"
)

func TestAnalyzer_AnalyzeResponse(t *testing.T) {
	analyzer := NewAnalyzer()

	tests := []struct {
		name        string
		contentType string
		url         string
		body        string
		wantCount   int
	}{
		{
			name:        "extract from JS content-type",
			contentType: "application/javascript",
			url:         "https://example.com/app.js",
			body:        "fetch('/api/users'); axios.get('/api/posts');",
			wantCount:   2,
		},
		{
			name:        "extract from .js URL",
			contentType: "",
			url:         "https://example.com/bundle.js",
			body:        "fetch('/api/data');",
			wantCount:   1,
		},
		{
			name:        "skip non-JS content",
			contentType: "text/html",
			url:         "https://example.com/index.html",
			body:        "fetch('/api/users');",
			wantCount:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", tt.url, nil)
			resp := &http.Response{
				StatusCode: 200,
				Header:     http.Header{"Content-Type": []string{tt.contentType}},
				Body:       io.NopCloser(bytes.NewBufferString(tt.body)),
				Request:    req,
			}

			urls, err := analyzer.AnalyzeResponse(resp)
			if err != nil {
				t.Fatalf("AnalyzeResponse() error = %v", err)
			}

			if len(urls) != tt.wantCount {
				t.Errorf("AnalyzeResponse() got %d URLs, want %d", len(urls), tt.wantCount)
			}
		})
	}
}
