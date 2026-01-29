package js

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
)

// Analyzer analyzes JavaScript files to extract API endpoints
type Analyzer struct {
	parser *Parser
}

// NewAnalyzer creates a new JS analyzer
func NewAnalyzer() *Analyzer {
	return &Analyzer{
		parser: NewParser(),
	}
}

// AnalyzeResponse processes an HTTP response to extract JS endpoints
func (a *Analyzer) AnalyzeResponse(resp *http.Response) ([]string, error) {
	// Only process JavaScript files
	ct := resp.Header.Get("Content-Type")
	if ct == "" {
		// Guess from URL
		if !isJSURL(resp.Request.URL.Path) {
			return nil, nil
		}
	} else if !isJavaScriptContentType(ct) {
		return nil, nil
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	// Restore body for other readers
	resp.Body = io.NopCloser(bytes.NewBuffer(body))

	// Extract endpoints
	endpoints := a.parser.ExtractEndpoints(string(body))

	// Convert to string URLs
	var urls []string
	for _, ep := range endpoints {
		urls = append(urls, ep.URL)
	}

	return urls, nil
}

func isJavaScriptContentType(ct string) bool {
	return bytes.Contains([]byte(ct), []byte("javascript")) ||
		bytes.Contains([]byte(ct), []byte("ecmascript"))
}

func isJSURL(path string) bool {
	return len(path) >= 3 && path[len(path)-3:] == ".js"
}
