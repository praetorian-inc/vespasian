package openapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// Detector finds OpenAPI/Swagger spec locations
type Detector struct {
	client *http.Client
}

// NewDetector creates a new OpenAPI detector
func NewDetector(client *http.Client) *Detector {
	return &Detector{client: client}
}

// Common OpenAPI spec paths
var commonPaths = []string{
	"/swagger.json",
	"/openapi.json",
	"/api-docs",
	"/v2/api-docs",
	"/v3/api-docs",
	"/swagger.yaml",
	"/openapi.yaml",
	"/swagger/v1/swagger.json",
	"/api/swagger.json",
	"/api/openapi.json",
}

// FindSpecLocations probes common paths for OpenAPI specs
func (d *Detector) FindSpecLocations(baseURL string) ([]string, error) {
	var locations []string

	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	for _, path := range commonPaths {
		testURL := parsedURL.ResolveReference(&url.URL{Path: path}).String()

		req, err := http.NewRequest("GET", testURL, nil)
		if err != nil {
			continue
		}

		resp, err := d.client.Do(req)
		if err != nil {
			continue
		}

		if resp.StatusCode == http.StatusOK {
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()

			if err == nil && d.DetectByContent(body) {
				locations = append(locations, testURL)
			}
		} else {
			resp.Body.Close()
		}
	}

	return locations, nil
}

// DetectByContent checks if content looks like an OpenAPI spec
func (d *Detector) DetectByContent(content []byte) bool {
	var spec map[string]interface{}
	if err := json.Unmarshal(content, &spec); err != nil {
		return false
	}

	// Check for OpenAPI 3.x
	if _, ok := spec["openapi"]; ok {
		return true
	}

	// Check for Swagger 2.0
	if _, ok := spec["swagger"]; ok {
		return true
	}

	return false
}
