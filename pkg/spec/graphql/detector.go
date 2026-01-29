package graphql

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// Detector finds GraphQL endpoints
type Detector struct {
	client *http.Client
}

// NewDetector creates a new GraphQL detector
func NewDetector(client *http.Client) *Detector {
	return &Detector{client: client}
}

// Common GraphQL paths
var commonPaths = []string{
	"/graphql",
	"/graphiql",
	"/playground",
	"/api/graphql",
	"/v1/graphql",
	"/query",
	"/gql",
}

// Introspection query to check if GraphQL introspection is enabled
const introspectionQuery = `{"query":"{ __schema { queryType { name } } }"}`

// FindEndpoints probes common paths for GraphQL endpoints
func (d *Detector) FindEndpoints(baseURL string) ([]string, error) {
	var endpoints []string

	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	for _, path := range commonPaths {
		testURL := parsedURL.ResolveReference(&url.URL{Path: path}).String()

		// Test with introspection query
		if d.testIntrospection(testURL) {
			endpoints = append(endpoints, testURL)
		}
	}

	return endpoints, nil
}

// testIntrospection tests if a URL supports GraphQL introspection
func (d *Detector) testIntrospection(url string) bool {
	req, err := http.NewRequest("POST", url, bytes.NewBufferString(introspectionQuery))
	if err != nil {
		return false
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}

	return d.isGraphQLResponse(body)
}

// isGraphQLResponse checks if response looks like a GraphQL response
func (d *Detector) isGraphQLResponse(body []byte) bool {
	var response map[string]interface{}
	if err := json.Unmarshal(body, &response); err != nil {
		return false
	}

	// Check for GraphQL response structure
	if data, ok := response["data"].(map[string]interface{}); ok {
		if _, ok := data["__schema"]; ok {
			return true
		}
	}

	// Check for GraphQL error structure
	if errors, ok := response["errors"].([]interface{}); ok && len(errors) > 0 {
		return true
	}

	return false
}
