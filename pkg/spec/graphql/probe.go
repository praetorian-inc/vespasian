package graphql

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/praetorian-inc/vespasian/pkg/probes"
	"github.com/praetorian-inc/vespasian/pkg/registry"
)

func init() {
	probes.Registry.Register("graphql", func(cfg registry.Config) (probes.Probe, error) {
		client := &http.Client{}

		// Allow custom HTTP client from config
		if c, ok := cfg["client"].(*http.Client); ok {
			client = c
		}

		return NewGraphQLProbe(client), nil
	})
}

// GraphQLProbe implements probes.Probe for GraphQL endpoint discovery
type GraphQLProbe struct {
	detector *Detector
	parser   *Parser
	client   *http.Client
}

// NewGraphQLProbe creates a new GraphQL probe
func NewGraphQLProbe(client *http.Client) *GraphQLProbe {
	return &GraphQLProbe{
		detector: NewDetector(client),
		parser:   NewParser(),
		client:   client,
	}
}

// Name returns the probe name
func (p *GraphQLProbe) Name() string {
	return "graphql"
}

// Category returns the probe category
func (p *GraphQLProbe) Category() probes.ProbeCategory {
	return probes.CategoryHTTP
}

// Priority returns execution priority (higher = earlier)
func (p *GraphQLProbe) Priority() int {
	return 45 // Slightly lower than OpenAPI
}

// Accepts returns true if probe can scan the target
func (p *GraphQLProbe) Accepts(target probes.Target) bool {
	// Accept HTTP/HTTPS targets
	switch target.Port {
	case 80, 443, 8080, 8443, 3000, 4000, 5000:
		return true
	default:
		return false
	}
}

// Run executes the GraphQL probe
func (p *GraphQLProbe) Run(ctx context.Context, target probes.Target, opts probes.ProbeOptions) (*probes.ProbeResult, error) {
	// Build base URL
	baseURL, err := buildBaseURL(target)
	if err != nil {
		return &probes.ProbeResult{
			ProbeCategory: p.Category(),
			Success:       false,
			Error:         err,
		}, err
	}

	// Find GraphQL endpoints
	endpoints, err := p.detector.FindEndpoints(baseURL)
	if err != nil {
		return &probes.ProbeResult{
			ProbeCategory: p.Category(),
			Success:       false,
			Error:         err,
		}, err
	}

	if len(endpoints) == 0 {
		return &probes.ProbeResult{
			ProbeCategory: p.Category(),
			Success:       false,
			Error:         fmt.Errorf("no GraphQL endpoints found"),
		}, nil
	}

	// Perform introspection on first endpoint
	graphqlURL := endpoints[0]

	introspectionQuery := `{
		"query": "{ __schema { queryType { name } mutationType { name } types { kind name fields { name args { name type { name kind ofType { name kind } } } } } } }"
	}`

	req, err := http.NewRequest("POST", graphqlURL, bytes.NewBufferString(introspectionQuery))
	if err != nil {
		return &probes.ProbeResult{
			ProbeCategory: p.Category(),
			Success:       false,
			Error:         err,
		}, err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return &probes.ProbeResult{
			ProbeCategory: p.Category(),
			Success:       false,
			Error:         err,
		}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return &probes.ProbeResult{
			ProbeCategory: p.Category(),
			Success:       false,
			Error:         fmt.Errorf("introspection failed with status %d", resp.StatusCode),
		}, nil
	}

	introspectionData, err := io.ReadAll(resp.Body)
	if err != nil {
		return &probes.ProbeResult{
			ProbeCategory: p.Category(),
			Success:       false,
			Error:         err,
		}, err
	}

	// Parse introspection response
	apiEndpoints, err := p.parser.ParseIntrospection(introspectionData)
	if err != nil {
		return &probes.ProbeResult{
			ProbeCategory: p.Category(),
			Success:       false,
			Error:         err,
		}, err
	}

	// Convert to probes.APIEndpoint
	// GraphQL operations are POST requests to the endpoint
	resultEndpoints := make([]probes.APIEndpoint, len(apiEndpoints))
	for i, ep := range apiEndpoints {
		// Format as "operationType.operationName" for clarity
		resultEndpoints[i] = probes.APIEndpoint{
			Path:   fmt.Sprintf("%s.%s", ep.Type, ep.Name),
			Method: "POST",
		}
	}

	return &probes.ProbeResult{
		ProbeCategory: p.Category(),
		Success:       true,
		Endpoints:     resultEndpoints,
	}, nil
}

// buildBaseURL constructs base URL from target
func buildBaseURL(target probes.Target) (string, error) {
	// Handle case where Host is already a full URL (from httptest)
	if parsed, err := url.Parse(target.Host); err == nil {
		if parsed.Scheme == "http" || parsed.Scheme == "https" {
			return target.Host, nil
		}
	}

	scheme := "http"
	if target.Port == 443 || target.Port == 8443 {
		scheme = "https"
	}

	return fmt.Sprintf("%s://%s:%d", scheme, target.Host, target.Port), nil
}
