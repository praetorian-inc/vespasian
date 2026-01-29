package openapi

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/praetorian-inc/vespasian/pkg/probes"
	"github.com/praetorian-inc/vespasian/pkg/registry"
)

func init() {
	probes.Registry.Register("openapi", func(cfg registry.Config) (probes.Probe, error) {
		client := &http.Client{}

		// Allow custom HTTP client from config
		if c, ok := cfg["client"].(*http.Client); ok {
			client = c
		}

		return NewOpenAPIProbe(client), nil
	})
}

// OpenAPIProbe implements probes.Probe for OpenAPI/Swagger spec discovery
type OpenAPIProbe struct {
	detector *Detector
	parser   *Parser
}

// NewOpenAPIProbe creates a new OpenAPI probe
func NewOpenAPIProbe(client *http.Client) *OpenAPIProbe {
	return &OpenAPIProbe{
		detector: NewDetector(client),
		parser:   NewParser(),
	}
}

// Name returns the probe name
func (p *OpenAPIProbe) Name() string {
	return "openapi"
}

// Category returns the probe category
func (p *OpenAPIProbe) Category() probes.ProbeCategory {
	return probes.CategoryHTTP
}

// Priority returns execution priority (higher = earlier)
func (p *OpenAPIProbe) Priority() int {
	return 50 // Medium priority - after protocol detection, before crawling
}

// Accepts returns true if probe can scan the target
func (p *OpenAPIProbe) Accepts(target probes.Target) bool {
	// Accept HTTP/HTTPS targets
	switch target.Port {
	case 80, 443, 8080, 8443, 3000, 5000:
		return true
	default:
		return false
	}
}

// Run executes the OpenAPI probe
func (p *OpenAPIProbe) Run(ctx context.Context, target probes.Target, opts probes.ProbeOptions) (*probes.ProbeResult, error) {
	// Build base URL
	baseURL, err := buildBaseURL(target)
	if err != nil {
		return &probes.ProbeResult{
			ProbeCategory: p.Category(),
			Success:       false,
			Error:         err,
		}, err
	}

	// Find OpenAPI spec locations
	locations, err := p.detector.FindSpecLocations(baseURL)
	if err != nil {
		return &probes.ProbeResult{
			ProbeCategory: p.Category(),
			Success:       false,
			Error:         err,
		}, err
	}

	if len(locations) == 0 {
		return &probes.ProbeResult{
			ProbeCategory: p.Category(),
			Success:       false,
			Error:         fmt.Errorf("no OpenAPI specs found"),
		}, nil
	}

	// Parse first found spec
	// TODO: In production, might want to parse all found specs
	specURL := locations[0]

	resp, err := http.Get(specURL)
	if err != nil {
		return &probes.ProbeResult{
			ProbeCategory: p.Category(),
			Success:       false,
			Error:         err,
		}, err
	}
	defer resp.Body.Close()

	// Read spec content
	var specData []byte
	if resp.StatusCode == http.StatusOK {
		specData = make([]byte, resp.ContentLength)
		_, err = resp.Body.Read(specData)
		if err != nil && err.Error() != "EOF" {
			return &probes.ProbeResult{
				ProbeCategory: p.Category(),
				Success:       false,
				Error:         err,
			}, err
		}
	}

	// Parse spec
	apiEndpoints, err := p.parser.ParseSpec(specData)
	if err != nil {
		return &probes.ProbeResult{
			ProbeCategory: p.Category(),
			Success:       false,
			Error:         err,
		}, err
	}

	// Convert to probes.APIEndpoint
	endpoints := make([]probes.APIEndpoint, len(apiEndpoints))
	for i, ep := range apiEndpoints {
		endpoints[i] = probes.APIEndpoint{
			Path:   ep.Path,
			Method: ep.Method,
		}
	}

	return &probes.ProbeResult{
		ProbeCategory: p.Category(),
		Success:       true,
		Endpoints:     endpoints,
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
