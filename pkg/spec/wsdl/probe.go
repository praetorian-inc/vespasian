package wsdl

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/praetorian-inc/vespasian/pkg/probes"
	"github.com/praetorian-inc/vespasian/pkg/registry"
)

func init() {
	probes.Registry.Register("wsdl", func(cfg registry.Config) (probes.Probe, error) {
		client := &http.Client{}

		// Allow custom HTTP client from config
		if c, ok := cfg["client"].(*http.Client); ok {
			client = c
		}

		return NewWSDLProbe(client), nil
	})
}

// WSDLProbe implements probes.Probe for WSDL/SOAP service discovery
type WSDLProbe struct {
	client *http.Client
	parser *Parser
	paths  []string
}

// NewWSDLProbe creates a new WSDL probe
func NewWSDLProbe(client *http.Client) *WSDLProbe {
	return &WSDLProbe{
		client: client,
		parser: NewParser(),
		paths: []string{
			"?wsdl",
			"/services?wsdl",
			"/*.asmx?wsdl",
			"/calculator.wsdl",
			"/service.wsdl",
		},
	}
}

// Name returns the probe name
func (p *WSDLProbe) Name() string {
	return "wsdl"
}

// Category returns the probe category
func (p *WSDLProbe) Category() probes.ProbeCategory {
	return probes.CategoryHTTP
}

// Priority returns execution priority (higher = earlier)
func (p *WSDLProbe) Priority() int {
	return 50 // Medium priority
}

// Accepts returns true if probe can scan the target
func (p *WSDLProbe) Accepts(target probes.Target) bool {
	// Accept HTTP/HTTPS targets
	switch target.Port {
	case 80, 443, 8080, 8443, 3000, 5000:
		return true
	default:
		return false
	}
}

// Run executes the WSDL probe
func (p *WSDLProbe) Run(ctx context.Context, target probes.Target, opts probes.ProbeOptions) (*probes.ProbeResult, error) {
	baseURL, err := buildBaseURL(target)
	if err != nil {
		return &probes.ProbeResult{
			ProbeCategory: p.Category(),
			Success:       false,
			Error:         err,
		}, err
	}

	// Try to find WSDL documents
	var wsdlData []byte
	var foundPath string

	for _, path := range p.paths {
		fullURL := baseURL + path
		resp, err := p.client.Get(fullURL)
		if err != nil {
			continue
		}

		if resp.StatusCode == http.StatusOK {
			data, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				continue
			}

			// Check if it's valid WSDL
			if isWSDL(data) {
				wsdlData = data
				foundPath = path
				break
			}
		} else {
			resp.Body.Close()
		}
	}

	if wsdlData == nil {
		return &probes.ProbeResult{
			ProbeCategory: p.Category(),
			Success:       false,
			Error:         fmt.Errorf("no WSDL found"),
		}, nil
	}

	// Parse WSDL
	defs, err := p.parser.ParseWSDL(wsdlData)
	if err != nil {
		return &probes.ProbeResult{
			ProbeCategory: p.Category(),
			Success:       false,
			Error:         err,
		}, err
	}

	// Convert operations to endpoints
	endpoints := make([]probes.APIEndpoint, 0, len(defs.Operations))
	for _, op := range defs.Operations {
		endpoints = append(endpoints, probes.APIEndpoint{
			Path:   foundPath + "/" + op.Name,
			Method: "POST", // SOAP operations are typically POST
		})
	}

	return &probes.ProbeResult{
		ProbeCategory: p.Category(),
		Success:       true,
		Endpoints:     endpoints,
	}, nil
}

// isWSDL checks if data appears to be a WSDL document
func isWSDL(data []byte) bool {
	// Simple heuristic: check for WSDL namespace
	content := string(data)
	return len(content) > 0 &&
		(contains(content, "wsdl:definitions") ||
		 contains(content, "definitions") && contains(content, "xmlns"))
}

// contains checks if s contains substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr || len(s) > len(substr) && findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
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
