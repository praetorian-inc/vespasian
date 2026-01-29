package openapi

import (
	"fmt"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

// APIEndpoint represents a discovered API endpoint
type APIEndpoint struct {
	Path       string
	Method     string
	Parameters []Parameter
}

// Parameter represents an endpoint parameter
type Parameter struct {
	Name     string
	In       string
	Required bool
	Type     string
}

// Parser parses OpenAPI specifications
type Parser struct{}

// NewParser creates a new OpenAPI parser
func NewParser() *Parser {
	return &Parser{}
}

// ParseSpec parses an OpenAPI spec and extracts endpoints
func (p *Parser) ParseSpec(data []byte) ([]APIEndpoint, error) {
	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = true

	doc, err := loader.LoadFromData(data)
	if err != nil {
		return nil, fmt.Errorf("failed to load OpenAPI spec: %w", err)
	}

	// Skip validation for better compatibility with real-world specs
	// Many specs have minor validation issues but are still parseable

	return p.extractEndpoints(doc), nil
}

// extractEndpoints extracts all endpoints from the OpenAPI document
func (p *Parser) extractEndpoints(doc *openapi3.T) []APIEndpoint {
	var endpoints []APIEndpoint

	if doc.Paths == nil {
		return endpoints
	}

	for path, pathItem := range doc.Paths.Map() {
		if pathItem == nil {
			continue
		}

		// Extract all HTTP methods
		methods := map[string]*openapi3.Operation{
			"GET":     pathItem.Get,
			"POST":    pathItem.Post,
			"PUT":     pathItem.Put,
			"DELETE":  pathItem.Delete,
			"PATCH":   pathItem.Patch,
			"OPTIONS": pathItem.Options,
			"HEAD":    pathItem.Head,
		}

		for method, operation := range methods {
			if operation == nil {
				continue
			}

			endpoint := APIEndpoint{
				Path:   path,
				Method: method,
			}

			// Extract parameters
			endpoint.Parameters = p.extractParameters(operation, pathItem)

			endpoints = append(endpoints, endpoint)
		}
	}

	return endpoints
}

// extractParameters extracts parameters from operation and path item
func (p *Parser) extractParameters(operation *openapi3.Operation, pathItem *openapi3.PathItem) []Parameter {
	var params []Parameter

	// Path-level parameters
	for _, paramRef := range pathItem.Parameters {
		if paramRef == nil || paramRef.Value == nil {
			continue
		}
		params = append(params, p.convertParameter(paramRef.Value))
	}

	// Operation-level parameters
	for _, paramRef := range operation.Parameters {
		if paramRef == nil || paramRef.Value == nil {
			continue
		}
		params = append(params, p.convertParameter(paramRef.Value))
	}

	return params
}

// convertParameter converts OpenAPI parameter to our Parameter type
func (p *Parser) convertParameter(param *openapi3.Parameter) Parameter {
	paramType := "string"
	if param.Schema != nil && param.Schema.Value != nil {
		paramType = param.Schema.Value.Type.Slice()[0]
	}

	return Parameter{
		Name:     param.Name,
		In:       param.In,
		Required: param.Required,
		Type:     paramType,
	}
}

// FormatEndpoints formats endpoints as strings for display
func FormatEndpoints(endpoints []APIEndpoint) []string {
	var formatted []string
	for _, ep := range endpoints {
		formatted = append(formatted, fmt.Sprintf("%s %s", ep.Method, ep.Path))
	}
	return formatted
}

// GetBasePath returns the base path from servers (OpenAPI 3.x) or basePath (Swagger 2.0)
func GetBasePath(doc *openapi3.T) string {
	if len(doc.Servers) > 0 && doc.Servers[0] != nil {
		url := doc.Servers[0].URL
		// Extract path component from URL
		if idx := strings.Index(url, "//"); idx != -1 {
			url = url[idx+2:]
			if idx := strings.Index(url, "/"); idx != -1 {
				return url[idx:]
			}
		}
	}
	return "/"
}
