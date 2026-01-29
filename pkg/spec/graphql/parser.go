package graphql

import (
	"encoding/json"
	"fmt"
)

// APIEndpoint represents a discovered GraphQL operation
type APIEndpoint struct {
	Name   string
	Type   string // "query" or "mutation" or "subscription"
	Fields []Field
}

// Field represents a field in a GraphQL type
type Field struct {
	Name string
	Args []Argument
}

// Argument represents an argument to a field
type Argument struct {
	Name string
	Type string
}

// Parser parses GraphQL introspection responses
type Parser struct{}

// NewParser creates a new GraphQL parser
func NewParser() *Parser {
	return &Parser{}
}

// ParseIntrospection parses a GraphQL introspection response
func (p *Parser) ParseIntrospection(data []byte) ([]APIEndpoint, error) {
	var response IntrospectionResponse
	if err := json.Unmarshal(data, &response); err != nil {
		return nil, fmt.Errorf("failed to parse introspection response: %w", err)
	}

	return p.extractEndpoints(&response.Data.Schema), nil
}

// extractEndpoints extracts operations from the schema
func (p *Parser) extractEndpoints(schema *Schema) []APIEndpoint {
	var endpoints []APIEndpoint

	// Extract queries
	if schema.QueryType != nil {
		queryType := p.findType(schema, schema.QueryType.Name)
		if queryType != nil {
			for _, field := range queryType.Fields {
				endpoints = append(endpoints, APIEndpoint{
					Name:   field.Name,
					Type:   "query",
					Fields: []Field{p.convertField(field)},
				})
			}
		}
	}

	// Extract mutations
	if schema.MutationType != nil {
		mutationType := p.findType(schema, schema.MutationType.Name)
		if mutationType != nil {
			for _, field := range mutationType.Fields {
				endpoints = append(endpoints, APIEndpoint{
					Name:   field.Name,
					Type:   "mutation",
					Fields: []Field{p.convertField(field)},
				})
			}
		}
	}

	return endpoints
}

// findType finds a type by name in the schema
func (p *Parser) findType(schema *Schema, name string) *Type {
	for _, t := range schema.Types {
		if t.Name == name {
			return &t
		}
	}
	return nil
}

// convertField converts an introspection field to our Field type
func (p *Parser) convertField(field TypeField) Field {
	f := Field{
		Name: field.Name,
		Args: make([]Argument, 0, len(field.Args)),
	}

	for _, arg := range field.Args {
		f.Args = append(f.Args, Argument{
			Name: arg.Name,
			Type: p.getTypeName(arg.Type),
		})
	}

	return f
}

// getTypeName extracts the type name from a TypeRef
func (p *Parser) getTypeName(typeRef TypeRef) string {
	if typeRef.Name != "" {
		return typeRef.Name
	}
	if typeRef.OfType != nil {
		return p.getTypeName(*typeRef.OfType)
	}
	return "Unknown"
}

// IntrospectionResponse represents the structure of a GraphQL introspection response
type IntrospectionResponse struct {
	Data struct {
		Schema Schema `json:"__schema"`
	} `json:"data"`
}

// Schema represents the GraphQL schema from introspection
type Schema struct {
	QueryType        *TypeRef `json:"queryType"`
	MutationType     *TypeRef `json:"mutationType"`
	SubscriptionType *TypeRef `json:"subscriptionType"`
	Types            []Type   `json:"types"`
}

// TypeRef is a reference to a type
type TypeRef struct {
	Kind   string   `json:"kind"`
	Name   string   `json:"name"`
	OfType *TypeRef `json:"ofType"`
}

// Type represents a GraphQL type
type Type struct {
	Kind   string      `json:"kind"`
	Name   string      `json:"name"`
	Fields []TypeField `json:"fields"`
}

// TypeField represents a field in a GraphQL type
type TypeField struct {
	Name string         `json:"name"`
	Args []TypeArgument `json:"args"`
}

// TypeArgument represents an argument to a field
type TypeArgument struct {
	Name string  `json:"name"`
	Type TypeRef `json:"type"`
}
