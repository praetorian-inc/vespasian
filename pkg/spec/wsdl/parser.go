package wsdl

import (
	"encoding/xml"
	"fmt"
)

// Definitions represents the root element of a WSDL document
type Definitions struct {
	XMLName    xml.Name   `xml:"definitions"`
	Name       string     `xml:"name,attr"`
	PortTypes  []PortType `xml:"portType"`
	Services   []Service  `xml:"service"`
	Operations []Operation
}

// PortType represents a WSDL portType
type PortType struct {
	Name       string      `xml:"name,attr"`
	Operations []Operation `xml:"operation"`
}

// Operation represents a WSDL operation
type Operation struct {
	Name string `xml:"name,attr"`
}

// Service represents a WSDL service
type Service struct {
	Name  string `xml:"name,attr"`
	Ports []Port `xml:"port"`
}

// Port represents a WSDL port
type Port struct {
	Name    string `xml:"name,attr"`
	Binding string `xml:"binding,attr"`
}

// Parser parses WSDL documents
type Parser struct{}

// NewParser creates a new WSDL parser
func NewParser() *Parser {
	return &Parser{}
}

// ParseWSDL parses WSDL XML and extracts operations
func (p *Parser) ParseWSDL(data []byte) (*Definitions, error) {
	var defs Definitions
	if err := xml.Unmarshal(data, &defs); err != nil {
		return nil, fmt.Errorf("failed to parse WSDL: %w", err)
	}

	// Extract all operations from portTypes
	for _, portType := range defs.PortTypes {
		defs.Operations = append(defs.Operations, portType.Operations...)
	}

	return &defs, nil
}
