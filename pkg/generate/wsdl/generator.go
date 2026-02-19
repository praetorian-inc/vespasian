// Copyright 2026 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package wsdl

import (
	"encoding/xml"
	"errors"

	"github.com/praetorian-inc/vespasian/pkg/classify"
)

// Generator produces WSDL specifications from classified SOAP requests.
type Generator struct{}

// APIType returns the API type this generator supports.
func (g *Generator) APIType() string {
	return "wsdl"
}

// DefaultExtension returns the default file extension for WSDL output.
func (g *Generator) DefaultExtension() string {
	return ".wsdl"
}

// Generate produces a WSDL specification from classified SOAP endpoints.
// Phase 1: If any endpoint has a WSDLDocument from probing, validate and return it.
// Phase 2: Fall back to inferring WSDL from observed traffic.
func (g *Generator) Generate(endpoints []classify.ClassifiedRequest) ([]byte, error) {
	if len(endpoints) == 0 {
		return nil, errors.New("no endpoints provided")
	}

	// Phase 1: Use probed WSDLDocument or response body if it contains valid WSDL
	for _, ep := range endpoints {
		// First try WSDLDocument (set by probe)
		if len(ep.WSDLDocument) > 0 {
			if _, err := ParseWSDL(ep.WSDLDocument); err == nil {
				return ep.WSDLDocument, nil
			}
		}
		// Also check if the response body itself is a valid WSDL (e.g., from ?wsdl crawl)
		if len(ep.Response.Body) > 0 {
			if _, err := ParseWSDL(ep.Response.Body); err == nil {
				return ep.Response.Body, nil
			}
		}
	}

	// Phase 2: Infer from traffic
	defs, err := InferWSDL(endpoints)
	if err != nil {
		return nil, err
	}

	output, err := xml.MarshalIndent(defs, "", "  ")
	if err != nil {
		return nil, err
	}

	// Prepend XML declaration
	return append([]byte(xml.Header), output...), nil
}
