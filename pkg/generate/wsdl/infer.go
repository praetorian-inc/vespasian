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
	"bytes"
	"encoding/xml"
	"errors"
	"net/url"
	"strings"

	"github.com/praetorian-inc/vespasian/pkg/classify"
)

// InferWSDL builds a partial but valid WSDL from observed SOAP traffic.
// It extracts operation names from SOAPAction headers or SOAP body first child elements.
func InferWSDL(endpoints []classify.ClassifiedRequest) (*Definitions, error) {
	if len(endpoints) == 0 {
		return nil, errors.New("no endpoints to infer WSDL from")
	}

	// Determine service URL from first endpoint
	serviceURL := endpoints[0].URL
	serviceName := inferServiceName(serviceURL)
	targetNS := inferTargetNamespace(serviceURL)

	var operations []string
	soapActions := make(map[string]string) // operation name -> SOAPAction URI
	seen := make(map[string]bool)

	for _, ep := range endpoints {
		opName, soapAction := extractOperation(ep)
		if opName == "" || seen[opName] {
			continue
		}
		seen[opName] = true
		operations = append(operations, opName)
		if soapAction != "" {
			soapActions[opName] = soapAction
		}
	}

	if len(operations) == 0 {
		return nil, errors.New("no SOAP operations found in traffic")
	}

	defs := &Definitions{
		Name:      serviceName,
		TargetNS:  targetNS,
		XMLNS:     "http://schemas.xmlsoap.org/wsdl/",
		XMLNSSOAP: "http://schemas.xmlsoap.org/wsdl/soap/",
		XMLNSTNS:  targetNS,
		XMLNSXSD:  "http://www.w3.org/2001/XMLSchema",
	}

	portTypeName := serviceName + "PortType"
	bindingName := serviceName + "Binding"

	// Build messages, portType operations, and binding operations
	var messages []Message
	var ptOps []Operation
	var bindOps []BindingOperation

	for _, opName := range operations {
		// Input message
		inputMsgName := opName + "Request"
		messages = append(messages, Message{
			Name:  inputMsgName,
			Parts: []MessagePart{{Name: "parameters", Element: "tns:" + opName}},
		})

		// Output message
		outputMsgName := opName + "Response"
		messages = append(messages, Message{
			Name:  outputMsgName,
			Parts: []MessagePart{{Name: "parameters", Element: "tns:" + opName + "Response"}},
		})

		// PortType operation
		ptOps = append(ptOps, Operation{
			Name:   opName,
			Input:  &IOMsg{Message: "tns:" + inputMsgName},
			Output: &IOMsg{Message: "tns:" + outputMsgName},
		})

		// Binding operation
		bop := BindingOperation{Name: opName}
		if sa, ok := soapActions[opName]; ok {
			bop.SOAPOperation = &SOAPOperation{SOAPAction: sa}
		}
		bindOps = append(bindOps, bop)
	}

	defs.Messages = messages
	defs.PortTypes = []PortType{{
		Name:       portTypeName,
		Operations: ptOps,
	}}
	defs.Bindings = []Binding{{
		Name: bindingName,
		Type: "tns:" + portTypeName,
		SOAPBinding: &SOAPBinding{
			Style:     "document",
			Transport: "http://schemas.xmlsoap.org/soap/http",
		},
		Operations: bindOps,
	}}
	defs.Services = []Service{{
		Name: serviceName,
		Ports: []Port{{
			Name:        serviceName + "Port",
			Binding:     "tns:" + bindingName,
			SOAPAddress: &SOAPAddress{Location: serviceURL},
		}},
	}}

	return defs, nil
}

// extractOperation extracts the operation name from a classified SOAP request.
// First tries SOAPAction header, then falls back to SOAP body first child element.
func extractOperation(ep classify.ClassifiedRequest) (opName string, soapAction string) {
	// Try SOAPAction header (case-insensitive)
	for k, v := range ep.Headers {
		if strings.EqualFold(k, "soapaction") {
			soapAction = strings.Trim(v, `"`)
			// Extract operation name from URI: last path segment or after last /
			opName = extractNameFromURI(soapAction)
			if opName != "" {
				return opName, soapAction
			}
		}
	}

	// Fall back to SOAP body first child element name
	if len(ep.Body) > 0 {
		opName = extractFirstBodyElement(ep.Body)
		if opName != "" {
			return opName, ""
		}
	}

	return "", ""
}

// extractNameFromURI extracts the last segment from a URI or URN.
func extractNameFromURI(uri string) string {
	uri = strings.Trim(uri, `"`)
	// Handle URN-style: urn:GetUser -> GetUser
	if strings.HasPrefix(uri, "urn:") {
		return uri[4:]
	}
	// Handle fragment: http://example.com/ws#GetUser -> GetUser
	if idx := strings.LastIndex(uri, "#"); idx >= 0 && idx < len(uri)-1 {
		return uri[idx+1:]
	}
	// Handle URL-style: take last path segment
	if idx := strings.LastIndex(uri, "/"); idx >= 0 && idx < len(uri)-1 {
		return uri[idx+1:]
	}
	return uri
}

// extractFirstBodyElement extracts the first child element name from within soap:Body.
func extractFirstBodyElement(body []byte) string {
	decoder := xml.NewDecoder(bytes.NewReader(body))
	inBody := false
	for {
		tok, err := decoder.Token()
		if err != nil {
			return ""
		}
		switch t := tok.(type) {
		case xml.StartElement:
			local := t.Name.Local
			if strings.EqualFold(local, "body") {
				inBody = true
				continue
			}
			if inBody {
				return local
			}
		}
	}
}

// inferServiceName derives a service name from the URL.
func inferServiceName(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "Service"
	}
	path := strings.TrimRight(parsed.Path, "/")
	if idx := strings.LastIndex(path, "/"); idx >= 0 {
		name := path[idx+1:]
		// Strip common extensions
		name = strings.TrimSuffix(name, ".php")
		name = strings.TrimSuffix(name, ".asmx")
		name = strings.TrimSuffix(name, ".svc")
		if name != "" {
			return name
		}
	}
	return "Service"
}

// inferTargetNamespace derives a target namespace from the URL.
func inferTargetNamespace(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "http://tempuri.org/"
	}
	return parsed.Scheme + "://" + parsed.Host + "/"
}
