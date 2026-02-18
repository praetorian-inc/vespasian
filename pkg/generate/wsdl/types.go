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

import "encoding/xml"

// Definitions is the root WSDL 1.1 element.
type Definitions struct {
	XMLName   xml.Name   `xml:"definitions"`
	Name      string     `xml:"name,attr,omitempty"`
	TargetNS  string     `xml:"targetNamespace,attr,omitempty"`
	XMLNS     string     `xml:"xmlns,attr,omitempty"`
	XMLNSWSDL string     `xml:"xmlns:wsdl,attr,omitempty"`
	XMLNSSOAP string     `xml:"xmlns:soap,attr,omitempty"`
	XMLNSTNS  string     `xml:"xmlns:tns,attr,omitempty"`
	XMLNSXSD  string     `xml:"xmlns:xsd,attr,omitempty"`
	Types     *Types     `xml:"types,omitempty"`
	Messages  []Message  `xml:"message"`
	PortTypes []PortType `xml:"portType"`
	Bindings  []Binding  `xml:"binding"`
	Services  []Service  `xml:"service"`
}

// Types wraps XSD schemas.
type Types struct {
	Schemas []Schema `xml:"schema"`
}

// Schema represents an XSD schema embedded in WSDL.
type Schema struct {
	XMLName      xml.Name      `xml:"schema"`
	TargetNS     string        `xml:"targetNamespace,attr,omitempty"`
	XMLNS        string        `xml:"xmlns,attr,omitempty"`
	Elements     []Element     `xml:"element"`
	ComplexTypes []ComplexType `xml:"complexType"`
}

// Element represents an XSD element.
type Element struct {
	XMLName     xml.Name     `xml:"element"`
	Name        string       `xml:"name,attr"`
	Type        string       `xml:"type,attr,omitempty"`
	ComplexType *ComplexType `xml:"complexType,omitempty"`
}

// ComplexType represents an XSD complex type.
type ComplexType struct {
	XMLName  xml.Name  `xml:"complexType"`
	Name     string    `xml:"name,attr,omitempty"`
	Sequence []Element `xml:"sequence>element"`
}

// Message represents a WSDL message.
type Message struct {
	XMLName xml.Name      `xml:"message"`
	Name    string        `xml:"name,attr"`
	Parts   []MessagePart `xml:"part"`
}

// MessagePart represents a part of a WSDL message.
type MessagePart struct {
	XMLName xml.Name `xml:"part"`
	Name    string   `xml:"name,attr"`
	Element string   `xml:"element,attr,omitempty"`
	Type    string   `xml:"type,attr,omitempty"`
}

// PortType groups related operations.
type PortType struct {
	XMLName    xml.Name    `xml:"portType"`
	Name       string      `xml:"name,attr"`
	Operations []Operation `xml:"operation"`
}

// Operation represents a WSDL operation.
type Operation struct {
	XMLName xml.Name `xml:"operation"`
	Name    string   `xml:"name,attr"`
	Input   *IOMsg   `xml:"input,omitempty"`
	Output  *IOMsg   `xml:"output,omitempty"`
}

// IOMsg references a message for input/output.
type IOMsg struct {
	Message string `xml:"message,attr"`
}

// Binding specifies protocol details for a port type.
type Binding struct {
	XMLName     xml.Name           `xml:"binding"`
	Name        string             `xml:"name,attr"`
	Type        string             `xml:"type,attr"`
	SOAPBinding *SOAPBinding       `xml:"http://schemas.xmlsoap.org/wsdl/soap/ binding,omitempty"`
	Operations  []BindingOperation `xml:"operation"`
}

// SOAPBinding specifies SOAP transport.
type SOAPBinding struct {
	Style     string `xml:"style,attr,omitempty"`
	Transport string `xml:"transport,attr,omitempty"`
}

// BindingOperation specifies SOAP action for an operation.
type BindingOperation struct {
	XMLName       xml.Name       `xml:"operation"`
	Name          string         `xml:"name,attr"`
	SOAPOperation *SOAPOperation `xml:"http://schemas.xmlsoap.org/wsdl/soap/ operation,omitempty"`
}

// SOAPOperation specifies SOAPAction.
type SOAPOperation struct {
	SOAPAction string `xml:"soapAction,attr,omitempty"`
}

// Service groups related ports.
type Service struct {
	XMLName xml.Name `xml:"service"`
	Name    string   `xml:"name,attr"`
	Ports   []Port   `xml:"port"`
}

// Port associates a binding with a network address.
type Port struct {
	XMLName     xml.Name     `xml:"port"`
	Name        string       `xml:"name,attr"`
	Binding     string       `xml:"binding,attr"`
	SOAPAddress *SOAPAddress `xml:"http://schemas.xmlsoap.org/wsdl/soap/ address,omitempty"`
}

// SOAPAddress specifies the endpoint URL.
type SOAPAddress struct {
	Location string `xml:"location,attr"`
}
