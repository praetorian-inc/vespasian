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
	"strings"
	"testing"

	"github.com/praetorian-inc/vespasian/pkg/classify"
	"github.com/praetorian-inc/vespasian/pkg/crawl"
)

func TestGenerator_APIType(t *testing.T) {
	g := &Generator{}
	if g.APIType() != "wsdl" {
		t.Errorf("APIType() = %q, want %q", g.APIType(), "wsdl")
	}
}

func TestGenerator_DefaultExtension(t *testing.T) {
	g := &Generator{}
	if g.DefaultExtension() != ".wsdl" {
		t.Errorf("DefaultExtension() = %q, want %q", g.DefaultExtension(), ".wsdl")
	}
}

func TestGenerator_Phase1_Passthrough(t *testing.T) {
	// Valid WSDL document from probe should be returned directly
	validWSDL := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<definitions name="TestService" xmlns="http://schemas.xmlsoap.org/wsdl/">
  <message name="GetUserRequest"><part name="parameters" element="tns:GetUser"/></message>
  <portType name="TestPortType">
    <operation name="GetUser"/>
  </portType>
</definitions>`)

	g := &Generator{}
	endpoints := []classify.ClassifiedRequest{{
		ObservedRequest: crawl.ObservedRequest{
			Method: "POST",
			URL:    "http://example.com/service",
		},
		WSDLDocument: validWSDL,
		APIType:      "wsdl",
	}}

	result, err := g.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	if string(result) != string(validWSDL) {
		t.Errorf("expected passthrough of WSDLDocument")
	}
}

func TestGenerator_Phase2_InferFromSOAPAction(t *testing.T) {
	g := &Generator{}
	endpoints := []classify.ClassifiedRequest{{
		ObservedRequest: crawl.ObservedRequest{
			Method:  "POST",
			URL:     "http://example.com/service.php",
			Headers: map[string]string{"SOAPAction": `"urn:GetUser"`},
			Body:    []byte(`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><GetUser/></soap:Body></soap:Envelope>`),
		},
		APIType: "wsdl",
	}}

	result, err := g.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	output := string(result)
	if !strings.Contains(output, "GetUser") {
		t.Error("expected operation name GetUser in output")
	}
	if !strings.Contains(output, "<?xml") {
		t.Error("expected XML declaration")
	}
}

func TestGenerator_Phase2_InferFromBody(t *testing.T) {
	g := &Generator{}
	endpoints := []classify.ClassifiedRequest{{
		ObservedRequest: crawl.ObservedRequest{
			Method: "POST",
			URL:    "http://example.com/service",
			Body:   []byte(`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><ListUsers xmlns="http://example.com/"/></soap:Body></soap:Envelope>`),
		},
		APIType: "wsdl",
	}}

	result, err := g.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	if !strings.Contains(string(result), "ListUsers") {
		t.Error("expected operation name ListUsers in output")
	}
}

func TestGenerator_ParseRoundTrip(t *testing.T) {
	g := &Generator{}
	endpoints := []classify.ClassifiedRequest{{
		ObservedRequest: crawl.ObservedRequest{
			Method:  "POST",
			URL:     "http://example.com/service",
			Headers: map[string]string{"SOAPAction": `"urn:Ping"`},
			Body:    []byte(`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><Ping/></soap:Body></soap:Envelope>`),
		},
		APIType: "wsdl",
	}}

	result, err := g.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	// Should be parseable back
	defs, err := ParseWSDL(result)
	if err != nil {
		t.Fatalf("ParseWSDL() error: %v", err)
	}

	if len(defs.PortTypes) == 0 {
		t.Fatal("expected at least one port type")
	}
}

func TestGenerator_EmptyEndpoints(t *testing.T) {
	g := &Generator{}
	_, err := g.Generate(nil)
	if err == nil {
		t.Error("expected error for empty endpoints")
	}
}

func TestGenerator_MalformedWSDLDocument_FallsThrough(t *testing.T) {
	g := &Generator{}
	endpoints := []classify.ClassifiedRequest{{
		ObservedRequest: crawl.ObservedRequest{
			Method:  "POST",
			URL:     "http://example.com/service",
			Headers: map[string]string{"SOAPAction": `"urn:TestOp"`},
			Body:    []byte(`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><TestOp/></soap:Body></soap:Envelope>`),
		},
		WSDLDocument: []byte(`this is not valid XML`),
		APIType:      "wsdl",
	}}

	result, err := g.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	// Should fall through to inference
	if !strings.Contains(string(result), "TestOp") {
		t.Error("expected fallthrough to inference with TestOp operation")
	}
}

// Test that xml.Unmarshal roundtrip works for the type structs
func TestParseWSDL_BasicDocument(t *testing.T) {
	wsdlXML := `<definitions name="Svc" xmlns="http://schemas.xmlsoap.org/wsdl/">
  <message name="Msg"><part name="p" type="xsd:string"/></message>
  <portType name="PT"><operation name="Op"><input message="tns:Msg"/></operation></portType>
</definitions>`

	defs, err := ParseWSDL([]byte(wsdlXML))
	if err != nil {
		t.Fatalf("ParseWSDL error: %v", err)
	}
	if defs.Name != "Svc" {
		t.Errorf("Name = %q, want Svc", defs.Name)
	}
	if len(defs.Messages) != 1 {
		t.Errorf("Messages count = %d, want 1", len(defs.Messages))
	}
	if len(defs.PortTypes) != 1 || len(defs.PortTypes[0].Operations) != 1 {
		t.Error("expected 1 portType with 1 operation")
	}

	// Verify roundtrip marshaling works
	_, err = xml.MarshalIndent(defs, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent error: %v", err)
	}
}

func TestParseWSDL_FullDocument(t *testing.T) {
	wsdlXML := `<definitions name="Calculator"
		xmlns="http://schemas.xmlsoap.org/wsdl/"
		xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
		xmlns:tns="http://example.com/"
		targetNamespace="http://example.com/">
	  <types>
		<schema xmlns="http://www.w3.org/2001/XMLSchema" targetNamespace="http://example.com/">
		  <element name="Add">
			<complexType><sequence>
			  <element name="a" type="xsd:int"/>
			  <element name="b" type="xsd:int"/>
			</sequence></complexType>
		  </element>
		</schema>
	  </types>
	  <message name="AddRequest"><part name="parameters" element="tns:Add"/></message>
	  <message name="AddResponse"><part name="parameters" element="tns:AddResponse"/></message>
	  <portType name="CalculatorPortType">
		<operation name="Add">
		  <input message="tns:AddRequest"/>
		  <output message="tns:AddResponse"/>
		</operation>
	  </portType>
	  <binding name="CalculatorBinding" type="tns:CalculatorPortType">
		<soap:binding style="document" transport="http://schemas.xmlsoap.org/soap/http"/>
		<operation name="Add">
		  <soap:operation soapAction="http://example.com/Add"/>
		</operation>
	  </binding>
	  <service name="Calculator">
		<port name="CalculatorPort" binding="tns:CalculatorBinding">
		  <soap:address location="http://example.com/calculator"/>
		</port>
	  </service>
	</definitions>`

	defs, err := ParseWSDL([]byte(wsdlXML))
	if err != nil {
		t.Fatalf("ParseWSDL error: %v", err)
	}
	if defs.Name != "Calculator" {
		t.Errorf("Name = %q, want Calculator", defs.Name)
	}
	if defs.Types == nil || len(defs.Types.Schemas) != 1 {
		t.Error("expected 1 schema in types")
	}
	if len(defs.Messages) != 2 {
		t.Errorf("Messages = %d, want 2", len(defs.Messages))
	}
	if len(defs.Bindings) != 1 {
		t.Errorf("Bindings = %d, want 1", len(defs.Bindings))
	}
	if len(defs.Services) != 1 || len(defs.Services[0].Ports) != 1 {
		t.Error("expected 1 service with 1 port")
	}
}

func TestParseWSDL_MalformedXML(t *testing.T) {
	_, err := ParseWSDL([]byte(`<not valid xml`))
	if err == nil {
		t.Error("expected error for malformed XML")
	}
}

func TestParseWSDL_EmptyInput(t *testing.T) {
	_, err := ParseWSDL([]byte{})
	if err == nil {
		t.Error("expected error for empty input")
	}
}

func TestGenerator_MultipleEndpoints(t *testing.T) {
	g := &Generator{}
	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:  "POST",
				URL:     "http://example.com/service",
				Headers: map[string]string{"SOAPAction": `"urn:GetUser"`},
				Body:    []byte(`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><GetUser/></soap:Body></soap:Envelope>`),
			},
			APIType: "wsdl",
		},
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:  "POST",
				URL:     "http://example.com/service",
				Headers: map[string]string{"SOAPAction": `"urn:ListUsers"`},
				Body:    []byte(`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><ListUsers/></soap:Body></soap:Envelope>`),
			},
			APIType: "wsdl",
		},
	}

	result, err := g.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	defs, err := ParseWSDL(result)
	if err != nil {
		t.Fatalf("ParseWSDL() error: %v", err)
	}
	if len(defs.PortTypes[0].Operations) != 2 {
		t.Errorf("operations = %d, want 2", len(defs.PortTypes[0].Operations))
	}
}

func TestGenerator_Phase1_FirstValidWins(t *testing.T) {
	validWSDL := []byte(`<definitions name="First" xmlns="http://schemas.xmlsoap.org/wsdl/"><portType name="PT"/></definitions>`)
	secondWSDL := []byte(`<definitions name="Second" xmlns="http://schemas.xmlsoap.org/wsdl/"><portType name="PT2"/></definitions>`)

	g := &Generator{}
	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{Method: "POST", URL: "http://example.com/svc1"},
			WSDLDocument:    validWSDL,
			APIType:         "wsdl",
		},
		{
			ObservedRequest: crawl.ObservedRequest{Method: "POST", URL: "http://example.com/svc2"},
			WSDLDocument:    secondWSDL,
			APIType:         "wsdl",
		},
	}

	result, err := g.Generate(endpoints)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	if string(result) != string(validWSDL) {
		t.Error("expected first valid WSDL to be returned")
	}
}
