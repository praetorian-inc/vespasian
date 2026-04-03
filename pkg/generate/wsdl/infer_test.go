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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/vespasian/pkg/classify"
	"github.com/praetorian-inc/vespasian/pkg/crawl"
)

func TestInferWSDL_FromSOAPAction(t *testing.T) {
	endpoints := []classify.ClassifiedRequest{{
		ObservedRequest: crawl.ObservedRequest{
			Method:  "POST",
			URL:     "http://example.com/calculator",
			Headers: map[string]string{"SOAPAction": `"urn:Add"`},
		},
	}}

	defs, err := InferWSDL(endpoints)
	require.NoError(t, err)
	require.Len(t, defs.PortTypes, 1)
	require.Len(t, defs.PortTypes[0].Operations, 1)
	assert.Equal(t, "Add", defs.PortTypes[0].Operations[0].Name)

	require.Len(t, defs.Bindings, 1)
	require.Len(t, defs.Bindings[0].Operations, 1)
	require.NotNil(t, defs.Bindings[0].Operations[0].SOAPOperation)
	assert.Equal(t, "urn:Add", defs.Bindings[0].Operations[0].SOAPOperation.SOAPAction)
}

func TestInferWSDL_FromBodyElement(t *testing.T) {
	endpoints := []classify.ClassifiedRequest{{
		ObservedRequest: crawl.ObservedRequest{
			Method: "POST",
			URL:    "http://example.com/service",
			Body:   []byte(`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><GetWeather xmlns="http://example.com/"/></soap:Body></soap:Envelope>`),
		},
	}}

	defs, err := InferWSDL(endpoints)
	require.NoError(t, err)
	require.Len(t, defs.PortTypes[0].Operations, 1)
	assert.Equal(t, "GetWeather", defs.PortTypes[0].Operations[0].Name)
}

func TestInferWSDL_DeduplicatesOperations(t *testing.T) {
	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:  "POST",
				URL:     "http://example.com/service",
				Headers: map[string]string{"SOAPAction": `"urn:GetUser"`},
			},
		},
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:  "POST",
				URL:     "http://example.com/service",
				Headers: map[string]string{"SOAPAction": `"urn:GetUser"`},
			},
		},
	}

	defs, err := InferWSDL(endpoints)
	require.NoError(t, err)
	assert.Len(t, defs.PortTypes[0].Operations, 1, "duplicate ops should be merged")
}

func TestInferWSDL_MultipleOperations(t *testing.T) {
	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:  "POST",
				URL:     "http://example.com/service",
				Headers: map[string]string{"SOAPAction": `"urn:GetUser"`},
			},
		},
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:  "POST",
				URL:     "http://example.com/service",
				Headers: map[string]string{"SOAPAction": `"urn:DeleteUser"`},
			},
		},
		{
			ObservedRequest: crawl.ObservedRequest{
				Method: "POST",
				URL:    "http://example.com/service",
				Body:   []byte(`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><ListUsers/></soap:Body></soap:Envelope>`),
			},
		},
	}

	defs, err := InferWSDL(endpoints)
	require.NoError(t, err)
	assert.Len(t, defs.PortTypes[0].Operations, 3)
	assert.Equal(t, 6, len(defs.Messages), "2 messages per operation")
}

func TestInferWSDL_EmptyEndpoints(t *testing.T) {
	_, err := InferWSDL(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no endpoints")
}

func TestInferWSDL_NoExtractableOperations(t *testing.T) {
	endpoints := []classify.ClassifiedRequest{{
		ObservedRequest: crawl.ObservedRequest{
			Method: "POST",
			URL:    "http://example.com/service",
		},
	}}

	_, err := InferWSDL(endpoints)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no SOAP operations")
}

func TestInferWSDL_FromResponseBody(t *testing.T) {
	// Simulates crawl-captured traffic where request body is empty but
	// the response contains a SOAP envelope.
	endpoints := []classify.ClassifiedRequest{{
		ObservedRequest: crawl.ObservedRequest{
			Method: "GET",
			URL:    "http://example.com/service",
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "text/xml",
				Body: []byte(`<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUserResponse xmlns="http://example.com/">
      <User><Name>Alice</Name></User>
    </GetUserResponse>
  </soap:Body>
</soap:Envelope>`),
			},
		},
	}}

	defs, err := InferWSDL(endpoints)
	require.NoError(t, err)
	require.Len(t, defs.PortTypes[0].Operations, 1)
	assert.Equal(t, "GetUser", defs.PortTypes[0].Operations[0].Name,
		"should strip Response suffix from response body element")
}

func TestInferWSDL_ResponseBodyNoSuffix(t *testing.T) {
	// Response body element without "Response" suffix should still work.
	endpoints := []classify.ClassifiedRequest{{
		ObservedRequest: crawl.ObservedRequest{
			Method: "GET",
			URL:    "http://example.com/service",
			Response: crawl.ObservedResponse{
				StatusCode:  200,
				ContentType: "text/xml",
				Body: []byte(`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body><ListUsers xmlns="http://example.com/"/></soap:Body>
</soap:Envelope>`),
			},
		},
	}}

	defs, err := InferWSDL(endpoints)
	require.NoError(t, err)
	require.Len(t, defs.PortTypes[0].Operations, 1)
	assert.Equal(t, "ListUsers", defs.PortTypes[0].Operations[0].Name)
}

func TestInferServiceName(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"http://example.com/calculator", "calculator"},
		{"http://example.com/ws/service.asmx", "service"},
		{"http://example.com/api/v1/endpoint.svc", "endpoint"},
		{"http://example.com/service.php", "service"},
		{"http://example.com/", "Service"},
		{"http://example.com", "Service"},
		{"://invalid", "Service"},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			assert.Equal(t, tt.want, inferServiceName(tt.url))
		})
	}
}

func TestExtractNameFromURI(t *testing.T) {
	tests := []struct {
		uri  string
		want string
	}{
		{"urn:GetUser", "GetUser"},
		{"http://example.com/ws/GetUser", "GetUser"},
		{"http://example.com/ws#GetUser", "GetUser"},
		{`"urn:GetUser"`, "GetUser"},
		{"GetUser", "GetUser"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.uri, func(t *testing.T) {
			assert.Equal(t, tt.want, extractNameFromURI(tt.uri))
		})
	}
}

func TestInferWSDL_StructureComplete(t *testing.T) {
	endpoints := []classify.ClassifiedRequest{{
		ObservedRequest: crawl.ObservedRequest{
			Method:  "POST",
			URL:     "http://example.com/calculator",
			Headers: map[string]string{"SOAPAction": `"urn:Add"`},
		},
	}}

	defs, err := InferWSDL(endpoints)
	require.NoError(t, err)

	assert.Equal(t, "calculator", defs.Name)
	assert.Equal(t, "http://example.com/", defs.TargetNS)
	assert.Len(t, defs.Messages, 2)
	assert.Len(t, defs.PortTypes, 1)
	assert.Len(t, defs.Bindings, 1)
	require.NotNil(t, defs.Bindings[0].SOAPBinding)
	assert.Equal(t, "document", defs.Bindings[0].SOAPBinding.Style)
	assert.Len(t, defs.Services, 1)
	assert.Len(t, defs.Services[0].Ports, 1)
	require.NotNil(t, defs.Services[0].Ports[0].SOAPAddress)
	assert.Equal(t, "http://example.com/calculator", defs.Services[0].Ports[0].SOAPAddress.Location)
}
