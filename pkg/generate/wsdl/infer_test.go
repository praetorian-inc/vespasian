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

// T016: RED — wire-up test: body parameters are extracted and placed into Types.
func TestInferWSDL_BodyParametersIntoTypes(t *testing.T) {
	body := []byte(`<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><tns:GetUserRequest xmlns:tns="http://x/"><id>1</id></tns:GetUserRequest></soap:Body></soap:Envelope>`)
	endpoints := []classify.ClassifiedRequest{{
		ObservedRequest: crawl.ObservedRequest{
			Method:  "POST",
			URL:     "http://example.com/service",
			Headers: map[string]string{"SOAPAction": `"urn:GetUser"`},
			Body:    body,
		},
	}}

	defs, err := InferWSDL(endpoints)
	require.NoError(t, err)
	require.NotNil(t, defs.Types, "Types should be non-nil when body params observed")
	require.Len(t, defs.Types.Schemas, 1)
	require.Len(t, defs.Types.Schemas[0].Elements, 1)
	el := defs.Types.Schemas[0].Elements[0]
	assert.Equal(t, "GetUser", el.Name)
	require.NotNil(t, el.ComplexType)
	require.Len(t, el.ComplexType.Sequence, 1)
	assert.Equal(t, "id", el.ComplexType.Sequence[0].Name)
	assert.Equal(t, "xsd:int", el.ComplexType.Sequence[0].Type)
}

// NT008: End-to-end SOAP 1.2 + xsi:type RPC/encoded round-trips through InferWSDL.
// Mirrors architecture §10 Example B exactly.
// Confirms: SOAP 1.2 envelope path, RPC/encoded shape (operation element directly
// under Body with xsi:typed scalars), and no-SOAPAction body-element fallback all
// work end-to-end.
func TestInferWSDL_SOAP12_RPCEncoded_xsiType(t *testing.T) {
	// SOAP 1.2 envelope with two xsi:typed parameters; no SOAPAction header.
	// The operation name ("Add") is resolved from the body element name.
	body := []byte(
		`<?xml version="1.0"?>` +
			`<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope"` +
			` xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"` +
			` xmlns:xsd="http://www.w3.org/2001/XMLSchema">` +
			`<env:Body>` +
			`<Add>` +
			`<a xsi:type="xsd:int">3</a>` +
			`<b xsi:type="xsd:int">7</b>` +
			`</Add>` +
			`</env:Body>` +
			`</env:Envelope>`,
	)

	endpoints := []classify.ClassifiedRequest{{
		ObservedRequest: crawl.ObservedRequest{
			Method: "POST",
			URL:    "http://example.com/calculator",
			Body:   body,
		},
	}}

	defs, err := InferWSDL(endpoints)
	require.NoError(t, err)

	// Operation extracted from body element name (no SOAPAction).
	require.Len(t, defs.PortTypes, 1)
	require.Len(t, defs.PortTypes[0].Operations, 1)
	assert.Equal(t, "Add", defs.PortTypes[0].Operations[0].Name)

	// Types section populated from xsi:typed parameters.
	require.NotNil(t, defs.Types, "Types must be non-nil for RPC/encoded xsi:type body")
	require.Len(t, defs.Types.Schemas, 1)
	require.Len(t, defs.Types.Schemas[0].Elements, 1)
	el := defs.Types.Schemas[0].Elements[0]
	assert.Equal(t, "Add", el.Name)
	require.NotNil(t, el.ComplexType)
	require.Len(t, el.ComplexType.Sequence, 2, "sequence must contain a and b")
	assert.Equal(t, "a", el.ComplexType.Sequence[0].Name)
	assert.Equal(t, "xsd:int", el.ComplexType.Sequence[0].Type)
	assert.Equal(t, "b", el.ComplexType.Sequence[1].Name)
	assert.Equal(t, "xsd:int", el.ComplexType.Sequence[1].Type)
}

// T016: RED — union test: multiple bodies for same op are merged into one element.
func TestInferWSDL_BodyParametersUnion(t *testing.T) {
	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:  "POST",
				URL:     "http://example.com/service",
				Headers: map[string]string{"SOAPAction": `"urn:CreateUser"`},
				Body:    []byte(`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><CreateUserRequest><name>alice</name></CreateUserRequest></soap:Body></soap:Envelope>`),
			},
		},
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:  "POST",
				URL:     "http://example.com/service",
				Headers: map[string]string{"SOAPAction": `"urn:CreateUser"`},
				Body:    []byte(`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><CreateUserRequest><name>bob</name><age>30</age></CreateUserRequest></soap:Body></soap:Envelope>`),
			},
		},
	}

	defs, err := InferWSDL(endpoints)
	require.NoError(t, err)
	require.NotNil(t, defs.Types)
	require.Len(t, defs.Types.Schemas[0].Elements, 1)
	el := defs.Types.Schemas[0].Elements[0]
	assert.Equal(t, "CreateUser", el.Name)
	require.NotNil(t, el.ComplexType)
	require.Len(t, el.ComplexType.Sequence, 2, "union should have both name and age")
	assert.Equal(t, "name", el.ComplexType.Sequence[0].Name)
	assert.Equal(t, "xsd:string", el.ComplexType.Sequence[0].Type)
	assert.Equal(t, "age", el.ComplexType.Sequence[1].Name)
	assert.Equal(t, "xsd:int", el.ComplexType.Sequence[1].Type)
}

// NT012: Duplicate operation across endpoints; second body contributes no new params.
// Exercises the merge-on-duplicate-op path at infer.go:48-55 where extractSOAPParameters
// succeeds but the second observation has an empty operation element (no OrderedKeys).
// Verifies the first observation is preserved and not corrupted.
func TestInferWSDL_BodyParametersUnion_SecondObservationEmpty(t *testing.T) {
	endpoints := []classify.ClassifiedRequest{
		{
			// First observation: op with one parameter.
			ObservedRequest: crawl.ObservedRequest{
				Method:  "POST",
				URL:     "http://example.com/service",
				Headers: map[string]string{"SOAPAction": `"urn:GetUser"`},
				Body: []byte(`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">` +
					`<soap:Body><GetUserRequest><id>1</id></GetUserRequest></soap:Body></soap:Envelope>`),
			},
		},
		{
			// Second observation: same SOAPAction, but body has empty operation element.
			ObservedRequest: crawl.ObservedRequest{
				Method:  "POST",
				URL:     "http://example.com/service",
				Headers: map[string]string{"SOAPAction": `"urn:GetUser"`},
				Body: []byte(`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">` +
					`<soap:Body><GetUserRequest/></soap:Body></soap:Envelope>`),
			},
		},
	}

	defs, err := InferWSDL(endpoints)
	require.NoError(t, err)

	// Should produce exactly one operation.
	require.Len(t, defs.PortTypes[0].Operations, 1)
	assert.Equal(t, "GetUser", defs.PortTypes[0].Operations[0].Name)

	// Types must be present (from the first observation).
	require.NotNil(t, defs.Types, "Types must be non-nil — first observation had params")
	require.Len(t, defs.Types.Schemas[0].Elements, 1)
	el := defs.Types.Schemas[0].Elements[0]
	assert.Equal(t, "GetUser", el.Name)
	require.NotNil(t, el.ComplexType)

	// The empty second observation must not corrupt the first: exactly one param.
	require.Len(t, el.ComplexType.Sequence, 1,
		"second empty observation must not add or remove params")
	assert.Equal(t, "id", el.ComplexType.Sequence[0].Name)
	assert.Equal(t, "xsd:int", el.ComplexType.Sequence[0].Type)
}

// TEST-001: end-to-end InferWSDL when the SOAP body has an empty operation
// element. Verifies the operation is still inferred (via SOAPAction or body
// child name) and Types contains an element with an empty sequence.
func TestInferWSDL_EmptyOperationElement(t *testing.T) {
	endpoints := []classify.ClassifiedRequest{{
		ObservedRequest: crawl.ObservedRequest{
			Method:  "POST",
			URL:     "http://example.com/svc",
			Headers: map[string]string{"SOAPAction": `"urn:Ping"`},
			Body: []byte(`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">` +
				`<soap:Body><tns:Ping xmlns:tns="http://example.com/svc/"/></soap:Body></soap:Envelope>`),
		},
	}}

	defs, err := InferWSDL(endpoints)
	require.NoError(t, err)
	require.Len(t, defs.PortTypes[0].Operations, 1)
	assert.Equal(t, "Ping", defs.PortTypes[0].Operations[0].Name)

	// Types is populated even when the operation element has zero params —
	// the operation element itself produces a complexType with an empty sequence.
	require.NotNil(t, defs.Types)
	require.Len(t, defs.Types.Schemas, 1)
	require.Len(t, defs.Types.Schemas[0].Elements, 1)
	require.NotNil(t, defs.Types.Schemas[0].Elements[0].ComplexType)
	assert.Empty(t, defs.Types.Schemas[0].Elements[0].ComplexType.Sequence,
		"empty operation element produces an empty parameter sequence")
}

// TEST-004 (LAB-2111 AC3): the namespace observed on the SOAP operation
// element is preserved into the generated output — not just on the in-memory
// structs but in the marshaled WSDL. The service URL here ("http://different/ns/"
// observed vs. URL-derived "http://api.example.com:8443/") makes the distinction
// observable: emission must carry the observed namespace, and tns: references
// must stay resolvable because definitions/tns/schema all share it.
func TestInferWSDL_SchemaTargetNamespacePreserved(t *testing.T) {
	endpoints := []classify.ClassifiedRequest{{
		ObservedRequest: crawl.ObservedRequest{
			Method:  "POST",
			URL:     "http://api.example.com:8443/soap",
			Headers: map[string]string{"SOAPAction": `"urn:GetUser"`},
			Body: []byte(`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">` +
				`<soap:Body><tns:GetUserRequest xmlns:tns="http://different/ns/"><id>1</id></tns:GetUserRequest></soap:Body></soap:Envelope>`),
		},
	}}

	defs, err := InferWSDL(endpoints)
	require.NoError(t, err)
	require.NotNil(t, defs.Types)
	require.Len(t, defs.Types.Schemas, 1)

	const observedNS = "http://different/ns/"
	// Struct-level: the observed namespace drives every namespace slot so tns:
	// references (messages -> schema elements, portType -> messages, etc.) all
	// resolve under a single namespace.
	assert.Equal(t, observedNS, defs.Types.Schemas[0].TargetNS,
		"schema targetNamespace must be the observed operation namespace")
	assert.Equal(t, observedNS, defs.TargetNS, "definitions.targetNamespace must match for tns: consistency")
	assert.Equal(t, observedNS, defs.XMLNSTNS, "tns prefix must bind to the observed namespace")
	// Service address is unaffected by the namespace change.
	require.NotNil(t, defs.Services[0].Ports[0].SOAPAddress)
	assert.Equal(t, "http://api.example.com:8443/soap", defs.Services[0].Ports[0].SOAPAddress.Location)

	// Emitted-output: the observed namespace must actually appear in the
	// marshaled WSDL (the gap the earlier struct-only assertion missed).
	out, err := xml.MarshalIndent(defs, "", "  ")
	require.NoError(t, err)
	xmlStr := string(out)
	assert.Contains(t, xmlStr, `targetNamespace="`+observedNS+`"`,
		"observed namespace must be emitted as targetNamespace")
	assert.Contains(t, xmlStr, `xmlns:tns="`+observedNS+`"`,
		"observed namespace must be emitted as the tns binding")
	assert.NotContains(t, xmlStr, "http://api.example.com:8443/\"",
		"URL-derived namespace must not leak into the emitted namespaces")
}

// typesNamespace prefers the observed operation namespace and falls back to the
// URL-derived one only when traffic carried none or operations disagreed.
func TestTypesNamespace(t *testing.T) {
	const urlNS = "http://url-derived/"
	t.Run("single observed namespace is used", func(t *testing.T) {
		obs := map[string]*soapBodyInfo{"Op": {Namespace: "http://observed/"}}
		assert.Equal(t, "http://observed/", typesNamespace([]string{"Op"}, obs, urlNS))
	})
	t.Run("no observed namespace falls back to URL-derived", func(t *testing.T) {
		obs := map[string]*soapBodyInfo{"Op": {Namespace: ""}}
		assert.Equal(t, urlNS, typesNamespace([]string{"Op"}, obs, urlNS))
	})
	t.Run("missing observation falls back to URL-derived", func(t *testing.T) {
		assert.Equal(t, urlNS, typesNamespace([]string{"Op"}, map[string]*soapBodyInfo{}, urlNS))
	})
	t.Run("agreeing namespaces across operations are used", func(t *testing.T) {
		obs := map[string]*soapBodyInfo{
			"A": {Namespace: "http://same/"},
			"B": {Namespace: "http://same/"},
		}
		assert.Equal(t, "http://same/", typesNamespace([]string{"A", "B"}, obs, urlNS))
	})
	t.Run("disagreeing namespaces fall back to URL-derived", func(t *testing.T) {
		obs := map[string]*soapBodyInfo{
			"A": {Namespace: "http://one/"},
			"B": {Namespace: "http://two/"},
		}
		assert.Equal(t, urlNS, typesNamespace([]string{"A", "B"}, obs, urlNS))
	})
}

// TEST-001 (round-2 blocker fix): regression test for the namespace-aware
// Body match added to extractFirstBodyElement. A <body> element that is NOT
// in a SOAP envelope namespace must be ignored — protects against false
// matches on HTML bodies, custom XML wrappers, or fault detail payloads.
func TestExtractFirstBodyElement_NamespaceGate(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "SOAP 1.1 envelope: matches body and returns first child",
			body: `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">` +
				`<soap:Body><GetUser/></soap:Body></soap:Envelope>`,
			want: "GetUser",
		},
		{
			name: "SOAP 1.2 envelope: matches body and returns first child",
			body: `<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope">` +
				`<env:Body><GetUser/></env:Body></env:Envelope>`,
			want: "GetUser",
		},
		{
			name: "HTML-like document: body with no namespace must NOT match",
			body: `<html><body><div>not a SOAP op</div></body></html>`,
			want: "",
		},
		{
			name: "Wrapped body in non-SOAP namespace must NOT match",
			body: `<wrapper xmlns="http://example.com/other"><body><FakeOp/></body></wrapper>`,
			want: "",
		},
		{
			name: "Envelope with no Body element returns empty",
			body: `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">` +
				`<soap:Header/></soap:Envelope>`,
			want: "",
		},
		{
			name: "Empty input",
			body: ``,
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractFirstBodyElement([]byte(tt.body))
			assert.Equal(t, tt.want, got, "extractFirstBodyElement(%q)", tt.body)
		})
	}
}

// CR1 (CodeRabbit round-3 review): regression for the dedup-branch
// SOAPAction backfill. If endpoint 1 registers the operation (via body
// child element) without a SOAPAction header, and a later endpoint for
// the same operation carries the SOAPAction, the binding metadata must
// be backfilled — otherwise the generated WSDL binding loses the
// soapAction attribute.
func TestInferWSDL_BackfillsSOAPActionInDedupBranch(t *testing.T) {
	endpoints := []classify.ClassifiedRequest{
		{
			// Endpoint 1: registers GetUser via body child, NO SOAPAction.
			ObservedRequest: crawl.ObservedRequest{
				Method: "POST",
				URL:    "http://example.com/svc",
				Body: []byte(`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">` +
					`<soap:Body><GetUser><id>1</id></GetUser></soap:Body></soap:Envelope>`),
			},
		},
		{
			// Endpoint 2: same op, CARRIES SOAPAction. Goes through the
			// dedup branch — the backfill must capture this header.
			ObservedRequest: crawl.ObservedRequest{
				Method:  "POST",
				URL:     "http://example.com/svc",
				Headers: map[string]string{"SOAPAction": `"urn:GetUser"`},
				Body: []byte(`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">` +
					`<soap:Body><GetUser><id>2</id></GetUser></soap:Body></soap:Envelope>`),
			},
		},
	}

	defs, err := InferWSDL(endpoints)
	require.NoError(t, err)
	require.Len(t, defs.Bindings, 1)
	require.Len(t, defs.Bindings[0].Operations, 1)
	require.NotNil(t, defs.Bindings[0].Operations[0].SOAPOperation,
		"binding operation must carry SOAPOperation backfilled from endpoint 2")
	assert.Equal(t, "urn:GetUser", defs.Bindings[0].Operations[0].SOAPOperation.SOAPAction,
		"SOAPAction must be backfilled when first observation lacked it")
}

// CR1 negative: when the first observation already carries SOAPAction, a
// later same-op endpoint with a different SOAPAction must NOT overwrite
// it. First-observed-soapaction wins (matches first-observed-type-wins
// throughout the package).
func TestInferWSDL_DoesNotOverwriteExistingSOAPAction(t *testing.T) {
	endpoints := []classify.ClassifiedRequest{
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:  "POST",
				URL:     "http://example.com/svc",
				Headers: map[string]string{"SOAPAction": `"urn:GetUserV1"`},
				Body: []byte(`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">` +
					`<soap:Body><GetUserV1><id>1</id></GetUserV1></soap:Body></soap:Envelope>`),
			},
		},
		{
			ObservedRequest: crawl.ObservedRequest{
				Method:  "POST",
				URL:     "http://example.com/svc",
				Headers: map[string]string{"SOAPAction": `"urn:GetUserV1Alt"`},
				Body: []byte(`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">` +
					`<soap:Body><GetUserV1><id>2</id></GetUserV1></soap:Body></soap:Envelope>`),
			},
		},
	}

	defs, err := InferWSDL(endpoints)
	require.NoError(t, err)
	require.NotNil(t, defs.Bindings[0].Operations[0].SOAPOperation)
	assert.Equal(t, "urn:GetUserV1", defs.Bindings[0].Operations[0].SOAPOperation.SOAPAction,
		"first-observed SOAPAction must not be overwritten by a later same-op endpoint")
}
