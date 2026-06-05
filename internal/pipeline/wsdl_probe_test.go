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

package pipeline_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/vespasian/internal/pipeline"
	"github.com/praetorian-inc/vespasian/pkg/crawl"
)

// validWSDLDocument is a minimal well-formed WSDL document accepted by ParseWSDL.
const validWSDLDocument = `<?xml version="1.0"?>
<definitions name="Calculator"
  xmlns="http://schemas.xmlsoap.org/wsdl/"
  xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
  xmlns:tns="http://example.com/"
  targetNamespace="http://example.com/">
  <message name="AddRequest"><part name="parameters" element="tns:Add"/></message>
  <message name="AddResponse"><part name="parameters" element="tns:AddResponse"/></message>
  <portType name="CalculatorPortType">
    <operation name="Add">
      <input message="tns:AddRequest"/>
      <output message="tns:AddResponse"/>
    </operation>
  </portType>
</definitions>`

// wsdlServer starts an httptest.Server that serves validWSDLDocument at ?wsdl
// and plain HTML for all other requests.
func wsdlServer(t *testing.T) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery == "wsdl" {
			w.Header().Set("Content-Type", "text/xml")
			w.Write([]byte(validWSDLDocument)) //nolint:gosec // G104: test code
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>Service</body></html>")) //nolint:gosec // G104: test code
	}))
	t.Cleanup(ts.Close)
	return ts
}

// ---------------------------------------------------------------------------
// TEST-004: happy-path tests for ProbeWSDLDocument
// ---------------------------------------------------------------------------

func TestProbeWSDLDocument_HappyPath(t *testing.T) {
	ts := wsdlServer(t)

	doc := pipeline.ProbeWSDLDocument(context.Background(), ts.URL+"/service.asmx", true, nil)
	require.NotNil(t, doc, "expected non-nil WSDL bytes for valid endpoint")
	assert.True(t, strings.Contains(string(doc), "Calculator"), "expected Calculator service in WSDL")
}

func TestProbeWSDLDocument_NotWSDLReturnsNil(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html>not wsdl</html>")) //nolint:gosec // G104: test code
	}))
	t.Cleanup(ts.Close)

	doc := pipeline.ProbeWSDLDocument(context.Background(), ts.URL, true, nil)
	assert.Nil(t, doc)
}

func TestProbeWSDLDocument_InvalidURLReturnsNil(t *testing.T) {
	var buf bytes.Buffer
	doc := pipeline.ProbeWSDLDocument(context.Background(), "://bad", true, &buf)
	assert.Nil(t, doc, "expected nil bytes when url.Parse fails")
	assert.Contains(t, buf.String(), "invalid URL")
}

func TestProbeWSDLDocument_StatusWriterRecordsProgress(t *testing.T) {
	ts := wsdlServer(t)

	var buf bytes.Buffer
	doc := pipeline.ProbeWSDLDocument(context.Background(), ts.URL, true, &buf)
	require.NotNil(t, doc)
	assert.Contains(t, buf.String(), "wsdl discovery")
}

// ---------------------------------------------------------------------------
// ProbeAndAppendWSDLRequest — happy-path and URL-correctness tests
// ---------------------------------------------------------------------------

func TestProbeAndAppendWSDLRequest_AppendsOnSuccess(t *testing.T) {
	ts := wsdlServer(t)

	initial := []crawl.ObservedRequest{
		{Method: "GET", URL: ts.URL + "/", Response: crawl.ObservedResponse{StatusCode: 200}},
	}

	augmented, foundWSDL, resolvedType := pipeline.ProbeAndAppendWSDLRequest(
		context.Background(), ts.URL, initial, true, nil,
	)

	assert.True(t, foundWSDL)
	assert.Equal(t, pipeline.APITypeWSDL, resolvedType)
	require.Len(t, augmented, 2, "expected one synthetic WSDL request appended")
	synthetic := augmented[1]
	assert.Equal(t, "GET", synthetic.Method)
	assert.Equal(t, "text/xml", synthetic.Response.ContentType)
	assert.Equal(t, 200, synthetic.Response.StatusCode)

	// Verify URL is well-formed (no double ? separator).
	assert.False(t, strings.Count(synthetic.URL, "?") > 1,
		"synthetic URL must not contain more than one '?': %s", synthetic.URL)
	assert.True(t, strings.HasSuffix(synthetic.URL, "?wsdl") || strings.Contains(synthetic.URL, "wsdl"),
		"synthetic URL must reference ?wsdl: %s", synthetic.URL)
}

func TestProbeAndAppendWSDLRequest_NoWSDLReturnsOriginal(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html>not soap</html>")) //nolint:gosec // G104: test code
	}))
	t.Cleanup(ts.Close)

	initial := []crawl.ObservedRequest{{Method: "GET", URL: ts.URL + "/"}}
	augmented, foundWSDL, resolvedType := pipeline.ProbeAndAppendWSDLRequest(
		context.Background(), ts.URL, initial, true, nil,
	)

	assert.False(t, foundWSDL)
	assert.Empty(t, resolvedType)
	assert.Equal(t, initial, augmented, "original slice must be returned unchanged")
}

func TestProbeAndAppendWSDLRequest_URLWithExistingQuery(t *testing.T) {
	// When targetURL already has a query string, the synthetic URL must use
	// RawQuery = "wsdl" (not string concatenation) so there is no double ?.
	ts := wsdlServer(t)
	targetURL := ts.URL + "/service?version=2"

	augmented, foundWSDL, _ := pipeline.ProbeAndAppendWSDLRequest(
		context.Background(), targetURL, nil, true, nil,
	)

	require.True(t, foundWSDL)
	require.Len(t, augmented, 1)

	syntheticURL := augmented[0].URL
	questionCount := strings.Count(syntheticURL, "?")
	assert.Equal(t, 1, questionCount,
		"synthetic URL must have exactly one '?', got %q", syntheticURL)
	assert.True(t, strings.HasSuffix(syntheticURL, "?wsdl"),
		"synthetic URL must end with ?wsdl, got %q", syntheticURL)
}

// ---------------------------------------------------------------------------
// TEST-003: SSRF gate — when allowPrivate=false, ProbeWSDLDocument must reject
// private URLs via probe.ValidateProbeURL. This is the SDK's call path
// (pkg/sdk/capability.go forwards allowPrivate=false).
// ---------------------------------------------------------------------------

func TestProbeWSDLDocument_SSRFRejectsPrivateURL(t *testing.T) {
	var buf bytes.Buffer
	doc := pipeline.ProbeWSDLDocument(context.Background(), "http://127.0.0.1:1/svc", false, &buf)
	assert.Nil(t, doc, "expected nil bytes for SSRF-rejected URL")
	assert.Contains(t, buf.String(), "SSRF protection")
}

// ---------------------------------------------------------------------------
// TEST-004: HTTP >= 400 gate — server-error responses must be rejected before
// ParseWSDL is called.
// ---------------------------------------------------------------------------

func TestProbeWSDLDocument_RejectsHTTPErrorStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(validWSDLDocument))
	}))
	t.Cleanup(ts.Close)

	var buf bytes.Buffer
	doc := pipeline.ProbeWSDLDocument(context.Background(), ts.URL+"/svc", true, &buf)
	assert.Nil(t, doc, "expected nil bytes for HTTP 404")
	assert.Contains(t, buf.String(), "returned HTTP 404")
}

// ---------------------------------------------------------------------------
// ResolveWSDLType — gate function tests
// ---------------------------------------------------------------------------

// TestResolveWSDLType_ProbeDisabledIsNoOp verifies that when probe=false the
// function returns the original requests and apiType unchanged without making
// any network connection (the target URL is deliberately unreachable so any
// accidental probe would produce a detectable error via the status writer).
func TestResolveWSDLType_ProbeDisabledIsNoOp(t *testing.T) {
	initial := []crawl.ObservedRequest{
		{Method: "GET", URL: "http://127.0.0.1:1/svc"},
	}

	var buf bytes.Buffer
	got, resolvedType, found := pipeline.ResolveWSDLType(
		context.Background(),
		"http://127.0.0.1:1/svc",
		pipeline.APITypeWSDL,
		initial,
		false, // probe disabled
		true,
		&buf,
	)

	assert.False(t, found, "probe disabled must return found=false")
	assert.Equal(t, pipeline.APITypeWSDL, resolvedType, "apiType must be returned unchanged on a miss")
	assert.Equal(t, initial, got, "requests slice must be returned unchanged when probe is disabled")
	assert.Empty(t, buf.String(), "no status output expected when probe is disabled")
}

// TestResolveWSDLType_NonWSDLRestTypeIsNoOp verifies that when apiType is
// neither APITypeWSDL nor APITypeREST the probe is skipped even when
// probe=true, returning the original requests and apiType unchanged.
func TestResolveWSDLType_NonWSDLRestTypeIsNoOp(t *testing.T) {
	initial := []crawl.ObservedRequest{
		{Method: "POST", URL: "http://127.0.0.1:1/graphql"},
	}

	var buf bytes.Buffer
	got, resolvedType, found := pipeline.ResolveWSDLType(
		context.Background(),
		"http://127.0.0.1:1/graphql",
		pipeline.APITypeGraphQL,
		initial,
		true, // probe enabled — but apiType is graphql, so must be skipped
		true,
		&buf,
	)

	assert.False(t, found, "graphql apiType must not be probed")
	assert.Equal(t, pipeline.APITypeGraphQL, resolvedType, "apiType must be returned unchanged on a miss")
	assert.Equal(t, initial, got, "requests slice must be returned unchanged for non-WSDL/REST types")
	assert.Empty(t, buf.String(), "no status output expected when gate skips the probe")
}

// TestResolveWSDLType_ProbeSuccessReturnsWSDL verifies that when probe=true,
// apiType is eligible (REST), and the server responds with a valid WSDL
// document, the function returns the augmented slice, APITypeWSDL, and
// found=true. Mirrors the success-path setup from
// TestProbeAndAppendWSDLRequest_AppendsOnSuccess.
func TestResolveWSDLType_ProbeSuccessReturnsWSDL(t *testing.T) {
	ts := wsdlServer(t)

	initial := []crawl.ObservedRequest{
		{Method: "GET", URL: ts.URL + "/", Response: crawl.ObservedResponse{StatusCode: 200}},
	}

	augmented, resolvedType, found := pipeline.ResolveWSDLType(
		context.Background(),
		ts.URL,
		pipeline.APITypeREST,
		initial,
		true, // probe enabled
		true,
		nil,
	)

	assert.True(t, found, "expected found=true when server serves a valid WSDL")
	assert.Equal(t, pipeline.APITypeWSDL, resolvedType, "apiType must be promoted to wsdl on success")
	require.Len(t, augmented, 2, "one synthetic WSDL request must be appended to original slice")
	assert.Equal(t, "GET", augmented[1].Method)
	assert.Equal(t, "text/xml", augmented[1].Response.ContentType)
}

// TestResolveWSDLType_ProbeFailureRetainsInputType verifies that when
// probe=true but the server does not serve a valid WSDL document, the original
// requests slice and input apiType are returned unchanged and found=false.
func TestResolveWSDLType_ProbeFailureRetainsInputType(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>not soap</html>"))
	}))
	t.Cleanup(ts.Close)

	initial := []crawl.ObservedRequest{
		{Method: "GET", URL: ts.URL + "/"},
	}

	got, resolvedType, found := pipeline.ResolveWSDLType(
		context.Background(),
		ts.URL,
		pipeline.APITypeREST,
		initial,
		true, // probe enabled
		true,
		nil,
	)

	assert.False(t, found, "probe finding no WSDL must return found=false")
	assert.Equal(t, pipeline.APITypeREST, resolvedType, "input apiType must be preserved when no WSDL found")
	assert.Equal(t, initial, got, "original requests slice must be returned unchanged")
}
