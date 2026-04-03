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

package importer

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBurpImporter_Name(t *testing.T) {
	b := &BurpImporter{}
	assert.Equal(t, "burp", b.Name())
}

func TestBurpImporter_Import(t *testing.T) {
	// Sample GET request
	getRequest := "GET /api HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Test\r\n\r\n"
	getResponse := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 13\r\n\r\n{\"ok\":true}"

	// Sample POST request with body
	postRequest := "POST /api/data HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n{\"test\":\"data\"}"
	postResponse := "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\n\r\n{\"id\":123}"

	tests := []struct {
		name         string
		xml          string
		wantRequests int
		wantMethod   string
		wantURL      string
		wantSource   string
		wantStatus   int
		wantReqBody  string
		wantRespBody string
	}{
		{
			name: "base64 encoded GET request",
			xml: `<?xml version="1.0"?>
<items>
  <item>
    <url>https://example.com/api</url>
    <host ip="1.2.3.4">example.com</host>
    <port>443</port>
    <protocol>https</protocol>
    <method>GET</method>
    <path>/api</path>
    <request base64="true"><![CDATA[` + base64.StdEncoding.EncodeToString([]byte(getRequest)) + `]]></request>
    <status>200</status>
    <response base64="true"><![CDATA[` + base64.StdEncoding.EncodeToString([]byte(getResponse)) + `]]></response>
  </item>
</items>`,
			wantRequests: 1,
			wantMethod:   "GET",
			wantURL:      "https://example.com/api",
			wantSource:   "import:burp",
			wantStatus:   200,
			wantReqBody:  "",
			wantRespBody: `{"ok":true}`,
		},
		{
			name: "base64 encoded POST request with body",
			xml: `<?xml version="1.0"?>
<items>
  <item>
    <url>https://example.com/api/data</url>
    <host>example.com</host>
    <port>443</port>
    <protocol>https</protocol>
    <method>POST</method>
    <path>/api/data</path>
    <request base64="true"><![CDATA[` + base64.StdEncoding.EncodeToString([]byte(postRequest)) + `]]></request>
    <status>201</status>
    <response base64="true"><![CDATA[` + base64.StdEncoding.EncodeToString([]byte(postResponse)) + `]]></response>
  </item>
</items>`,
			wantRequests: 1,
			wantMethod:   "POST",
			wantURL:      "https://example.com/api/data",
			wantSource:   "import:burp",
			wantStatus:   201,
			wantReqBody:  `{"test":"data"}`,
			wantRespBody: `{"id":123}`,
		},
		{
			name: "non-base64 encoded request",
			xml: `<?xml version="1.0"?>
<items>
  <item>
    <url>https://example.com/test</url>
    <host>example.com</host>
    <port>443</port>
    <protocol>https</protocol>
    <method>GET</method>
    <path>/test</path>
    <request base64="false"><![CDATA[` + getRequest + `]]></request>
    <status>200</status>
    <response base64="false"><![CDATA[` + getResponse + `]]></response>
  </item>
</items>`,
			wantRequests: 1,
			wantMethod:   "GET",
			wantURL:      "https://example.com/test",
			wantSource:   "import:burp",
			wantStatus:   200,
		},
		{
			name: "multiple items",
			xml: `<?xml version="1.0"?>
<items>
  <item>
    <url>https://example.com/first</url>
    <host>example.com</host>
    <port>443</port>
    <protocol>https</protocol>
    <method>GET</method>
    <path>/first</path>
    <request base64="true"><![CDATA[` + base64.StdEncoding.EncodeToString([]byte(getRequest)) + `]]></request>
    <status>200</status>
    <response base64="true"><![CDATA[` + base64.StdEncoding.EncodeToString([]byte(getResponse)) + `]]></response>
  </item>
  <item>
    <url>https://example.com/second</url>
    <host>example.com</host>
    <port>443</port>
    <protocol>https</protocol>
    <method>GET</method>
    <path>/second</path>
    <request base64="true"><![CDATA[` + base64.StdEncoding.EncodeToString([]byte(getRequest)) + `]]></request>
    <status>200</status>
    <response base64="true"><![CDATA[` + base64.StdEncoding.EncodeToString([]byte(getResponse)) + `]]></response>
  </item>
</items>`,
			wantRequests: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &BurpImporter{}
			requests, err := b.Import(strings.NewReader(tt.xml))
			require.NoError(t, err)

			require.Len(t, requests, tt.wantRequests)

			if tt.wantRequests > 0 {
				req := requests[0]

				if tt.wantMethod != "" {
					assert.Equal(t, tt.wantMethod, req.Method)
				}

				if tt.wantURL != "" {
					assert.Equal(t, tt.wantURL, req.URL)
				}

				if tt.wantSource != "" {
					assert.Equal(t, tt.wantSource, req.Source)
				}

				if tt.wantStatus != 0 {
					assert.Equal(t, tt.wantStatus, req.Response.StatusCode)
				}

				if tt.wantReqBody != "" {
					assert.Equal(t, tt.wantReqBody, string(req.Body))
				}

				if tt.wantRespBody != "" {
					assert.Equal(t, tt.wantRespBody, string(req.Response.Body))
				}

				// Verify headers are parsed
				assert.NotEmpty(t, req.Headers)
				assert.NotEmpty(t, req.Response.Headers)
			}
		})
	}
}

func TestBurpImporter_Import_Errors(t *testing.T) {
	tests := []struct {
		name    string
		xml     string
		wantErr bool
	}{
		{
			name:    "invalid xml",
			xml:     "not xml at all",
			wantErr: true,
		},
		{
			name: "invalid base64",
			xml: `<?xml version="1.0"?>
<items>
  <item>
    <url>https://example.com/api</url>
    <request base64="true"><![CDATA[!!!invalid-base64!!!]]></request>
    <status>200</status>
    <response base64="true"><![CDATA[dGVzdA==]]></response>
  </item>
</items>`,
			wantErr: true,
		},
		{
			name:    "malformed response status line",
			xml:     `<?xml version="1.0"?><items><item><url>https://example.com/test</url><request base64="false">GET / HTTP/1.1\r\nHost: test.com\r\n\r\n</request><response base64="false">HTTP/1.1\r\n\r\n</response></item></items>`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &BurpImporter{}
			_, err := b.Import(strings.NewReader(tt.xml))
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestBurpImporter_XXESafety verifies that Go's encoding/xml safely handles
// ENTITY declarations without resolving external entities. The XML parser
// provides XXE protection by default — no pre-scan rejection is needed.
func TestBurpImporter_XXESafety(t *testing.T) {
	tests := []struct {
		name    string
		xml     string
		wantErr bool
	}{
		{
			name:    "valid XML without DOCTYPE passes",
			xml:     `<?xml version="1.0"?><items></items>`,
			wantErr: false,
		},
		{
			name:    "Burp Suite XML with DOCTYPE passes",
			xml:     `<?xml version="1.0"?><!DOCTYPE items [<!ELEMENT items (item)*><!ELEMENT item (url|request|status|response)*>]><items><item><url>http://example.com</url><request base64="true">R0VUIC8gSFRUUC8xLjENCkhvc3Q6IGV4YW1wbGUuY29tDQoNCg==</request><status>200</status><response base64="true">SFRUUC8xLjEgMjAwIE9LDQpDb250ZW50LVR5cGU6IHRleHQvaHRtbA0KDQpPSw==</response></item></items>`,
			wantErr: false,
		},
		{
			name:    "DOCTYPE with internal ENTITY parsed safely",
			xml:     `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "test">]><items></items>`,
			wantErr: false,
		},
		{
			name:    "lowercase doctype passes",
			xml:     `<?xml version="1.0"?><!doctype foo><items></items>`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &BurpImporter{}
			_, err := b.Import(strings.NewReader(tt.xml))
			if tt.wantErr {
				require.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestBurpImporter_ContentType(t *testing.T) {
	xml := `<?xml version="1.0"?>
<items>
	<item>
		<url>https://example.com/api</url>
		<request base64="true">R0VUIC9hcGkgSFRUUC8xLjENCkhvc3Q6IGV4YW1wbGUuY29tDQoNCg==</request>
		<status>200</status>
		<response base64="true">SFRUUC8xLjEgMjAwIE9LDQpDb250ZW50LVR5cGU6IGFwcGxpY2F0aW9uL2pzb247IGNoYXJzZXQ9dXRmLTgNCg0Ke30=</response>
	</item>
</items>`

	b := &BurpImporter{}
	requests, err := b.Import(strings.NewReader(xml))
	require.NoError(t, err)

	require.Len(t, requests, 1)

	req := requests[0]
	wantContentType := "application/json; charset=utf-8"
	assert.Equal(t, wantContentType, req.Response.ContentType)
}

func TestBurpImporter_QueryParams(t *testing.T) {
	xml := `<?xml version="1.0"?>
<items>
	<item>
		<url>https://example.com/api?page=1&amp;limit=10</url>
		<request base64="true">R0VUIC9hcGk/cGFnZT0xJmxpbWl0PTEwIEhUVFAvMS4xDQpIb3N0OiBleGFtcGxlLmNvbQ0KDQo=</request>
		<status>200</status>
		<response base64="true">SFRUUC8xLjEgMjAwIE9LDQoNCg==</response>
	</item>
</items>`

	b := &BurpImporter{}
	requests, err := b.Import(strings.NewReader(xml))
	require.NoError(t, err)

	require.Len(t, requests, 1)

	req := requests[0]
	require.NotNil(t, req.QueryParams)

	wantParams := map[string]string{
		"page":  "1",
		"limit": "10",
	}

	assert.Len(t, req.QueryParams, len(wantParams))

	for key, want := range wantParams {
		assert.Contains(t, req.QueryParams, key)
		assert.Equal(t, want, req.QueryParams[key])
	}
}

func TestBurpImporter_DuplicateHeaders(t *testing.T) {
	// Test that duplicate headers use "last wins" behavior
	requestWithDuplicates := "GET /api HTTP/1.1\r\nHost: example.com\r\nX-Custom: first\r\nX-Custom: second\r\nX-Custom: last\r\n\r\n"
	response := "HTTP/1.1 200 OK\r\n\r\n"

	xml := `<?xml version="1.0"?>
<items>
	<item>
		<url>https://example.com/api</url>
		<request base64="true">` + base64.StdEncoding.EncodeToString([]byte(requestWithDuplicates)) + `</request>
		<status>200</status>
		<response base64="true">` + base64.StdEncoding.EncodeToString([]byte(response)) + `</response>
	</item>
</items>`

	b := &BurpImporter{}
	requests, err := b.Import(strings.NewReader(xml))
	require.NoError(t, err)
	require.Len(t, requests, 1)

	req := requests[0]
	// Duplicate headers: last wins
	assert.Equal(t, "last", req.Headers["X-Custom"])
}

func TestBurpImporter_InvalidHTTPMethod(t *testing.T) {
	xml := `<?xml version="1.0"?>
<items>
	<item>
		<url>https://example.com</url>
		<request base64="false">INVALID /api HTTP/1.1
Host: example.com

</request>
		<status>200</status>
		<response base64="false">HTTP/1.1 200 OK

</response>
	</item>
</items>`

	b := &BurpImporter{}
	_, err := b.Import(strings.NewReader(xml))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid HTTP method")
}

func TestBurpImporter_MalformedStatusCode(t *testing.T) {
	// Test with non-numeric status code
	xml := `<?xml version="1.0"?>
<items>
	<item>
		<url>https://example.com</url>
		<request base64="false">GET /api HTTP/1.1
Host: example.com

</request>
		<status>200</status>
		<response base64="false">HTTP/1.1 abc OK

</response>
	</item>
</items>`

	b := &BurpImporter{}
	_, err := b.Import(strings.NewReader(xml))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid status code")
}

func TestBurpImporter_MalformedRequestLine(t *testing.T) {
	// Test with missing HTTP version
	xml := `<?xml version="1.0"?>
<items>
	<item>
		<url>https://example.com</url>
		<request base64="false">GET

</request>
		<status>200</status>
		<response base64="false">HTTP/1.1 200 OK

</response>
	</item>
</items>`

	b := &BurpImporter{}
	_, err := b.Import(strings.NewReader(xml))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid request line")
}

func TestBurpImporter_EmptyRequestBody(t *testing.T) {
	// GET request should have nil body
	getRequest := "GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"
	getResponse := "HTTP/1.1 200 OK\r\n\r\n"

	xml := `<?xml version="1.0"?>
<items>
	<item>
		<url>https://example.com/api</url>
		<request base64="true">` + base64.StdEncoding.EncodeToString([]byte(getRequest)) + `</request>
		<status>200</status>
		<response base64="true">` + base64.StdEncoding.EncodeToString([]byte(getResponse)) + `</response>
	</item>
</items>`

	b := &BurpImporter{}
	requests, err := b.Import(strings.NewReader(xml))
	require.NoError(t, err)
	require.Len(t, requests, 1)

	// Body should be nil for empty body (not []byte{})
	assert.Nil(t, requests[0].Body)
	assert.Nil(t, requests[0].Response.Body)
}

func TestBurpImporter_StatusOverride(t *testing.T) {
	// Verify that XML status overrides parsed response status
	getRequest := "GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"
	getResponse := "HTTP/1.1 500 Internal Server Error\r\n\r\n"

	xml := `<?xml version="1.0"?>
<items>
	<item>
		<url>https://example.com/api</url>
		<request base64="true">` + base64.StdEncoding.EncodeToString([]byte(getRequest)) + `</request>
		<status>200</status>
		<response base64="true">` + base64.StdEncoding.EncodeToString([]byte(getResponse)) + `</response>
	</item>
</items>`

	b := &BurpImporter{}
	requests, err := b.Import(strings.NewReader(xml))
	require.NoError(t, err)
	require.Len(t, requests, 1)

	// XML status (200) should override parsed response status (500)
	assert.Equal(t, 200, requests[0].Response.StatusCode)
}

func TestBurpImporter_LFOnlyLineEndings(t *testing.T) {
	// Test with LF-only line endings (instead of CRLF)
	getRequest := "GET /api HTTP/1.1\nHost: example.com\n\n"
	getResponse := "HTTP/1.1 200 OK\nContent-Type: text/plain\n\nOK"

	xml := `<?xml version="1.0"?>
<items>
	<item>
		<url>https://example.com/api</url>
		<request base64="true">` + base64.StdEncoding.EncodeToString([]byte(getRequest)) + `</request>
		<status>200</status>
		<response base64="true">` + base64.StdEncoding.EncodeToString([]byte(getResponse)) + `</response>
	</item>
</items>`

	b := &BurpImporter{}
	requests, err := b.Import(strings.NewReader(xml))
	require.NoError(t, err)
	require.Len(t, requests, 1)

	// Should parse successfully with LF-only endings
	assert.Equal(t, "GET", requests[0].Method)
	assert.Equal(t, "example.com", requests[0].Headers["Host"])
	assert.Equal(t, "OK", string(requests[0].Response.Body))
}

func TestBurpImporter_HeaderWithEmptyValue(t *testing.T) {
	// Header with empty value should still be included
	getRequest := "GET /api HTTP/1.1\r\nHost: example.com\r\nX-Empty:\r\nX-Valid: value\r\n\r\n"
	getResponse := "HTTP/1.1 200 OK\r\n\r\n"

	xml := `<?xml version="1.0"?>
<items>
	<item>
		<url>https://example.com/api</url>
		<request base64="true">` + base64.StdEncoding.EncodeToString([]byte(getRequest)) + `</request>
		<status>200</status>
		<response base64="true">` + base64.StdEncoding.EncodeToString([]byte(getResponse)) + `</response>
	</item>
</items>`

	b := &BurpImporter{}
	requests, err := b.Import(strings.NewReader(xml))
	require.NoError(t, err)
	require.Len(t, requests, 1)

	// Empty value header should be included with empty string value
	assert.Equal(t, "", requests[0].Headers["X-Empty"])
	assert.Equal(t, "value", requests[0].Headers["X-Valid"])
}

func TestBurpImporter_InvalidResponseBase64(t *testing.T) {
	// Valid request but invalid base64 response
	getRequest := "GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"

	xml := `<?xml version="1.0"?>
<items>
	<item>
		<url>https://example.com/api</url>
		<request base64="true">` + base64.StdEncoding.EncodeToString([]byte(getRequest)) + `</request>
		<status>200</status>
		<response base64="true">!!!invalid-base64-data!!!</response>
	</item>
</items>`

	b := &BurpImporter{}
	_, err := b.Import(strings.NewReader(xml))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode response")
}

func TestBurpImporter_ResponseNoSeparator(t *testing.T) {
	// Response without header/body separator
	getRequest := "GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"
	badResponse := "HTTP/1.1 200 OK"

	xml := `<?xml version="1.0"?>
<items>
	<item>
		<url>https://example.com/api</url>
		<request base64="true">` + base64.StdEncoding.EncodeToString([]byte(getRequest)) + `</request>
		<status>200</status>
		<response base64="true">` + base64.StdEncoding.EncodeToString([]byte(badResponse)) + `</response>
	</item>
</items>`

	b := &BurpImporter{}
	_, err := b.Import(strings.NewReader(xml))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

func TestBurpImporter_RequestNoSeparator(t *testing.T) {
	// Request without header/body separator
	badRequest := "GET /api HTTP/1.1"
	getResponse := "HTTP/1.1 200 OK\r\n\r\n"

	xml := `<?xml version="1.0"?>
<items>
	<item>
		<url>https://example.com/api</url>
		<request base64="true">` + base64.StdEncoding.EncodeToString([]byte(badRequest)) + `</request>
		<status>200</status>
		<response base64="true">` + base64.StdEncoding.EncodeToString([]byte(getResponse)) + `</response>
	</item>
</items>`

	b := &BurpImporter{}
	_, err := b.Import(strings.NewReader(xml))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse request")
}

func TestBurpImporter_InvalidResponseStatusLine(t *testing.T) {
	// Response with incomplete status line (less than 2 parts)
	getRequest := "GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"
	badResponse := "HTTP/1.1\r\n\r\n" // Missing status code

	xml := `<?xml version="1.0"?>
<items>
	<item>
		<url>https://example.com/api</url>
		<request base64="true">` + base64.StdEncoding.EncodeToString([]byte(getRequest)) + `</request>
		<status>0</status>
		<response base64="true">` + base64.StdEncoding.EncodeToString([]byte(badResponse)) + `</response>
	</item>
</items>`

	b := &BurpImporter{}
	_, err := b.Import(strings.NewReader(xml))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid status line")
}

func TestBurpImporter_MinimalResponse(t *testing.T) {
	// Response with only status line (no headers)
	getRequest := "GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"
	minimalResponse := "HTTP/1.1 200 OK\r\n\r\n" // Only status line, no headers

	xml := `<?xml version="1.0"?>
<items>
	<item>
		<url>https://example.com/api</url>
		<request base64="true">` + base64.StdEncoding.EncodeToString([]byte(getRequest)) + `</request>
		<status>200</status>
		<response base64="true">` + base64.StdEncoding.EncodeToString([]byte(minimalResponse)) + `</response>
	</item>
</items>`

	b := &BurpImporter{}
	requests, err := b.Import(strings.NewReader(xml))
	require.NoError(t, err)
	require.Len(t, requests, 1)
	assert.Equal(t, 200, requests[0].Response.StatusCode)
}

func TestBurpImporter_ResponseWithEmptyLines(t *testing.T) {
	// Response with empty lines in header section
	getRequest := "GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"
	responseWithEmptyLines := "HTTP/1.1 200 OK\r\n\r\n\r\nBody content"

	xml := `<?xml version="1.0"?>
<items>
	<item>
		<url>https://example.com/api</url>
		<request base64="true">` + base64.StdEncoding.EncodeToString([]byte(getRequest)) + `</request>
		<status>200</status>
		<response base64="true">` + base64.StdEncoding.EncodeToString([]byte(responseWithEmptyLines)) + `</response>
	</item>
</items>`

	b := &BurpImporter{}
	requests, err := b.Import(strings.NewReader(xml))
	require.NoError(t, err)
	require.Len(t, requests, 1)
}

func TestBurpImporter_HeadersWithBlankLines(t *testing.T) {
	// Headers with blank lines between them (unusual but valid per splitHTTPMessage)
	// The blank line check (len(line) == 0) in splitHTTPMessage needs to be exercised
	getRequest := "GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"
	// Response with blank line BETWEEN headers (before separator)
	responseWithBlankHeader := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nX-Custom: value\r\n\r\nBody"

	xml := `<?xml version="1.0"?>
<items>
	<item>
		<url>https://example.com/api</url>
		<request base64="true">` + base64.StdEncoding.EncodeToString([]byte(getRequest)) + `</request>
		<status>200</status>
		<response base64="true">` + base64.StdEncoding.EncodeToString([]byte(responseWithBlankHeader)) + `</response>
	</item>
</items>`

	b := &BurpImporter{}
	requests, err := b.Import(strings.NewReader(xml))
	require.NoError(t, err)
	require.Len(t, requests, 1)
	assert.Equal(t, "text/html", requests[0].Response.Headers["Content-Type"])
}

func TestBurpImporter_EmptyResponse(t *testing.T) {
	// Simulate a timeout/connection reset where Burp records an empty response
	getRequest := "GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"

	xml := `<?xml version="1.0"?>
<items>
	<item>
		<url>https://example.com/api</url>
		<request base64="true">` + base64.StdEncoding.EncodeToString([]byte(getRequest)) + `</request>
		<status>504</status>
		<!-- base64("") == "" — simulates Burp's <response base64="true"></response> for timed-out requests -->
		<response base64="true">` + base64.StdEncoding.EncodeToString([]byte("")) + `</response>
	</item>
</items>`

	b := &BurpImporter{}
	requests, err := b.Import(strings.NewReader(xml))
	require.NoError(t, err)
	require.Len(t, requests, 1)

	req := requests[0]
	assert.Equal(t, "GET", req.Method)
	assert.Equal(t, "https://example.com/api", req.URL)
	assert.Equal(t, "import:burp", req.Source)
	assert.Equal(t, 504, req.Response.StatusCode)
	assert.Empty(t, req.Response.Headers)
	assert.Nil(t, req.Response.Body)
}

func TestBurpImporter_EmptyResponseNonBase64(t *testing.T) {
	// Non-base64 empty response element (no base64 attribute or base64="false")
	getRequest := "GET /page HTTP/1.1\r\nHost: example.com\r\n\r\n"

	xml := `<?xml version="1.0"?>
<items>
	<item>
		<url>https://example.com/page</url>
		<request base64="true">` + base64.StdEncoding.EncodeToString([]byte(getRequest)) + `</request>
		<status>0</status>
		<response></response>
	</item>
</items>`

	b := &BurpImporter{}
	requests, err := b.Import(strings.NewReader(xml))
	require.NoError(t, err)
	require.Len(t, requests, 1)

	req := requests[0]
	assert.Equal(t, "GET", req.Method)
	assert.Equal(t, "https://example.com/page", req.URL)
	assert.Equal(t, "import:burp", req.Source)
	assert.Equal(t, 0, req.Response.StatusCode)
	assert.Empty(t, req.Response.Headers)
	assert.Nil(t, req.Response.Body)
}
