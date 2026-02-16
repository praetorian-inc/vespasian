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
			name: "malformed response status line",
			xml:  `<?xml version="1.0"?><items><item><url>https://example.com/test</url><request base64="false">GET / HTTP/1.1\r\nHost: test.com\r\n\r\n</request><response base64="false">HTTP/1.1\r\n\r\n</response></item></items>`,
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

func TestBurpImporter_XXEPrevention(t *testing.T) {
	tests := []struct {
		name    string
		xml     string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "DOCTYPE declaration rejected",
			xml:     `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "test">]><items></items>`,
			wantErr: true,
			errMsg:  "DOCTYPE or ENTITY",
		},
		{
			name:    "ENTITY declaration rejected",
			xml:     `<?xml version="1.0"?><!ENTITY xxe SYSTEM "file:///etc/passwd"><items></items>`,
			wantErr: true,
			errMsg:  "DOCTYPE or ENTITY",
		},
		{
			name:    "lowercase doctype rejected",
			xml:     `<?xml version="1.0"?><!doctype foo><items></items>`,
			wantErr: true,
			errMsg:  "DOCTYPE or ENTITY",
		},
		{
			name:    "mixed case DOCTYPE rejected",
			xml:     `<?xml version="1.0"?><!DocType foo><items></items>`,
			wantErr: true,
			errMsg:  "DOCTYPE or ENTITY",
		},
		{
			name:    "mixed case ENTITY rejected",
			xml:     `<?xml version="1.0"?><!EnTiTy xxe "test"><items></items>`,
			wantErr: true,
			errMsg:  "DOCTYPE or ENTITY",
		},
		{
			name:    "valid XML without DOCTYPE passes",
			xml:     `<?xml version="1.0"?><items></items>`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &BurpImporter{}
			_, err := b.Import(strings.NewReader(tt.xml))
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
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
