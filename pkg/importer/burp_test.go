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
)

func TestBurpImporter_Name(t *testing.T) {
	b := &BurpImporter{}
	if b.Name() != "burp" {
		t.Errorf("Name() = %q, want %q", b.Name(), "burp")
	}
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
			if err != nil {
				t.Fatalf("Import() error = %v", err)
			}

			if len(requests) != tt.wantRequests {
				t.Fatalf("Import() returned %d requests, want %d", len(requests), tt.wantRequests)
			}

			if tt.wantRequests > 0 {
				req := requests[0]

				if tt.wantMethod != "" && req.Method != tt.wantMethod {
					t.Errorf("Method = %q, want %q", req.Method, tt.wantMethod)
				}

				if tt.wantURL != "" && req.URL != tt.wantURL {
					t.Errorf("URL = %q, want %q", req.URL, tt.wantURL)
				}

				if tt.wantSource != "" && req.Source != tt.wantSource {
					t.Errorf("Source = %q, want %q", req.Source, tt.wantSource)
				}

				if tt.wantStatus != 0 && req.Response.StatusCode != tt.wantStatus {
					t.Errorf("Response.StatusCode = %d, want %d", req.Response.StatusCode, tt.wantStatus)
				}

				if tt.wantReqBody != "" && string(req.Body) != tt.wantReqBody {
					t.Errorf("Body = %q, want %q", string(req.Body), tt.wantReqBody)
				}

				if tt.wantRespBody != "" && string(req.Response.Body) != tt.wantRespBody {
					t.Errorf("Response.Body = %q, want %q", string(req.Response.Body), tt.wantRespBody)
				}

				// Verify headers are parsed
				if len(req.Headers) == 0 {
					t.Error("Headers should not be empty")
				}
				if len(req.Response.Headers) == 0 {
					t.Error("Response.Headers should not be empty")
				}
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &BurpImporter{}
			_, err := b.Import(strings.NewReader(tt.xml))
			if (err != nil) != tt.wantErr {
				t.Errorf("Import() error = %v, wantErr %v", err, tt.wantErr)
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
				if err == nil {
					t.Error("expected error but got nil")
				} else if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("error = %q, want to contain %q", err.Error(), tt.errMsg)
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
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
	if err != nil {
		t.Fatalf("Import() error = %v", err)
	}

	if len(requests) != 1 {
		t.Fatalf("Import() returned %d requests, want 1", len(requests))
	}

	req := requests[0]
	wantContentType := "application/json; charset=utf-8"
	if req.Response.ContentType != wantContentType {
		t.Errorf("Response.ContentType = %q, want %q", req.Response.ContentType, wantContentType)
	}
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
	if err != nil {
		t.Fatalf("Import() error = %v", err)
	}

	if len(requests) != 1 {
		t.Fatalf("Import() returned %d requests, want 1", len(requests))
	}

	req := requests[0]
	if req.QueryParams == nil {
		t.Fatal("QueryParams should not be nil")
	}

	wantParams := map[string]string{
		"page":  "1",
		"limit": "10",
	}

	if len(req.QueryParams) != len(wantParams) {
		t.Errorf("QueryParams has %d entries, want %d", len(req.QueryParams), len(wantParams))
	}

	for key, want := range wantParams {
		if got, ok := req.QueryParams[key]; !ok {
			t.Errorf("QueryParams missing key %q", key)
		} else if got != want {
			t.Errorf("QueryParams[%q] = %q, want %q", key, got, want)
		}
	}
}
