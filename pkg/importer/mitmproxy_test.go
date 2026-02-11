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

func TestMitmproxyImporter_Name(t *testing.T) {
	m := &MitmproxyImporter{}
	if m.Name() != "mitmproxy" {
		t.Errorf("Name() = %q, want %q", m.Name(), "mitmproxy")
	}
}

func TestMitmproxyImporter_Import(t *testing.T) {
	reqBody := []byte(`{"test":"data"}`)
	respBody := []byte(`{"id":123}`)

	tests := []struct {
		name         string
		json         string
		wantRequests int
		wantMethod   string
		wantURL      string
		wantSource   string
		wantStatus   int
		wantReqBody  string
		wantRespBody string
	}{
		{
			name: "GET request https default port",
			json: `{
				"request": {
					"method": "GET",
					"scheme": "https",
					"host": "example.com",
					"port": 443,
					"path": "/api?page=1",
					"headers": [
						["User-Agent", "Test"],
						["Accept", "application/json"]
					],
					"content": null
				},
				"response": {
					"status_code": 200,
					"headers": [
						["Content-Type", "application/json"]
					],
					"content": "` + base64.StdEncoding.EncodeToString(respBody) + `"
				}
			}`,
			wantRequests: 1,
			wantMethod:   "GET",
			wantURL:      "https://example.com/api?page=1",
			wantSource:   "import:mitmproxy",
			wantStatus:   200,
			wantRespBody: `{"id":123}`,
		},
		{
			name: "POST request with body non-default port",
			json: `{
				"request": {
					"method": "POST",
					"scheme": "http",
					"host": "example.com",
					"port": 8080,
					"path": "/api/data",
					"headers": [
						["Content-Type", "application/json"]
					],
					"content": "` + base64.StdEncoding.EncodeToString(reqBody) + `"
				},
				"response": {
					"status_code": 201,
					"headers": [
						["Content-Type", "application/json"]
					],
					"content": "` + base64.StdEncoding.EncodeToString(respBody) + `"
				}
			}`,
			wantRequests: 1,
			wantMethod:   "POST",
			wantURL:      "http://example.com:8080/api/data",
			wantSource:   "import:mitmproxy",
			wantStatus:   201,
			wantReqBody:  `{"test":"data"}`,
			wantRespBody: `{"id":123}`,
		},
		{
			name: "array of flows",
			json: `[
				{
					"request": {
						"method": "GET",
						"scheme": "https",
						"host": "example.com",
						"port": 443,
						"path": "/first",
						"headers": [],
						"content": null
					},
					"response": {
						"status_code": 200,
						"headers": [],
						"content": null
					}
				},
				{
					"request": {
						"method": "GET",
						"scheme": "https",
						"host": "example.com",
						"port": 443,
						"path": "/second",
						"headers": [],
						"content": null
					},
					"response": {
						"status_code": 200,
						"headers": [],
						"content": null
					}
				}
			]`,
			wantRequests: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &MitmproxyImporter{}
			requests, err := m.Import(strings.NewReader(tt.json))
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

				// Verify headers are parsed (if present in test case)
				if tt.wantMethod == "GET" && strings.Contains(tt.json, "User-Agent") {
					if len(req.Headers) == 0 {
						t.Error("Headers should not be empty")
					}
				}
			}
		})
	}
}

func TestMitmproxyImporter_Import_Errors(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		wantErr bool
	}{
		{
			name:    "invalid json",
			json:    "not json",
			wantErr: true,
		},
		{
			name: "invalid base64 content",
			json: `{
				"request": {
					"method": "GET",
					"scheme": "https",
					"host": "example.com",
					"port": 443,
					"path": "/test",
					"headers": [],
					"content": "!!!invalid-base64!!!"
				},
				"response": {
					"status_code": 200,
					"headers": [],
					"content": null
				}
			}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &MitmproxyImporter{}
			_, err := m.Import(strings.NewReader(tt.json))
			if (err != nil) != tt.wantErr {
				t.Errorf("Import() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
