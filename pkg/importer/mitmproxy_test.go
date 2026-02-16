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

func TestMitmproxyImporter_Name(t *testing.T) {
	m := &MitmproxyImporter{}
	assert.Equal(t, "mitmproxy", m.Name())
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
		{
			name:         "empty array",
			json:         `[]`,
			wantRequests: 0,
		},
		{
			name: "whitespace before valid object",
			json: `   {
				"request": {
					"method": "GET",
					"scheme": "https",
					"host": "example.com",
					"port": 443,
					"path": "/api",
					"headers": [],
					"content": null
				},
				"response": {
					"status_code": 200,
					"headers": [],
					"content": null
				}
			}`,
			wantRequests: 1,
			wantMethod:   "GET",
			wantURL:      "https://example.com/api",
			wantSource:   "import:mitmproxy",
			wantStatus:   200,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &MitmproxyImporter{}
			requests, err := m.Import(strings.NewReader(tt.json))
			require.NoError(t, err)

			assert.Len(t, requests, tt.wantRequests)

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

				// Verify headers are parsed (if present in test case)
				if tt.wantMethod == "GET" && strings.Contains(tt.json, "User-Agent") {
					assert.NotEmpty(t, req.Headers)
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
		{
			name:    "invalid JSON type number",
			json:    "123",
			wantErr: true,
		},
		{
			name:    "invalid JSON type string",
			json:    `"hello"`,
			wantErr: true,
		},
		{
			name:    "empty input",
			json:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &MitmproxyImporter{}
			_, err := m.Import(strings.NewReader(tt.json))
			assert.True(t, (err != nil) == tt.wantErr, "Import() error = %v, wantErr %v", err, tt.wantErr)
		})
	}
}

func TestMitmproxyImporter_ContentType(t *testing.T) {
	json := `{
		"request": {
			"method": "GET",
			"scheme": "https",
			"host": "example.com",
			"port": 443,
			"path": "/api",
			"headers": []
		},
		"response": {
			"status_code": 200,
			"headers": [
				["Content-Type", "application/json; charset=utf-8"]
			],
			"content": "e30="
		}
	}`

	m := &MitmproxyImporter{}
	requests, err := m.Import(strings.NewReader(json))
	require.NoError(t, err)

	require.Len(t, requests, 1)

	req := requests[0]
	wantContentType := "application/json; charset=utf-8"
	assert.Equal(t, wantContentType, req.Response.ContentType)
}

func TestMitmproxyImporter_QueryParams(t *testing.T) {
	json := `{
		"request": {
			"method": "GET",
			"scheme": "https",
			"host": "example.com",
			"port": 443,
			"path": "/api?page=1&limit=10",
			"headers": []
		},
		"response": {
			"status_code": 200,
			"headers": [],
			"content": null
		}
	}`

	m := &MitmproxyImporter{}
	requests, err := m.Import(strings.NewReader(json))
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
