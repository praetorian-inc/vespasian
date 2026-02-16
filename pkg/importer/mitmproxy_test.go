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
	"fmt"
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

func TestMitmproxyImporter_InvalidPort(t *testing.T) {
	tests := []struct {
		name    string
		port    int
		wantErr string
	}{
		{
			name:    "negative port",
			port:    -1,
			wantErr: "invalid port: -1 (must be 0-65535)",
		},
		{
			name:    "port too large",
			port:    65536,
			wantErr: "invalid port: 65536 (must be 0-65535)",
		},
		{
			name:    "very large port",
			port:    100000,
			wantErr: "invalid port: 100000 (must be 0-65535)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			json := `{
				"request": {
					"method": "GET",
					"scheme": "https",
					"host": "example.com",
					"port": ` + strings.Replace(strings.Replace(`PORT`, "PORT", "", 1), "", fmt.Sprintf("%d", tt.port), 1) + `,
					"path": "/api",
					"headers": []
				},
				"response": {
					"status_code": 200,
					"headers": [],
					"content": null
				}
			}`
			// Build JSON with port value
			json = strings.Replace(json, "PORT", "", 1)
			json = `{
				"request": {
					"method": "GET",
					"scheme": "https",
					"host": "example.com",
					"port": ` + fmt.Sprintf("%d", tt.port) + `,
					"path": "/api",
					"headers": []
				},
				"response": {
					"status_code": 200,
					"headers": [],
					"content": null
				}
			}`

			m := &MitmproxyImporter{}
			_, err := m.Import(strings.NewReader(json))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestMitmproxyImporter_InvalidResponseContent(t *testing.T) {
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
			"headers": [],
			"content": "!!!invalid-base64!!!"
		}
	}`

	m := &MitmproxyImporter{}
	_, err := m.Import(strings.NewReader(json))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode response content")
}

func TestMitmproxyImporter_EmptyHeaderNames(t *testing.T) {
	json := `{
		"request": {
			"method": "GET",
			"scheme": "https",
			"host": "example.com",
			"port": 443,
			"path": "/api",
			"headers": [
				["", "empty-name-value"],
				["Valid-Header", "valid-value"],
				["", "another-empty"],
				["Another-Valid", "another-value"]
			]
		},
		"response": {
			"status_code": 200,
			"headers": [
				["Content-Type", "application/json"],
				["", "should-be-skipped"]
			],
			"content": null
		}
	}`

	m := &MitmproxyImporter{}
	requests, err := m.Import(strings.NewReader(json))
	require.NoError(t, err)
	require.Len(t, requests, 1)

	// Only valid headers should be present (empty names skipped)
	req := requests[0]
	assert.Len(t, req.Headers, 2)
	assert.Equal(t, "valid-value", req.Headers["Valid-Header"])
	assert.Equal(t, "another-value", req.Headers["Another-Valid"])
	assert.NotContains(t, req.Headers, "")

	// Response headers should also skip empty names
	assert.Len(t, req.Response.Headers, 1)
	assert.Equal(t, "application/json", req.Response.Headers["Content-Type"])
}

func TestMitmproxyImporter_MalformedHeaders(t *testing.T) {
	json := `{
		"request": {
			"method": "GET",
			"scheme": "https",
			"host": "example.com",
			"port": 443,
			"path": "/api",
			"headers": [
				["Only-One-Element"],
				["Valid-Header", "valid-value"],
				[],
				["Another-Valid", "value", "extra-ignored"]
			]
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

	// Only valid headers (len >= 2) should be present
	req := requests[0]
	assert.Len(t, req.Headers, 2)
	assert.Equal(t, "valid-value", req.Headers["Valid-Header"])
	assert.Equal(t, "value", req.Headers["Another-Valid"])
}

func TestMitmproxyImporter_ArrayParseError(t *testing.T) {
	// Malformed array with invalid flow object
	json := `[{"invalid": "structure"}]`

	m := &MitmproxyImporter{}
	requests, err := m.Import(strings.NewReader(json))
	// This should succeed because the JSON is valid, just with missing fields
	// The flow will have zero values for missing fields
	require.NoError(t, err)
	assert.Len(t, requests, 1)
}

func TestMitmproxyImporter_ValidPortBoundaries(t *testing.T) {
	tests := []struct {
		name string
		port int
	}{
		{"port 0", 0},
		{"port 1", 1},
		{"port 80", 80},
		{"port 443", 443},
		{"port 8080", 8080},
		{"port 65535", 65535},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			json := `{
				"request": {
					"method": "GET",
					"scheme": "https",
					"host": "example.com",
					"port": ` + fmt.Sprintf("%d", tt.port) + `,
					"path": "/api",
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
			assert.Len(t, requests, 1)
		})
	}
}

func TestMitmproxyImporter_TruncatedArrayJSON(t *testing.T) {
	// Test truncated JSON array (simulates hitting file size limit)
	truncatedJSON := `[{"request":{"method":"GET","scheme":"https","host":"example.com","port":443,"path":"/api","headers":[]},"response":{"status_code":200`

	m := &MitmproxyImporter{}
	_, err := m.Import(strings.NewReader(truncatedJSON))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode flow")
}

func TestMitmproxyImporter_TruncatedObjectJSON(t *testing.T) {
	// Test truncated single object JSON
	truncatedJSON := `{"request":{"method":"GET","scheme":"https","host":"example.com","port":443`

	m := &MitmproxyImporter{}
	_, err := m.Import(strings.NewReader(truncatedJSON))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode flow")
}

func TestMitmproxyImporter_ParseFlowErrorInArray(t *testing.T) {
	// Test parseFlow error within array loop
	json := `[{"request":{"method":"GET","scheme":"https","host":"example.com","port":-999,"path":"/api","headers":[]},"response":{"status_code":200,"headers":[],"content":null}}]`

	m := &MitmproxyImporter{}
	_, err := m.Import(strings.NewReader(json))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid port")
}

func TestMitmproxyImporter_EmptyInput(t *testing.T) {
	// Test empty input triggers peekFirstNonWhitespace error
	m := &MitmproxyImporter{}
	_, err := m.Import(strings.NewReader(""))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read input")
}

func TestMitmproxyImporter_WhitespaceOnlyInput(t *testing.T) {
	// Test whitespace-only input triggers EOF error
	m := &MitmproxyImporter{}
	_, err := m.Import(strings.NewReader("   \n\t\r  "))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read input")
}

func TestMitmproxyImporter_InvalidFirstToken(t *testing.T) {
	// Test unexpected token (not [ or {) triggers error
	m := &MitmproxyImporter{}
	_, err := m.Import(strings.NewReader(`"string value"`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected JSON array or object")
}

func TestMitmproxyImporter_InvalidArrayToken(t *testing.T) {
	// Test invalid array start (number instead of flow object)
	m := &MitmproxyImporter{}
	_, err := m.Import(strings.NewReader(`[123, 456]`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode flow")
}

func TestMitmproxyImporter_MissingArrayClose(t *testing.T) {
	// Test array without closing bracket (but valid flow)
	// This tests the closing ']' token error path
	json := `[{"request":{"method":"GET","scheme":"https","host":"example.com","port":443,"path":"/","headers":[]},"response":{"status_code":200,"headers":[],"content":null}}`
	m := &MitmproxyImporter{}
	_, err := m.Import(strings.NewReader(json))
	require.Error(t, err)
	// JSON decoder will report unexpected EOF when looking for closing bracket
	assert.Contains(t, err.Error(), "mitmproxy importer")
}

func TestMitmproxyImporter_InvalidRequestContent(t *testing.T) {
	// Test invalid base64 in request content
	json := `{
		"request": {
			"method": "POST",
			"scheme": "https",
			"host": "example.com",
			"port": 443,
			"path": "/api",
			"headers": [],
			"content": "!!!invalid-base64!!!"
		},
		"response": {
			"status_code": 200,
			"headers": [],
			"content": null
		}
	}`

	m := &MitmproxyImporter{}
	_, err := m.Import(strings.NewReader(json))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode request content")
}
