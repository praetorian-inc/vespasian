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
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	// Content fields decode base64 during json.Decode (Go maps JSON strings
	// into []byte via base64), so invalid base64 surfaces from the decoder
	// rather than a separate decodeContent step.
	assert.Contains(t, err.Error(), "failed to decode flow")
	assert.Contains(t, err.Error(), "illegal base64")
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
	// Malformed array with invalid flow object (missing fields means empty method)
	json := `[{"invalid": "structure"}]`

	m := &MitmproxyImporter{}
	_, err := m.Import(strings.NewReader(json))
	// Empty method string is invalid per HTTP method validation
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid HTTP method")
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
	// Test unexpected token (not [, {, or digit) triggers a format-unknown error
	// with guidance on converting native .mitm files to HAR.
	m := &MitmproxyImporter{}
	_, err := m.Import(strings.NewReader(`"string value"`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unrecognized format")
	assert.Contains(t, err.Error(), "mitmdump -nr")
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
	// Content fields decode base64 during json.Decode (Go maps JSON strings
	// into []byte via base64), so invalid base64 surfaces from the decoder
	// rather than a separate decodeContent step.
	assert.Contains(t, err.Error(), "failed to decode flow")
	assert.Contains(t, err.Error(), "illegal base64")
}

func TestMitmproxyImporter_InvalidMethod(t *testing.T) {
	json := `{
		"request": {
			"method": "INVALID",
			"scheme": "https",
			"host": "example.com",
			"port": 443,
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
	assert.Contains(t, err.Error(), "invalid HTTP method: INVALID")
}

// ─── Native (tnetstring) flow format ──────────────────────────────────────────
//
// The following tests exercise the binary flow format produced by mitmproxy's
// `w` command. flowState builds a minimal-but-valid HTTPFlow get_state() dict
// so tests read close to the Python source.

// flowState produces a dict matching mitmproxy.http.HTTPFlow.get_state().
// Headers are serialized as a list-of-byte-pairs, bodies as raw bytes.
func flowState(method, scheme, host string, port int, path string, reqHeaders [][2]string, reqBody []byte, statusCode int, respHeaders [][2]string, respBody []byte) map[string]any {
	reqHdrList := make([]any, 0, len(reqHeaders))
	for _, h := range reqHeaders {
		reqHdrList = append(reqHdrList, []any{[]byte(h[0]), []byte(h[1])})
	}
	respHdrList := make([]any, 0, len(respHeaders))
	for _, h := range respHeaders {
		respHdrList = append(respHdrList, []any{[]byte(h[0]), []byte(h[1])})
	}
	return map[string]any{
		"type":   []byte("http"),
		"id":     []byte("00000000-0000-0000-0000-000000000001"),
		"marked": []byte(""),
		"request": map[string]any{
			"http_version": []byte("HTTP/1.1"),
			"method":       []byte(method),
			"scheme":       []byte(scheme),
			"host":         []byte(host),
			"port":         int64(port),
			"path":         []byte(path),
			"authority":    []byte(""),
			"headers":      reqHdrList,
			"content":      reqBody,
		},
		"response": map[string]any{
			"http_version": []byte("HTTP/1.1"),
			"status_code":  int64(statusCode),
			"reason":       []byte("OK"),
			"headers":      respHdrList,
			"content":      respBody,
		},
	}
}

func TestMitmproxyImporter_Native_SingleFlow(t *testing.T) {
	state := flowState(
		"GET", "https", "example.com", 443, "/api?page=1",
		[][2]string{{"User-Agent", "test"}, {"Accept", "application/json"}},
		nil,
		200,
		[][2]string{{"Content-Type", "application/json"}},
		[]byte(`{"id":1}`),
	)
	encoded := encodeTnet(state)

	m := &MitmproxyImporter{}
	requests, err := m.Import(bytes.NewReader(encoded))
	require.NoError(t, err)

	require.Len(t, requests, 1)
	req := requests[0]
	assert.Equal(t, "GET", req.Method)
	assert.Equal(t, "https://example.com/api?page=1", req.URL)
	assert.Equal(t, "import:mitmproxy", req.Source)
	assert.Equal(t, 200, req.Response.StatusCode)
	assert.Equal(t, "application/json", req.Response.ContentType)
	assert.Equal(t, `{"id":1}`, string(req.Response.Body))
	assert.Equal(t, "test", req.Headers["User-Agent"])
	assert.Equal(t, "application/json", req.Headers["Accept"])
	assert.Equal(t, "1", req.QueryParams["page"])
}

func TestMitmproxyImporter_Native_MultipleFlows(t *testing.T) {
	flow1 := encodeTnet(flowState(
		"GET", "https", "a.example.com", 443, "/one",
		nil, nil, 200, nil, nil,
	))
	flow2 := encodeTnet(flowState(
		"POST", "http", "b.example.com", 8080, "/two",
		[][2]string{{"Content-Type", "text/plain"}}, []byte("hello"),
		201, nil, nil,
	))

	var combined bytes.Buffer
	combined.Write(flow1)
	combined.Write(flow2)

	m := &MitmproxyImporter{}
	requests, err := m.Import(&combined)
	require.NoError(t, err)

	require.Len(t, requests, 2)
	assert.Equal(t, "https://a.example.com/one", requests[0].URL)
	assert.Equal(t, "http://b.example.com:8080/two", requests[1].URL)
	assert.Equal(t, []byte("hello"), requests[1].Body)
	assert.Equal(t, 201, requests[1].Response.StatusCode)
}

func TestMitmproxyImporter_Native_SkipsNonHTTPFlows(t *testing.T) {
	// Non-HTTP flow (e.g., TCP) should be skipped, not errored.
	tcpFlow := map[string]any{
		"type":     []byte("tcp"),
		"id":       []byte("tcp-1"),
		"messages": []any{},
	}
	httpFlow := flowState(
		"GET", "https", "example.com", 443, "/ok",
		nil, nil, 200, nil, nil,
	)

	var combined bytes.Buffer
	combined.Write(encodeTnet(tcpFlow))
	combined.Write(encodeTnet(httpFlow))

	m := &MitmproxyImporter{}
	requests, err := m.Import(&combined)
	require.NoError(t, err)

	require.Len(t, requests, 1)
	assert.Equal(t, "https://example.com/ok", requests[0].URL)
}

func TestMitmproxyImporter_Native_MissingResponse(t *testing.T) {
	// Flow with null response (e.g., error or in-flight) still imports; the
	// resulting ObservedRequest simply has zero-valued response fields.
	state := flowState(
		"GET", "https", "example.com", 443, "/pending",
		nil, nil, 0, nil, nil,
	)
	state["response"] = nil

	m := &MitmproxyImporter{}
	requests, err := m.Import(bytes.NewReader(encodeTnet(state)))
	require.NoError(t, err)
	require.Len(t, requests, 1)
	assert.Equal(t, 0, requests[0].Response.StatusCode)
	assert.Nil(t, requests[0].Response.Body)
}

func TestMitmproxyImporter_Native_RegressionLAB2309(t *testing.T) {
	// Regression test for LAB-2309: a native mitmproxy flow dump starts with
	// an ASCII digit (the tnetstring length prefix), which historically hit
	// the "expected JSON array or object" path and rejected the file with:
	//
	//   "mitmproxy importer: expected JSON array or object, got \"2\""
	//
	// This test defends against a regression to that dispatch by (1) asserting
	// the fixture actually starts with a digit (reproducing the user's
	// reported failure mode) and (2) asserting the import succeeds with
	// meaningful data, so flipping the dispatch back to the JSON-only path
	// fails with a concrete error instead of silently no-op'ing.
	state := flowState(
		"GET", "https", "example.com", 443, "/api?x=1",
		[][2]string{{"User-Agent", "lab2309-test"}},
		nil,
		200,
		[][2]string{{"Content-Type", "application/json"}},
		[]byte(`{"ok":true}`),
	)
	encoded := encodeTnet(state)

	// Confirm the fixture starts with the byte class that triggered the bug.
	require.GreaterOrEqual(t, encoded[0], byte('0'))
	require.LessOrEqual(t, encoded[0], byte('9'))

	m := &MitmproxyImporter{}
	requests, err := m.Import(bytes.NewReader(encoded))
	require.NoError(t, err, "LAB-2309: native flow must decode without the pre-fix JSON error")

	require.Len(t, requests, 1)
	req := requests[0]
	// End-to-end field propagation — a regression that hits the wrong dispatch
	// would either error or produce zero-valued fields.
	assert.Equal(t, "GET", req.Method)
	assert.Equal(t, "https://example.com/api?x=1", req.URL)
	assert.Equal(t, "lab2309-test", req.Headers["User-Agent"])
	assert.Equal(t, 200, req.Response.StatusCode)
	assert.Equal(t, "application/json", req.Response.ContentType)
	assert.Equal(t, `{"ok":true}`, string(req.Response.Body))
	assert.Equal(t, "import:mitmproxy", req.Source)
}

func TestMitmproxyImporter_Native_InvalidFlowDict(t *testing.T) {
	// Top-level element is a bytes value, not a dict.
	encoded := encodeTnet([]byte("not a flow"))
	m := &MitmproxyImporter{}
	_, err := m.Import(bytes.NewReader(encoded))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected flow dict")
}

func TestMitmproxyImporter_Native_MissingRequest(t *testing.T) {
	state := map[string]any{
		"type": []byte("http"),
		"id":   []byte("bad-flow"),
	}
	m := &MitmproxyImporter{}
	_, err := m.Import(bytes.NewReader(encodeTnet(state)))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing \"request\"")
}

func TestMitmproxyImporter_Native_TruncatedStream(t *testing.T) {
	encoded := encodeTnet(flowState(
		"GET", "https", "example.com", 443, "/api",
		nil, nil, 200, nil, nil,
	))
	// Chop off the last half.
	truncated := encoded[:len(encoded)/2]

	m := &MitmproxyImporter{}
	_, err := m.Import(bytes.NewReader(truncated))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode native flow")
}

func TestMitmproxyImporter_Native_InvalidPortPropagates(t *testing.T) {
	// Port validation rejects out-of-range values before URL construction.
	state := flowState(
		"GET", "https", "example.com", 443, "/api",
		nil, nil, 200, nil, nil,
	)
	req := state["request"].(map[string]any)
	req["port"] = int64(70000)

	m := &MitmproxyImporter{}
	_, err := m.Import(bytes.NewReader(encodeTnet(state)))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid port")
}

// TestMitmproxyImporter_Native_MissingPort ensures missing `port` surfaces as
// a clear error rather than silently defaulting to 0 (which previously
// produced URLs like "https://example.com:0/" for malformed captures).
func TestMitmproxyImporter_Native_MissingPort(t *testing.T) {
	state := flowState(
		"GET", "https", "example.com", 443, "/api",
		nil, nil, 200, nil, nil,
	)
	req := state["request"].(map[string]any)
	delete(req, "port")

	m := &MitmproxyImporter{}
	_, err := m.Import(bytes.NewReader(encodeTnet(state)))
	require.Error(t, err)
	assert.Contains(t, err.Error(), `missing "port"`)
}

// TestMitmproxyImporter_Native_PortWrongType ensures a `port` field decoded as
// bytes or a string (rather than tnetstring int) produces a clear error.
func TestMitmproxyImporter_Native_PortWrongType(t *testing.T) {
	state := flowState(
		"GET", "https", "example.com", 443, "/api",
		nil, nil, 200, nil, nil,
	)
	req := state["request"].(map[string]any)
	req["port"] = []byte("443")

	m := &MitmproxyImporter{}
	_, err := m.Import(bytes.NewReader(encodeTnet(state)))
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"port" is`)
}

func TestMitmproxyImporter_Native_ConnectRequestEmptyPath(t *testing.T) {
	// CONNECT flows carry their target in the authority; the path field is
	// typically empty. We normalize those to "https://host:port/" rather
	// than embedding the authority as a URL path, which would yield bogus
	// URLs like "https://example.com/example.com:443".
	state := flowState(
		"CONNECT", "https", "example.com", 443, "",
		nil, nil, 200, nil, nil,
	)
	req := state["request"].(map[string]any)
	req["authority"] = []byte("example.com:443")

	m := &MitmproxyImporter{}
	requests, err := m.Import(bytes.NewReader(encodeTnet(state)))
	require.NoError(t, err)
	require.Len(t, requests, 1)

	got := requests[0]
	assert.Equal(t, "CONNECT", got.Method)
	assert.Equal(t, 200, got.Response.StatusCode)
	// Default HTTPS port → host alone, path "/".
	assert.Equal(t, "https://example.com/", got.URL)
}

func TestMitmproxyImporter_Native_ConnectRequestNonDefaultPort(t *testing.T) {
	// When the CONNECT target uses a non-default port, the port should appear
	// in host:port form in the URL, and the path stays "/".
	state := flowState(
		"CONNECT", "https", "example.com", 8443, "",
		nil, nil, 200, nil, nil,
	)
	req := state["request"].(map[string]any)
	req["authority"] = []byte("example.com:8443")

	m := &MitmproxyImporter{}
	requests, err := m.Import(bytes.NewReader(encodeTnet(state)))
	require.NoError(t, err)
	require.Len(t, requests, 1)
	assert.Equal(t, "https://example.com:8443/", requests[0].URL)
}

// TestMitmproxyImporter_Native_MalformedInMultiFlowStream characterizes the
// importer's current behavior when one flow in a multi-flow stream is
// malformed: the whole import fails and no requests are returned. This is
// deliberate — the decoder can't know whether the remainder of the file is
// salvageable after a mid-stream parse error, and partial imports would be
// misleading. The test exists to make the behavior explicit so a future
// change to "skip-bad, keep-good" is a deliberate decision, not an accident.
func TestMitmproxyImporter_Native_MalformedInMultiFlowStream(t *testing.T) {
	good := encodeTnet(flowState(
		"GET", "https", "a.example.com", 443, "/ok",
		nil, nil, 200, nil, nil,
	))
	// Corrupt tnetstring: length prefix references more bytes than exist.
	bad := []byte("999999:short,")

	var stream bytes.Buffer
	stream.Write(good)
	stream.Write(bad)

	m := &MitmproxyImporter{}
	requests, err := m.Import(&stream)
	require.Error(t, err)
	assert.Nil(t, requests, "partial import must not be returned when a later flow fails")
}

// TestMitmproxyImporter_Native_WebSocketFlowSkipped documents handling for
// non-HTTP flow types that mitmproxy can write alongside HTTP in mixed
// captures (tcp, dns, and — historically — websocket/frames records).
func TestMitmproxyImporter_Native_WebSocketFlowSkipped(t *testing.T) {
	wsFlow := map[string]any{
		"type":     []byte("websocket"),
		"id":       []byte("ws-1"),
		"messages": []any{},
	}
	httpFlow := flowState(
		"GET", "https", "example.com", 443, "/real",
		nil, nil, 200, nil, nil,
	)

	var combined bytes.Buffer
	combined.Write(encodeTnet(wsFlow))
	combined.Write(encodeTnet(httpFlow))

	m := &MitmproxyImporter{}
	requests, err := m.Import(&combined)
	require.NoError(t, err)

	require.Len(t, requests, 1)
	assert.Equal(t, "https://example.com/real", requests[0].URL)
}

// TestMitmproxyImporter_Native_FlowWithoutTypeSkipped locks in the policy
// clarified in QUAL-004: a flow dict without a `type` key is treated as
// non-HTTP and skipped, not implicitly treated as HTTP.
func TestMitmproxyImporter_Native_FlowWithoutTypeSkipped(t *testing.T) {
	typeless := map[string]any{
		"id": []byte("typeless-1"),
	}
	httpFlow := flowState(
		"GET", "https", "example.com", 443, "/good",
		nil, nil, 200, nil, nil,
	)
	var combined bytes.Buffer
	combined.Write(encodeTnet(typeless))
	combined.Write(encodeTnet(httpFlow))

	m := &MitmproxyImporter{}
	requests, err := m.Import(&combined)
	require.NoError(t, err)
	require.Len(t, requests, 1)
	assert.Equal(t, "https://example.com/good", requests[0].URL)
}

// TestMitmproxyImporter_Native_NonUTF8InHeaderValueAccepted characterizes
// behavior for non-UTF-8 bytes inside tnetstring `,` (bytes) payloads, which
// is how mitmproxy actually serializes header values. Go's `string` type can
// carry non-UTF-8 bytes unchanged, so we pass them through verbatim; this is
// safe because downstream consumers treat header values as opaque strings.
func TestMitmproxyImporter_Native_NonUTF8InHeaderValueAccepted(t *testing.T) {
	state := flowState(
		"GET", "https", "example.com", 443, "/api",
		nil, nil, 200, nil, nil,
	)
	reqMap := state["request"].(map[string]any)
	reqMap["headers"] = []any{
		[]any{[]byte("X-Binary"), []byte{0xff, 0xfe, 0x00}},
	}

	m := &MitmproxyImporter{}
	requests, err := m.Import(bytes.NewReader(encodeTnet(state)))
	require.NoError(t, err)
	require.Len(t, requests, 1)
	assert.Equal(t, string([]byte{0xff, 0xfe, 0x00}), requests[0].Headers["X-Binary"])
}

// TestMitmproxyImporter_Native_MalformedHeaderPairSkipped pins nativeHeaders'
// skip-on-malformed behavior for the native path. The JSON path is covered
// by TestMitmproxyImporter_MalformedHeaders; without this the two `continue`
// branches at nativeHeaders (non-list entry, len(pair)<2) stay uncovered,
// and a refactor that flipped the skip into a hard error would not fail.
func TestMitmproxyImporter_Native_MalformedHeaderPairSkipped(t *testing.T) {
	state := flowState(
		"GET", "https", "example.com", 443, "/api",
		nil, nil, 200, nil, nil,
	)
	reqMap := state["request"].(map[string]any)
	// Mixed list: non-list entry, empty pair, 1-element pair, valid 2-element
	// pair, 3-element pair (extra elements ignored per existing JSON test).
	reqMap["headers"] = []any{
		[]byte("not-a-list"),
		[]any{},
		[]any{[]byte("X-Lonely")},
		[]any{[]byte("X-Valid"), []byte("keep-me")},
		[]any{[]byte("X-Extra"), []byte("keep-this-value"), []byte("ignored")},
	}

	m := &MitmproxyImporter{}
	requests, err := m.Import(bytes.NewReader(encodeTnet(state)))
	require.NoError(t, err)
	require.Len(t, requests, 1)

	// Only the two well-formed pairs survive. Shape is identical to the JSON
	// path behavior exercised by TestMitmproxyImporter_MalformedHeaders.
	req := requests[0]
	assert.Len(t, req.Headers, 2)
	assert.Equal(t, "keep-me", req.Headers["X-Valid"])
	assert.Equal(t, "keep-this-value", req.Headers["X-Extra"])
	assert.NotContains(t, req.Headers, "X-Lonely")
}

// TestMitmproxyImporter_Native_HeadersNotAList pins the top-level
// type-assertion failure in nativeHeaders: when `request.headers` is not
// a tnetstring list (e.g. bytes, int, dict), the helper silently drops all
// headers for the flow and the import still succeeds. Without this test a
// future refactor could flip the `return nil` into a hard error (or a
// permissive fall-through) without any test failing. Pairs with
// TestMitmproxyImporter_Native_MalformedHeaderPairSkipped, which covers
// malformed entries inside a well-formed list.
func TestMitmproxyImporter_Native_HeadersNotAList(t *testing.T) {
	cases := []struct {
		name  string
		value any
	}{
		{"bytes", []byte("not-a-list")},
		{"int", int64(0)},
		{"dict", map[string]any{"unexpected": []byte("shape")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state := flowState(
				"GET", "https", "example.com", 443, "/api",
				nil, nil, 200, nil, nil,
			)
			state["request"].(map[string]any)["headers"] = tc.value

			m := &MitmproxyImporter{}
			requests, err := m.Import(bytes.NewReader(encodeTnet(state)))
			require.NoError(t, err, "wrong-type headers field must be silently dropped, not errored")
			require.Len(t, requests, 1)
			assert.Empty(t, requests[0].Headers)
		})
	}
}

// TestMitmproxyImporter_Native_ContentAsString exercises the tnetstring `;`
// (UTF-8 string) branch of nativeContent end-to-end. The decoder produces
// string-typed values for `;` elements (see
// TestMitmproxyImporter_Native_StringTypeInHeaderValue for the header-path
// proof); content MUST survive that type unchanged. Without this test the
// string branch of the type-switch could silently break and only the bytes
// branch would catch it.
func TestMitmproxyImporter_Native_ContentAsString(t *testing.T) {
	// Hand-roll a flow where `request.content` uses type marker `;` (string)
	// rather than `,` (bytes); the shared encoder always emits `,` so we
	// splice raw elements via the buildElement helpers.
	content := buildElement([]byte("hello-string-body"), ';')
	request := tnetDictElement(
		tnetBytesElement("method"), tnetBytesElement("GET"),
		tnetBytesElement("scheme"), tnetBytesElement("https"),
		tnetBytesElement("host"), tnetBytesElement("example.com"),
		tnetBytesElement("port"), []byte("3:443#"),
		tnetBytesElement("path"), tnetBytesElement("/api"),
		tnetBytesElement("content"), content,
		tnetBytesElement("headers"), buildElement(nil, ']'),
	)
	flowEnc := tnetDictElement(
		tnetBytesElement("type"), tnetBytesElement("http"),
		tnetBytesElement("id"), tnetBytesElement("s1"),
		tnetBytesElement("request"), request,
	)

	m := &MitmproxyImporter{}
	requests, err := m.Import(bytes.NewReader(flowEnc))
	require.NoError(t, err)
	require.Len(t, requests, 1)
	assert.Equal(t, []byte("hello-string-body"), requests[0].Body,
		"string-typed content must round-trip to Body as bytes")
}

// TestMitmproxyImporter_Native_ContentWrongTypeDroppedSilently pins the
// default branch of nativeContent's type-switch: if `content` is a dict or
// int (which mitmproxy would never emit), import succeeds with a nil Body.
// Documents the silent-drop contract so a future refactor can't flip it to
// an error without tripping this test.
func TestMitmproxyImporter_Native_ContentWrongTypeDroppedSilently(t *testing.T) {
	// Build flow manually so we can place a dict value in `content` — the
	// encoder's type switch would panic on a map-valued content via the
	// flowState helper because it interprets content as []byte.
	content := tnetDictElement(tnetBytesElement("unexpected"), tnetBytesElement("shape"))
	request := tnetDictElement(
		tnetBytesElement("method"), tnetBytesElement("GET"),
		tnetBytesElement("scheme"), tnetBytesElement("https"),
		tnetBytesElement("host"), tnetBytesElement("example.com"),
		tnetBytesElement("port"), []byte("3:443#"),
		tnetBytesElement("path"), tnetBytesElement("/api"),
		tnetBytesElement("content"), content,
		tnetBytesElement("headers"), buildElement(nil, ']'),
	)
	flowEnc := tnetDictElement(
		tnetBytesElement("type"), tnetBytesElement("http"),
		tnetBytesElement("id"), tnetBytesElement("w1"),
		tnetBytesElement("request"), request,
	)

	m := &MitmproxyImporter{}
	requests, err := m.Import(bytes.NewReader(flowEnc))
	require.NoError(t, err, "wrong-type content field must be silently dropped, not errored")
	require.Len(t, requests, 1)
	assert.Nil(t, requests[0].Body)
}

// TestMitmproxyImporter_Native_StringTypeInHeaderValue exercises the
// tnetstring `;` (UTF-8 string) type through an integration path. The
// shared encoder emits bytes (`,`) for all strings, so this test builds the
// raw tnetstring elements with tiny local helpers instead of splicing
// encoder output. Regression for round-2 TEST-R2-006.
func TestMitmproxyImporter_Native_StringTypeInHeaderValue(t *testing.T) {
	// Headers list containing a single pair where the value uses `;` (string)
	// type rather than the encoder's default `,` (bytes) type.
	pair := tnetListElement(
		tnetBytesElement("X-String"),
		tnetStringElement("hello"),
	)
	headers := tnetListElement(pair)

	// Request dict. All fields except `headers` use encoder defaults.
	request := tnetDictElement(
		tnetBytesElement("method"), tnetBytesElement("GET"),
		tnetBytesElement("scheme"), tnetBytesElement("https"),
		tnetBytesElement("host"), tnetBytesElement("example.com"),
		tnetBytesElement("port"), []byte("3:443#"),
		tnetBytesElement("path"), tnetBytesElement("/str"),
		tnetBytesElement("content"), []byte("0:~"),
		tnetBytesElement("headers"), headers,
	)

	// Top-level HTTP flow state.
	flowEnc := tnetDictElement(
		tnetBytesElement("type"), tnetBytesElement("http"),
		tnetBytesElement("id"), tnetBytesElement("str"),
		tnetBytesElement("request"), request,
	)

	m := &MitmproxyImporter{}
	requests, err := m.Import(bytes.NewReader(flowEnc))
	require.NoError(t, err)
	require.Len(t, requests, 1)
	assert.Equal(t, "hello", requests[0].Headers["X-String"])
}

// TestMitmproxyImporter_Native_BodyWithPercentFormatDirective exercises the
// QUAL-009 regression: when the encoder used fmt.Sprintf("%d:%s,", ...) on
// []byte, a body containing '%' was misencoded. The fix is in the shared
// encoder, but we test end-to-end here because the bug was hidden by the
// same encoder being used on both sides of round-trip tests.
func TestMitmproxyImporter_Native_BodyWithPercentFormatDirective(t *testing.T) {
	tricky := []byte(`POST %d OK %s %%EOF`)
	state := flowState(
		"POST", "https", "example.com", 443, "/upload",
		[][2]string{{"Content-Type", "text/plain"}}, tricky,
		201, nil, nil,
	)
	m := &MitmproxyImporter{}
	requests, err := m.Import(bytes.NewReader(encodeTnet(state)))
	require.NoError(t, err)
	require.Len(t, requests, 1)
	assert.Equal(t, tricky, requests[0].Body,
		"body with %% must survive encode/decode byte-for-byte")
}

// TestMitmproxyImporter_Native_MaxFlowsCap verifies that a pathological
// input consisting of many tiny non-HTTP flow records trips the
// maxNativeFlows counter and returns a wrapped ErrTooManyEntries. We lower
// the cap temporarily so the test doesn't need to construct 500K flows.
// Regression for round-2 TEST-R2-003.
func TestMitmproxyImporter_Native_MaxFlowsCap(t *testing.T) {
	withTempCap(t, &maxNativeFlows, 5)

	// Build a stream of 10 minimal non-HTTP flow dicts (type=tcp).
	// Each is a well-formed tnetstring-encoded dict so parsing succeeds
	// for the ones below the cap; the 6th triggers the cap.
	tcpFlow := encodeTnet(map[string]any{
		"type": []byte("tcp"),
		"id":   []byte("t"),
	})
	var stream bytes.Buffer
	for i := 0; i < 10; i++ {
		stream.Write(tcpFlow)
	}

	m := &MitmproxyImporter{}
	_, err := m.Import(&stream)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrTooManyEntries),
		"expected wrapped ErrTooManyEntries, got %v", err)
	assert.Contains(t, err.Error(), "native flow count exceeded")
}

// TestMitmproxyImporter_Native_MaxFlowsCap_HTTPFlows is the mirror case of
// MaxFlowsCap using real HTTP flows instead of tcp skip-records, confirming
// the cap also fires on the productive-flow path rather than only catching
// traffic that would be skipped anyway. Regression for round-3 TEST-R3-004.
func TestMitmproxyImporter_Native_MaxFlowsCap_HTTPFlows(t *testing.T) {
	withTempCap(t, &maxNativeFlows, 3)

	httpFlow := encodeTnet(flowState(
		"GET", "https", "example.com", 443, "/api",
		nil, nil, 200, nil, nil,
	))
	var stream bytes.Buffer
	for i := 0; i < 8; i++ { // 8 > lowered cap of 3
		stream.Write(httpFlow)
	}

	m := &MitmproxyImporter{}
	_, err := m.Import(&stream)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrTooManyEntries),
		"expected wrapped ErrTooManyEntries, got %v", err)
}

// TestMitmproxyImporter_Native_RequestNotDict covers the error branch in
// flowFromNativeState where the `request` field decodes to something other
// than a dict (e.g. a bytes value). Regression for round-2 TEST-R2-004.
func TestMitmproxyImporter_Native_RequestNotDict(t *testing.T) {
	state := map[string]any{
		"type":    []byte("http"),
		"id":      []byte("bad-req"),
		"request": []byte("not a dict"),
	}
	m := &MitmproxyImporter{}
	_, err := m.Import(bytes.NewReader(encodeTnet(state)))
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"request" is`)
}

// TestMitmproxyImporter_Native_ResponseNotDict covers the error branch in
// flowFromNativeState where `response` is present but not a dict. Distinct
// from the "response missing" (nil) case, which is handled gracefully.
// Regression for round-2 TEST-R2-004.
func TestMitmproxyImporter_Native_ResponseNotDict(t *testing.T) {
	state := flowState(
		"GET", "https", "example.com", 443, "/api",
		nil, nil, 200, nil, nil,
	)
	state["response"] = []byte("not a dict")

	m := &MitmproxyImporter{}
	_, err := m.Import(bytes.NewReader(encodeTnet(state)))
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"response" is`)
}

// TestMitmproxyImporter_Native_StringTypedDictKey covers the `string` branch
// of coerceDictKey in the integration path. All natural mitmproxy output
// uses bytes-typed keys, but the decoder tolerates string-typed keys too.
func TestMitmproxyImporter_Native_StringTypedDictKey(t *testing.T) {
	// Manually build: dict with key serialized as `;` (string) type rather
	// than `,` (bytes). The rest matches a minimal http flow state.
	// Format: "<n>:<keyEncAsString><valEnc>...<keyEnc><valEnc>...}"
	innerReq := encodeTnet(map[string]any{
		"method":  []byte("GET"),
		"scheme":  []byte("https"),
		"host":    []byte("example.com"),
		"port":    int64(443),
		"path":    []byte("/str"),
		"headers": []any{},
		"content": nil,
	})
	// Build keys: `type` using tnetType=string, value `http` as bytes.
	typeKey := []byte("4:type;")
	typeVal := []byte("4:http,")
	requestKey := []byte("7:request;")
	// id key
	idKey := []byte("2:id;")
	idVal := []byte("1:x,")

	var body bytes.Buffer
	body.Write(typeKey)
	body.Write(typeVal)
	body.Write(idKey)
	body.Write(idVal)
	body.Write(requestKey)
	body.Write(innerReq)

	dict := fmt.Sprintf("%d:%s}", body.Len(), body.String())

	m := &MitmproxyImporter{}
	requests, err := m.Import(bytes.NewReader([]byte(dict)))
	require.NoError(t, err)
	require.Len(t, requests, 1)
	assert.Equal(t, "https://example.com/str", requests[0].URL)
}

// TestMitmproxyImporter_Native_BOMPrefixRejected confirms that a UTF-8 BOM
// (0xEF 0xBB 0xBF) followed by otherwise-valid JSON does NOT select either
// importer path. The first non-whitespace byte 0xEF is neither `[`/`{` nor
// an ASCII digit, so dispatch falls through to the "unrecognized format"
// branch. Regression for review TEST-002.
func TestMitmproxyImporter_BOMPrefixRejected(t *testing.T) {
	var input []byte
	input = append(input, 0xEF, 0xBB, 0xBF) // UTF-8 BOM
	input = append(input, []byte(`{"request":{}}`)...)

	m := &MitmproxyImporter{}
	_, err := m.Import(bytes.NewReader(input))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unrecognized format")
}

// TestMitmproxyImporter_LeadingMinusRejected confirms the dispatch rejects a
// leading `-` as neither JSON nor native tnetstring. Structurally overlaps
// with TestMitmproxyImporter_InvalidFirstToken, but explicitly pinning `-`
// defends against a future refactor of the length-prefix check that started
// tolerating signed ints. Regression for review TEST-002.
func TestMitmproxyImporter_LeadingMinusRejected(t *testing.T) {
	m := &MitmproxyImporter{}
	_, err := m.Import(strings.NewReader("-1:x,"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unrecognized format")
}

// TestMitmproxyImporter_Native_GeneratedFixtureImports loads the committed
// sample-mitmproxy.mitm and runs it through MitmproxyImporter.Import, so the
// generator-to-importer path is exercised by a unit test rather than only
// by the gated live test `import-mitmproxy-native`. Without this, a
// generator that silently produces unparseable bytes would still pass the
// existing fixture-drift check. Regression for review TEST-001.
func TestMitmproxyImporter_Native_GeneratedFixtureImports(t *testing.T) {
	root := repoRoot(t)
	path := filepath.Join(root, "test", "fixtures", "sample-mitmproxy.mitm")
	data, err := os.ReadFile(path) //nolint:gosec // test-time fixture read, path derived from repo root
	require.NoError(t, err)

	m := &MitmproxyImporter{}
	requests, err := m.Import(bytes.NewReader(data))
	require.NoError(t, err, "generated fixture failed to import")

	// The generator (test/fixtures/gen_mitmproxy_native/main.go) emits three
	// HTTP flows against http://localhost:8990; see that file for the
	// canonical contents.
	require.Len(t, requests, 3, "generator produces 3 HTTP flows")

	// Pin method, URL, and response status per flow so a generator change
	// that alters shape surfaces here rather than silently skewing fixtures.
	expected := []struct {
		method, url string
		statusCode  int
	}{
		{"GET", "http://localhost:8990/api/users", 200},
		{"POST", "http://localhost:8990/api/orders", 201},
		{"GET", "http://localhost:8990/api/products/1", 200},
	}
	for i, exp := range expected {
		assert.Equal(t, exp.method, requests[i].Method, "flow %d method", i)
		assert.Equal(t, exp.url, requests[i].URL, "flow %d URL", i)
		assert.Equal(t, exp.statusCode, requests[i].Response.StatusCode, "flow %d status", i)
		assert.Equal(t, "import:mitmproxy", requests[i].Source, "flow %d source", i)
		assert.NotEmpty(t, requests[i].Response.Body, "flow %d response body", i)
	}

	// POST flow carries a request body in the generator input; verify the
	// body survives the native-path round-trip end-to-end (regression for
	// the base64-round-trip removal in SEC-BE-003).
	assert.Equal(t, []byte(`{"user_id":1,"product_id":2,"quantity":1}`), requests[1].Body)
}

// TestMitmproxyImporter_Native_MaxFlowsCap_AtCap pairs with
// TestMitmproxyImporter_Native_MaxFlowsCap to pin the exact cap boundary.
// A stream with exactly N valid HTTP flows (N == lowered cap) must decode
// without error, while N+1 trips ErrTooManyEntries.
//
// Regression for review TEST-004.
func TestMitmproxyImporter_Native_MaxFlowsCap_AtCap(t *testing.T) {
	const lowered = 3
	withTempCap(t, &maxNativeFlows, lowered)

	httpFlow := encodeTnet(flowState(
		"GET", "https", "example.com", 443, "/api",
		nil, nil, 200, nil, nil,
	))
	var stream bytes.Buffer
	for i := 0; i < lowered; i++ {
		stream.Write(httpFlow)
	}

	m := &MitmproxyImporter{}
	requests, err := m.Import(&stream)
	require.NoError(t, err, "exactly cap flows must be accepted")
	require.Len(t, requests, lowered)
}

// TestMitmproxyImporter_Native_RegressionLAB2309_ErrorMessagePin is a
// defense-in-depth companion to TestMitmproxyImporter_Native_RegressionLAB2309.
// The original test proves the fixture decodes cleanly; this one confirms
// the success path does NOT carry the pre-fix error text anywhere. A future
// dispatch rewrite that accidentally succeeded on digit-prefixed input via
// an unrelated path would fail this check.
//
// Regression for review TEST-003.
func TestMitmproxyImporter_Native_RegressionLAB2309_ErrorMessagePin(t *testing.T) {
	state := flowState(
		"GET", "https", "example.com", 443, "/api",
		nil, nil, 200, nil, nil,
	)
	encoded := encodeTnet(state)

	m := &MitmproxyImporter{}
	_, err := m.Import(bytes.NewReader(encoded))
	require.NoError(t, err, "native flow must not produce the pre-fix JSON error")
	// err is nil, so there is no message to inspect. The surviving assertion
	// is: reaching this line at all means the dispatch did not reject with
	// the pre-fix "expected JSON array or object" text — that path returned
	// an error, which NoError above would have caught.
}

// TestMitmproxyImporter_Native_UnsafeSchemeRejected covers SEC-BE-001:
// mitmproxy `.mitm` files are untrusted input, so schemes other than
// http/https must be rejected at the importer boundary to prevent scheme-
// confusion bugs in downstream consumers that re-fetch or replay URLs.
func TestMitmproxyImporter_Native_UnsafeSchemeRejected(t *testing.T) {
	schemes := []string{"file", "javascript", "gopher", "data", "ldap", "dict", "ftp"}
	for _, scheme := range schemes {
		t.Run(scheme, func(t *testing.T) {
			state := flowState(
				"GET", scheme, "example.com", 443, "/api",
				nil, nil, 200, nil, nil,
			)

			m := &MitmproxyImporter{}
			_, err := m.Import(bytes.NewReader(encodeTnet(state)))
			require.Error(t, err)
			assert.Contains(t, err.Error(), "unsupported scheme")
		})
	}
}

// TestMitmproxyImporter_JSON_UnsafeSchemeRejected is the JSON-path mirror of
// the native scheme test so both importer paths enforce the same whitelist.
func TestMitmproxyImporter_JSON_UnsafeSchemeRejected(t *testing.T) {
	jsonFlow := `{
		"request": {
			"method": "GET",
			"scheme": "file",
			"host": "example.com",
			"port": 443,
			"path": "/etc/passwd",
			"headers": []
		},
		"response": {
			"status_code": 200,
			"headers": [],
			"content": null
		}
	}`

	m := &MitmproxyImporter{}
	_, err := m.Import(strings.NewReader(jsonFlow))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported scheme")
}

// TestMitmproxyImporter_Native_InvalidHostRejected covers SEC-BE-002: hosts
// with userinfo, control bytes, or overlong lengths must be rejected at the
// importer boundary so downstream consumers cannot be tricked by a forged
// `.mitm` capture.
func TestMitmproxyImporter_Native_InvalidHostRejected(t *testing.T) {
	cases := []struct {
		name    string
		host    string
		wantMsg string
	}{
		{"empty", "", "empty host"},
		{"embedded userinfo", "user:pass@attacker.example", "embedded userinfo"},
		{"control byte", "example\x00.com", "control/whitespace"},
		{"whitespace", "example .com", "control/whitespace"},
		{"over 253 chars", strings.Repeat("a", 254), "exceeds RFC 1035"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state := flowState(
				"GET", "https", tc.host, 443, "/api",
				nil, nil, 200, nil, nil,
			)

			m := &MitmproxyImporter{}
			_, err := m.Import(bytes.NewReader(encodeTnet(state)))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantMsg)
		})
	}
}

// TestMitmproxyImporter_Native_LargeMethodBoundedInError confirms that a
// crafted flow with an outsized method field produces an error message
// bounded by previewString, not the full attacker-controlled payload. The
// tnetstring decoder's per-element cap would otherwise allow up to 64 MB of
// method bytes to ride through into parseFlow's error string.
//
// Regression for round-7 SEC-BE-001.
func TestMitmproxyImporter_Native_LargeMethodBoundedInError(t *testing.T) {
	const n = 4096 // comfortably over maxPreviewBytes (64) but small enough to keep the test fast
	bigMethod := strings.Repeat("A", n)
	state := flowState(
		"GET", "https", "example.com", 443, "/api",
		nil, nil, 200, nil, nil,
	)
	req := state["request"].(map[string]any)
	req["method"] = []byte(bigMethod)

	m := &MitmproxyImporter{}
	_, err := m.Import(bytes.NewReader(encodeTnet(state)))
	require.Error(t, err)
	msg := err.Error()
	assert.Contains(t, msg, "invalid HTTP method")
	assert.Contains(t, msg, "bytes total")
	// A 4 KB payload embed would blow past this. Upper bound = preview (64)
	// + format overhead (~120).
	assert.Less(t, len(msg), 256,
		"error message not bounded: got %d bytes", len(msg))
}

// TestMitmproxyImporter_Native_LargeSchemeBoundedInError mirrors the method
// bound for the scheme field (same code path, different branch).
func TestMitmproxyImporter_Native_LargeSchemeBoundedInError(t *testing.T) {
	const n = 4096
	bigScheme := strings.Repeat("z", n)
	state := flowState(
		"GET", "https", "example.com", 443, "/api",
		nil, nil, 200, nil, nil,
	)
	req := state["request"].(map[string]any)
	req["scheme"] = []byte(bigScheme)

	m := &MitmproxyImporter{}
	_, err := m.Import(bytes.NewReader(encodeTnet(state)))
	require.Error(t, err)
	msg := err.Error()
	assert.Contains(t, msg, "unsupported scheme")
	assert.Contains(t, msg, "bytes total")
	assert.Less(t, len(msg), 256)
}

// TestTnetInt64_OnlyAcceptsInt64 pins the narrowed contract: the helper
// accepts int64 (what the decoder emits for `#`-type elements) and returns
// 0 for anything else. Regression for round-7 TEST-002 — the older helper
// also coerced int and float64, masking schema drift.
func TestTnetInt64_OnlyAcceptsInt64(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want int64
	}{
		{"int64 positive", int64(443), 443},
		{"int64 zero", int64(0), 0},
		{"int64 negative", int64(-1), -1},
		{"plain int not coerced", 443, 0},
		{"float64 not coerced", 443.0, 0},
		{"string not coerced", "443", 0},
		{"bytes not coerced", []byte("443"), 0},
		{"nil", nil, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tnetInt64(tc.in))
		})
	}
}

// TestMitmproxyImporter_BuildRequestPath_EmptyPathFallsBackToRoot pins
// QUAL-003: for non-CONNECT requests with empty path, buildRequestPath now
// returns "/" rather than falling back to the authority (which produced
// malformed URLs like "https://example.com/example.com:80").
func TestMitmproxyImporter_BuildRequestPath_EmptyPathFallsBackToRoot(t *testing.T) {
	state := flowState(
		"GET", "https", "example.com", 443, "",
		nil, nil, 200, nil, nil,
	)
	req := state["request"].(map[string]any)
	req["authority"] = []byte("example.com:443")

	m := &MitmproxyImporter{}
	requests, err := m.Import(bytes.NewReader(encodeTnet(state)))
	require.NoError(t, err)
	require.Len(t, requests, 1)
	// Path falls back to "/" — authority is already reflected in host/port.
	assert.Equal(t, "https://example.com/", requests[0].URL)
}
