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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHARImporter_Name(t *testing.T) {
	h := &HARImporter{}
	assert.Equal(t, "har", h.Name())
}

func TestHARImporter_Import(t *testing.T) {
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
			name: "GET request",
			json: `{
				"log": {
					"entries": [{
						"request": {
							"method": "GET",
							"url": "https://example.com/api?page=1",
							"headers": [
								{"name": "User-Agent", "value": "Test"},
								{"name": "Accept", "value": "application/json"}
							]
						},
						"response": {
							"status": 200,
							"headers": [
								{"name": "Content-Type", "value": "application/json"}
							],
							"content": {
								"text": "{\"ok\":true}",
								"mimeType": "application/json"
							}
						}
					}]
				}
			}`,
			wantRequests: 1,
			wantMethod:   "GET",
			wantURL:      "https://example.com/api?page=1",
			wantSource:   "import:har",
			wantStatus:   200,
			wantRespBody: `{"ok":true}`,
		},
		{
			name: "POST request with body",
			json: `{
				"log": {
					"entries": [{
						"request": {
							"method": "POST",
							"url": "https://example.com/api/data",
							"headers": [
								{"name": "Content-Type", "value": "application/json"}
							],
							"postData": {
								"text": "{\"test\":\"data\"}"
							}
						},
						"response": {
							"status": 201,
							"headers": [
								{"name": "Content-Type", "value": "application/json"}
							],
							"content": {
								"text": "{\"id\":123}",
								"mimeType": "application/json"
							}
						}
					}]
				}
			}`,
			wantRequests: 1,
			wantMethod:   "POST",
			wantURL:      "https://example.com/api/data",
			wantSource:   "import:har",
			wantStatus:   201,
			wantReqBody:  `{"test":"data"}`,
			wantRespBody: `{"id":123}`,
		},
		{
			name: "multiple entries",
			json: `{
				"log": {
					"entries": [
						{
							"request": {
								"method": "GET",
								"url": "https://example.com/first",
								"headers": []
							},
							"response": {
								"status": 200,
								"headers": [],
								"content": {}
							}
						},
						{
							"request": {
								"method": "GET",
								"url": "https://example.com/second",
								"headers": []
							},
							"response": {
								"status": 200,
								"headers": [],
								"content": {}
							}
						}
					]
				}
			}`,
			wantRequests: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &HARImporter{}
			requests, err := h.Import(strings.NewReader(tt.json))
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
				if tt.wantMethod == "GET" {
					assert.NotEmpty(t, req.Headers)
				}
			}
		})
	}
}

func TestHARImporter_Import_Errors(t *testing.T) {
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
			name:    "empty log",
			json:    `{"log": {}}`,
			wantErr: false, // Should return empty slice
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &HARImporter{}
			_, err := h.Import(strings.NewReader(tt.json))
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHARImporter_ContentType(t *testing.T) {
	json := `{
		"log": {
			"entries": [{
				"request": {
					"method": "GET",
					"url": "https://example.com/api",
					"headers": []
				},
				"response": {
					"status": 200,
					"headers": [
						{"name": "Content-Type", "value": "application/json; charset=utf-8"}
					],
					"content": {
						"text": "{}",
						"mimeType": "application/json"
					}
				}
			}]
		}
	}`

	h := &HARImporter{}
	requests, err := h.Import(strings.NewReader(json))
	require.NoError(t, err)

	require.Len(t, requests, 1)

	req := requests[0]
	wantContentType := "application/json; charset=utf-8"
	assert.Equal(t, wantContentType, req.Response.ContentType)
}

func TestHARImporter_QueryParams(t *testing.T) {
	json := `{
		"log": {
			"entries": [{
				"request": {
					"method": "GET",
					"url": "https://example.com/api?page=1&limit=10",
					"headers": []
				},
				"response": {
					"status": 200,
					"headers": [],
					"content": {}
				}
			}]
		}
	}`

	h := &HARImporter{}
	requests, err := h.Import(strings.NewReader(json))
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

func TestHARImporter_SizeLimit(t *testing.T) {
	// Create a valid HAR structure
	normalHAR := `{"log":{"entries":[{"request":{"method":"GET","url":"https://example.com/test","headers":[]},"response":{"status":200,"headers":[],"content":{}}}]}}`

	h := &HARImporter{}

	// Normal parse should work
	requests, err := h.Import(strings.NewReader(normalHAR))
	require.NoError(t, err)
	assert.Len(t, requests, 1)

	// Truncated JSON should produce decode error
	truncated := normalHAR[:len(normalHAR)/2]
	_, err = h.Import(strings.NewReader(truncated))
	assert.Error(t, err)
}
