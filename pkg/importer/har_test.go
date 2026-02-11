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
)

func TestHARImporter_Name(t *testing.T) {
	h := &HARImporter{}
	if h.Name() != "har" {
		t.Errorf("Name() = %q, want %q", h.Name(), "har")
	}
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
				if tt.wantMethod == "GET" && len(req.Headers) == 0 {
					t.Error("Headers should not be empty for GET request")
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
			if (err != nil) != tt.wantErr {
				t.Errorf("Import() error = %v, wantErr %v", err, tt.wantErr)
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
