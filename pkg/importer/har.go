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
	"encoding/json"
	"fmt"
	"io"

	"github.com/praetorian-inc/vespasian/pkg/crawl"
)

// HARImporter imports HAR 1.2 JSON traffic captures.
type HARImporter struct{}

// Name returns the importer name.
func (i *HARImporter) Name() string {
	return "har"
}

type harLog struct {
	Log struct {
		Entries []harEntry `json:"entries"`
	} `json:"log"`
}

type harEntry struct {
	Request  harRequest  `json:"request"`
	Response harResponse `json:"response"`
}

type harRequest struct {
	Method   string      `json:"method"`
	URL      string      `json:"url"`
	Headers  []harHeader `json:"headers"`
	PostData struct {
		Text string `json:"text"`
	} `json:"postData"`
}

type harResponse struct {
	Status  int         `json:"status"`
	Headers []harHeader `json:"headers"`
	Content struct {
		Text     string `json:"text"`
		MimeType string `json:"mimeType"`
	} `json:"content"`
}

type harHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Import reads HAR 1.2 JSON and converts to ObservedRequest format.
func (i *HARImporter) Import(r io.Reader) ([]crawl.ObservedRequest, error) {
	// Limit reader to prevent resource exhaustion
	limitedReader := io.LimitReader(r, maxImportSize)

	var har harLog
	if err := json.NewDecoder(limitedReader).Decode(&har); err != nil {
		return nil, fmt.Errorf("har importer: failed to decode JSON: %w", err)
	}

	var requests []crawl.ObservedRequest
	for _, entry := range har.Log.Entries {
		respHeaders := convertHeaders(entry.Response.Headers)

		// Convert request body only if non-empty
		var reqBody []byte
		if entry.Request.PostData.Text != "" {
			reqBody = []byte(entry.Request.PostData.Text)
		}

		// Convert response body only if non-empty
		var respBody []byte
		if entry.Response.Content.Text != "" {
			respBody = []byte(entry.Response.Content.Text)
		}

		req := crawl.ObservedRequest{
			Method:      entry.Request.Method,
			URL:         entry.Request.URL,
			Headers:     convertHeaders(entry.Request.Headers),
			QueryParams: extractQueryParams(entry.Request.URL),
			Body:        reqBody,
			Response: crawl.ObservedResponse{
				StatusCode:  entry.Response.Status,
				Headers:     respHeaders,
				ContentType: respHeaders["Content-Type"],
				Body:        respBody,
			},
			Source: "import:har",
		}
		requests = append(requests, req)
	}

	return requests, nil
}

// convertHeaders converts HAR header array to map.
func convertHeaders(harHeaders []harHeader) map[string]string {
	headers := make(map[string]string)
	for _, h := range harHeaders {
		headers[h.Name] = h.Value
	}
	return headers
}
