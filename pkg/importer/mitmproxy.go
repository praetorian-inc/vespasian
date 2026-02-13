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
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/praetorian-inc/vespasian/pkg/crawl"
)

// MitmproxyImporter imports mitmproxy JSON traffic captures.
type MitmproxyImporter struct{}

// Name returns the importer name.
func (i *MitmproxyImporter) Name() string {
	return "mitmproxy"
}

type mitmproxyFlow struct {
	Request  mitmproxyRequest  `json:"request"`
	Response mitmproxyResponse `json:"response"`
}

type mitmproxyRequest struct {
	Method  string     `json:"method"`
	Scheme  string     `json:"scheme"`
	Host    string     `json:"host"`
	Port    int        `json:"port"`
	Path    string     `json:"path"`
	Headers [][]string `json:"headers"`
	Content *string    `json:"content"`
}

type mitmproxyResponse struct {
	StatusCode int        `json:"status_code"`
	Headers    [][]string `json:"headers"`
	Content    *string    `json:"content"`
}

// Import reads mitmproxy JSON and converts to ObservedRequest format.
// Handles both single flow and array of flows.
func (i *MitmproxyImporter) Import(r io.Reader) ([]crawl.ObservedRequest, error) {
	// Limit reader to prevent resource exhaustion
	limitedReader := io.LimitReader(r, maxImportSize)
	data, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("mitmproxy importer: failed to read input: %w", err)
	}

	// Try parsing as array first
	var flows []mitmproxyFlow
	if err := json.Unmarshal(data, &flows); err != nil {
		// Try parsing as single flow
		var flow mitmproxyFlow
		if err := json.Unmarshal(data, &flow); err != nil {
			return nil, fmt.Errorf("mitmproxy importer: failed to decode JSON: %w", err)
		}
		flows = []mitmproxyFlow{flow}
	}

	var requests []crawl.ObservedRequest
	for _, flow := range flows {
		req, err := i.parseFlow(flow)
		if err != nil {
			return nil, fmt.Errorf("mitmproxy importer: %w", err)
		}
		requests = append(requests, req)
	}

	return requests, nil
}

func (i *MitmproxyImporter) parseFlow(flow mitmproxyFlow) (crawl.ObservedRequest, error) {
	// Construct URL
	url := constructURL(flow.Request.Scheme, flow.Request.Host, flow.Request.Port, flow.Request.Path)

	// Decode request content
	reqBody, err := decodeContent(flow.Request.Content)
	if err != nil {
		return crawl.ObservedRequest{}, fmt.Errorf("failed to decode request content: %w", err)
	}

	// Decode response content
	respBody, err := decodeContent(flow.Response.Content)
	if err != nil {
		return crawl.ObservedRequest{}, fmt.Errorf("failed to decode response content: %w", err)
	}

	respHeaders := convertMitmproxyHeaders(flow.Response.Headers)
	return crawl.ObservedRequest{
		Method:      flow.Request.Method,
		URL:         url,
		Headers:     convertMitmproxyHeaders(flow.Request.Headers),
		QueryParams: extractQueryParams(url),
		Body:        reqBody,
		Response: crawl.ObservedResponse{
			StatusCode:  flow.Response.StatusCode,
			Headers:     respHeaders,
			ContentType: respHeaders["Content-Type"],
			Body:        respBody,
		},
		Source: "import:mitmproxy",
	}, nil
}

// constructURL builds URL from mitmproxy components using url.URL struct.
func constructURL(scheme, host string, port int, path string) string {
	// Parse path to separate path and query
	pathPart, query, _ := strings.Cut(path, "?")

	u := &url.URL{
		Scheme:   scheme,
		Host:     host,
		Path:     pathPart,
		RawQuery: query,
	}

	// Add port if non-default
	isDefaultPort := (scheme == "https" && port == 443) || (scheme == "http" && port == 80)
	if !isDefaultPort {
		u.Host = fmt.Sprintf("%s:%d", host, port)
	}

	return u.String()
}

// decodeContent decodes base64-encoded content.
func decodeContent(content *string) ([]byte, error) {
	if content == nil || *content == "" {
		return nil, nil
	}

	decoded, err := base64.StdEncoding.DecodeString(*content)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}
	return decoded, nil
}

// convertMitmproxyHeaders converts mitmproxy header tuples to map.
func convertMitmproxyHeaders(mitmHeaders [][]string) map[string]string {
	headers := make(map[string]string)
	for _, h := range mitmHeaders {
		if len(h) >= 2 {
			headers[h[0]] = h[1]
		}
	}
	return headers
}
