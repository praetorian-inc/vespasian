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
	"bufio"
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
//
// Memory efficiency (S3 fix): Uses streaming json.NewDecoder instead of io.ReadAll
// to avoid allocating the entire input as a raw byte buffer (up to 500MB).
// The decoder reads in ~4KB chunks. Note: parsed flow structs are still accumulated
// in memory as required by the []ObservedRequest return type - the improvement
// eliminates the raw JSON buffer, not the parsed data.
func (i *MitmproxyImporter) Import(r io.Reader) ([]crawl.ObservedRequest, error) {
	// Limit reader to prevent resource exhaustion
	limitedReader := io.LimitReader(r, maxImportSize)
	bufReader := bufio.NewReader(limitedReader)

	// Peek first non-whitespace byte to determine JSON type (array vs object)
	firstByte, err := peekFirstNonWhitespace(bufReader)
	if err != nil {
		return nil, fmt.Errorf("mitmproxy importer: failed to read input: %w", err)
	}

	decoder := json.NewDecoder(bufReader)
	var flows []mitmproxyFlow

	switch firstByte {
	case '[':
		// Array of flows - stream decode each element
		// Consume opening '['
		if _, err := decoder.Token(); err != nil {
			return nil, fmt.Errorf("mitmproxy importer: failed to read array start: %w", err)
		}
		// Decode each flow individually (memory efficient)
		for decoder.More() {
			var flow mitmproxyFlow
			if err := decoder.Decode(&flow); err != nil {
				return nil, fmt.Errorf("mitmproxy importer: failed to decode flow: %w", err)
			}
			flows = append(flows, flow)
		}
		// Consume closing ']'
		if _, err := decoder.Token(); err != nil {
			return nil, fmt.Errorf("mitmproxy importer: failed to read array end: %w", err)
		}
	case '{':
		// Single flow object
		var flow mitmproxyFlow
		if err := decoder.Decode(&flow); err != nil {
			return nil, fmt.Errorf("mitmproxy importer: failed to decode flow: %w", err)
		}
		flows = []mitmproxyFlow{flow}
	default:
		return nil, fmt.Errorf("mitmproxy importer: expected JSON array or object, got %q", string(firstByte))
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

// peekFirstNonWhitespace reads and unreads bytes until finding a non-whitespace character.
func peekFirstNonWhitespace(r *bufio.Reader) (byte, error) {
	for {
		b, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		// Skip JSON whitespace: space, tab, newline, carriage return
		if b != ' ' && b != '\t' && b != '\n' && b != '\r' {
			// Unread so decoder sees it
			if err := r.UnreadByte(); err != nil {
				return 0, err
			}
			return b, nil
		}
	}
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
