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

// Name returns the importer name.
func (MitmproxyImporter) Name() string {
	return "mitmproxy"
}

// Import reads mitmproxy JSON and converts to ObservedRequest format.
// Handles both single flow and array of flows.
//
// Memory efficiency (S3 fix): Uses streaming json.NewDecoder instead of io.ReadAll
// to avoid allocating the entire input as a raw byte buffer (up to 500MB).
// The decoder reads in ~4KB chunks. Note: parsed flow structs are still accumulated
// in memory as required by the []ObservedRequest return type - the improvement
// eliminates the raw JSON buffer, not the parsed data.
func (i *MitmproxyImporter) Import(r io.Reader) ([]crawl.ObservedRequest, error) { //nolint:gocyclo // mitmproxy format parsing
	// Limit reader to prevent resource exhaustion
	limitedReader := newLimitedReader(r, maxImportSize)
	bufReader := bufio.NewReader(limitedReader)

	// Peek first non-whitespace byte to determine JSON type (array vs object)
	firstByte, err := peekFirstNonWhitespace(bufReader)
	if err != nil {
		if limitedReader.hitLimit {
			return nil, ErrFileTooLarge
		}
		return nil, fmt.Errorf("mitmproxy importer: failed to read input: %w", err)
	}

	decoder := json.NewDecoder(bufReader)
	var requests []crawl.ObservedRequest

	switch firstByte {
	case '[':
		// Array of flows - parse and convert in single pass
		// Consume opening '['
		if _, err := decoder.Token(); err != nil {
			if limitedReader.hitLimit {
				return nil, ErrFileTooLarge
			}
			return nil, fmt.Errorf("mitmproxy importer: failed to read array start: %w", err)
		}
		// Decode and convert each flow immediately
		for decoder.More() {
			var flow mitmproxyFlow
			if err := decoder.Decode(&flow); err != nil {
				if limitedReader.hitLimit {
					return nil, ErrFileTooLarge
				}
				return nil, fmt.Errorf("mitmproxy importer: failed to decode flow: %w", err)
			}
			req, err := i.parseFlow(flow)
			if err != nil {
				return nil, fmt.Errorf("mitmproxy importer: %w", err)
			}
			requests = append(requests, req)
		}
		// Consume closing ']'
		if _, err := decoder.Token(); err != nil {
			if limitedReader.hitLimit {
				return nil, ErrFileTooLarge
			}
			return nil, fmt.Errorf("mitmproxy importer: failed to read array end: %w", err)
		}
	case '{':
		// Single flow object
		var flow mitmproxyFlow
		if err := decoder.Decode(&flow); err != nil {
			if limitedReader.hitLimit {
				return nil, ErrFileTooLarge
			}
			return nil, fmt.Errorf("mitmproxy importer: failed to decode flow: %w", err)
		}
		req, err := i.parseFlow(flow)
		if err != nil {
			return nil, fmt.Errorf("mitmproxy importer: %w", err)
		}
		requests = []crawl.ObservedRequest{req}
	default:
		return nil, fmt.Errorf("mitmproxy importer: expected JSON array or object, got %q", string(firstByte))
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

// parseFlow converts a mitmproxyFlow into an ObservedRequest.
// Constructs URL from request components, decodes base64 content, and extracts headers.
func (i *MitmproxyImporter) parseFlow(flow mitmproxyFlow) (crawl.ObservedRequest, error) {
	// Validate port
	if flow.Request.Port < 0 || flow.Request.Port > 65535 {
		return crawl.ObservedRequest{}, fmt.Errorf("invalid port: %d (must be 0-65535)", flow.Request.Port)
	}

	// Validate HTTP method for consistency with Burp importer
	if !validHTTPMethods[flow.Request.Method] {
		return crawl.ObservedRequest{}, fmt.Errorf("invalid HTTP method: %s", flow.Request.Method)
	}

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

// decodeContent decodes base64-encoded content from mitmproxy flow.
// Returns nil for nil or empty content, decoded bytes otherwise.
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
// Skips headers with empty names or malformed tuples (per RFC 7230).
func convertMitmproxyHeaders(mitmHeaders [][]string) map[string]string {
	headers := make(map[string]string)
	for _, h := range mitmHeaders {
		if len(h) >= 2 && h[0] != "" {
			headers[h[0]] = h[1]
		}
	}
	return headers
}
