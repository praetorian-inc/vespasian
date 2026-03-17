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
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/praetorian-inc/vespasian/pkg/crawl"
)

const (
	// Maximum file size for imports (500MB)
	maxImportSize = 500 * 1024 * 1024
)

var (
	validHTTPMethods = map[string]bool{
		"GET": true, "POST": true, "PUT": true, "DELETE": true,
		"PATCH": true, "HEAD": true, "OPTIONS": true, "TRACE": true, "CONNECT": true,
	}
)

// BurpImporter imports Burp Suite XML traffic captures.
type BurpImporter struct{}

type burpItems struct {
	XMLName xml.Name   `xml:"items"`
	Items   []burpItem `xml:"item"`
}

type burpItem struct {
	URL      string   `xml:"url"`
	Request  burpData `xml:"request"`
	Status   int      `xml:"status"`
	Response burpData `xml:"response"`
}

type burpData struct {
	Base64 string `xml:"base64,attr"`
	Data   string `xml:",chardata"`
}

// Name returns the importer name.
func (BurpImporter) Name() string {
	return "burp"
}

// containsXXEEntity checks for ENTITY declarations in XML data (XXE attack vector).
// DOCTYPE declarations are allowed as they are standard in Burp Suite XML exports.
func containsXXEEntity(data []byte) bool {
	target := []byte("<!ENTITY")
	for i := 0; i <= len(data)-len(target); i++ {
		// Fast-path: skip positions that don't start with '<' to avoid
		// calling EqualFold on every byte offset.
		if data[i] == '<' && bytes.EqualFold(data[i:i+len(target)], target) {
			return true
		}
	}
	return false
}

// Import reads Burp Suite XML and converts to ObservedRequest format.
func (i *BurpImporter) Import(r io.Reader) ([]crawl.ObservedRequest, error) {
	// Limit reader to prevent resource exhaustion
	limitedReader := newLimitedReader(r, maxImportSize)

	// Read all content to check for entity declarations
	data, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("burp importer: failed to read input: %w", err)
	}

	// Check if file was too large
	if limitedReader.hitLimit {
		return nil, ErrFileTooLarge
	}

	// Check for ENTITY declarations (XXE attack vectors)
	if containsXXEEntity(data) {
		return nil, fmt.Errorf("burp importer: XML validation: ENTITY declarations not allowed")
	}

	var items burpItems
	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.Strict = true
	if err := decoder.Decode(&items); err != nil {
		return nil, fmt.Errorf("burp importer: failed to decode XML: %w", err)
	}

	var requests []crawl.ObservedRequest
	for _, item := range items.Items {
		req, err := i.parseItem(item)
		if err != nil {
			return nil, fmt.Errorf("burp importer: %w", err)
		}
		requests = append(requests, req)
	}

	return requests, nil
}

func (i *BurpImporter) parseItem(item burpItem) (crawl.ObservedRequest, error) {
	// Decode request
	reqBytes, err := decodeData(item.Request)
	if err != nil {
		return crawl.ObservedRequest{}, fmt.Errorf("failed to decode request: %w", err)
	}

	// Decode response
	respBytes, err := decodeData(item.Response)
	if err != nil {
		return crawl.ObservedRequest{}, fmt.Errorf("failed to decode response: %w", err)
	}

	// Parse HTTP request
	method, headers, body, err := parseHTTPRequest(reqBytes)
	if err != nil {
		return crawl.ObservedRequest{}, fmt.Errorf("failed to parse request: %w", err)
	}

	// Handle empty response data (e.g., timeouts, connection resets)
	if len(respBytes) == 0 {
		return crawl.ObservedRequest{
			Method:      method,
			URL:         item.URL,
			Headers:     headers,
			QueryParams: extractQueryParams(item.URL),
			Body:        body,
			Response: crawl.ObservedResponse{
				StatusCode: item.Status,
				Headers:    map[string]string{},
			},
			Source: "import:burp",
		}, nil
	}

	// Parse HTTP response
	statusCode, respHeaders, respBody, err := parseHTTPResponse(respBytes)
	if err != nil {
		return crawl.ObservedRequest{}, fmt.Errorf("failed to parse response: %w", err)
	}

	// Override with status from XML if present
	if item.Status != 0 {
		statusCode = item.Status
	}

	return crawl.ObservedRequest{
		Method:      method,
		URL:         item.URL,
		Headers:     headers,
		QueryParams: extractQueryParams(item.URL),
		Body:        body,
		Response: crawl.ObservedResponse{
			StatusCode:  statusCode,
			Headers:     respHeaders,
			ContentType: respHeaders["Content-Type"],
			Body:        respBody,
		},
		Source: "import:burp",
	}, nil
}

// decodeData decodes burpData based on base64 attribute.
// Returns raw bytes if base64="false", decoded bytes if base64="true".
func decodeData(d burpData) ([]byte, error) {
	if strings.EqualFold(d.Base64, "true") {
		decoded, err := base64.StdEncoding.DecodeString(d.Data)
		if err != nil {
			return nil, fmt.Errorf("failed to decode base64: %w", err)
		}
		return decoded, nil
	}
	return []byte(d.Data), nil
}

// splitHTTPMessage splits raw HTTP data into first line, headers, and body.
// It handles both \r\n\r\n and \n\n as header/body separators.
func splitHTTPMessage(data []byte) (firstLine string, headers map[string]string, body []byte, err error) {
	headers = make(map[string]string)

	// Find the header/body separator
	separator := []byte("\r\n\r\n")
	sepIdx := bytes.Index(data, separator)
	if sepIdx == -1 {
		separator = []byte("\n\n")
		sepIdx = bytes.Index(data, separator)
		if sepIdx == -1 {
			return "", nil, nil, fmt.Errorf("no header/body separator found")
		}
	}

	// Split headers and body
	headerSection := data[:sepIdx]
	if sepIdx+len(separator) < len(data) {
		bodyData := data[sepIdx+len(separator):]
		if len(bodyData) > 0 {
			body = bodyData
		}
	}

	// Parse lines
	lines := bytes.Split(headerSection, []byte("\n"))
	if len(lines) == 0 {
		return "", nil, nil, fmt.Errorf("empty message")
	}

	// First line
	firstLine = string(bytes.TrimRight(lines[0], "\r"))

	// Parse headers
	for i := 1; i < len(lines); i++ {
		line := bytes.TrimRight(lines[i], "\r")
		if len(line) == 0 {
			continue
		}
		idx := bytes.IndexByte(line, ':')
		if idx > 0 {
			key := string(bytes.TrimSpace(line[:idx]))
			value := string(bytes.TrimSpace(line[idx+1:]))
			headers[key] = value
		}
	}

	return firstLine, headers, body, nil
}

// parseHTTPRequest parses raw HTTP request data into method, headers, and body.
// Validates HTTP method against validHTTPMethods.
func parseHTTPRequest(data []byte) (method string, headers map[string]string, body []byte, err error) {
	firstLine, headers, body, err := splitHTTPMessage(data)
	if err != nil {
		return "", nil, nil, err
	}

	parts := strings.Fields(firstLine)
	if len(parts) < 2 {
		return "", nil, nil, fmt.Errorf("invalid request line")
	}

	method = parts[0]
	if !validHTTPMethods[method] {
		return "", nil, nil, fmt.Errorf("invalid HTTP method: %s", method)
	}

	return method, headers, body, nil
}

// parseHTTPResponse parses raw HTTP response data into status code, headers, and body.
// Extracts status code from response status line (e.g., "HTTP/1.1 200 OK" -> 200).
func parseHTTPResponse(data []byte) (statusCode int, headers map[string]string, body []byte, err error) {
	firstLine, headers, body, err := splitHTTPMessage(data)
	if err != nil {
		return 0, nil, nil, err
	}

	parts := strings.Fields(firstLine)
	if len(parts) < 2 {
		return 0, nil, nil, fmt.Errorf("invalid status line")
	}

	statusCode, err = strconv.Atoi(parts[1])
	if err != nil {
		return 0, nil, nil, fmt.Errorf("invalid status code: %w", err)
	}

	return statusCode, headers, body, nil
}
