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
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/praetorian-inc/vespasian/pkg/crawl"
)

// BurpImporter imports Burp Suite XML traffic captures.
type BurpImporter struct{}

// Name returns the importer name.
func (i *BurpImporter) Name() string {
	return "burp"
}

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

// Import reads Burp Suite XML and converts to ObservedRequest format.
func (i *BurpImporter) Import(r io.Reader) ([]crawl.ObservedRequest, error) {
	var items burpItems
	if err := xml.NewDecoder(r).Decode(&items); err != nil {
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

func decodeData(d burpData) ([]byte, error) {
	if d.Base64 == "true" {
		decoded, err := base64.StdEncoding.DecodeString(d.Data)
		if err != nil {
			return nil, fmt.Errorf("failed to decode base64: %w", err)
		}
		return decoded, nil
	}
	return []byte(d.Data), nil
}

func parseHTTPRequest(data []byte) (method string, headers map[string]string, body []byte, err error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	headers = make(map[string]string)

	// Parse request line
	if !scanner.Scan() {
		return "", nil, nil, fmt.Errorf("empty request")
	}
	parts := strings.Fields(scanner.Text())
	if len(parts) < 2 {
		return "", nil, nil, fmt.Errorf("invalid request line")
	}
	method = parts[0]

	// Parse headers
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || line == "\r" {
			// End of headers
			break
		}
		// Parse header
		idx := strings.Index(line, ":")
		if idx > 0 {
			key := strings.TrimSpace(line[:idx])
			value := strings.TrimSpace(line[idx+1:])
			headers[key] = value
		}
	}

	// Rest is body
	var bodyBuf bytes.Buffer
	for scanner.Scan() {
		bodyBuf.Write(scanner.Bytes())
		bodyBuf.WriteByte('\n')
	}
	if bodyBuf.Len() > 0 {
		// Remove trailing newline
		body = bytes.TrimRight(bodyBuf.Bytes(), "\n")
	}

	return method, headers, body, nil
}

func parseHTTPResponse(data []byte) (statusCode int, headers map[string]string, body []byte, err error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	headers = make(map[string]string)

	// Parse status line
	if !scanner.Scan() {
		return 0, nil, nil, fmt.Errorf("empty response")
	}
	parts := strings.Fields(scanner.Text())
	if len(parts) < 2 {
		return 0, nil, nil, fmt.Errorf("invalid status line")
	}
	statusCode, err = strconv.Atoi(parts[1])
	if err != nil {
		return 0, nil, nil, fmt.Errorf("invalid status code: %w", err)
	}

	// Parse headers
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || line == "\r" {
			// End of headers
			break
		}
		// Parse header
		idx := strings.Index(line, ":")
		if idx > 0 {
			key := strings.TrimSpace(line[:idx])
			value := strings.TrimSpace(line[idx+1:])
			headers[key] = value
		}
	}

	// Rest is body
	var bodyBuf bytes.Buffer
	for scanner.Scan() {
		bodyBuf.Write(scanner.Bytes())
		bodyBuf.WriteByte('\n')
	}
	if bodyBuf.Len() > 0 {
		// Remove trailing newline
		body = bytes.TrimRight(bodyBuf.Bytes(), "\n")
	}

	return statusCode, headers, body, nil
}
