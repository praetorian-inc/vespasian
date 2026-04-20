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
	"fmt"
	"io"
	"strconv"
)

// parseNativeRequest extracts the request fields needed from a native mitmproxy flow map.
func parseNativeRequest(raw map[string]any) (mitmproxyNormalizedRequest, error) {
	method, err := tnetValueString(raw["method"])
	if err != nil {
		return mitmproxyNormalizedRequest{}, fmt.Errorf("invalid native request method: %w", err)
	}
	scheme, err := tnetValueString(raw["scheme"])
	if err != nil {
		return mitmproxyNormalizedRequest{}, fmt.Errorf("invalid native request scheme: %w", err)
	}
	host, err := tnetValueString(raw["host"])
	if err != nil {
		return mitmproxyNormalizedRequest{}, fmt.Errorf("invalid native request host: %w", err)
	}
	port, err := tnetValueInt(raw["port"])
	if err != nil {
		return mitmproxyNormalizedRequest{}, fmt.Errorf("invalid native request port: %w", err)
	}
	path, err := tnetValueString(raw["path"])
	if err != nil {
		return mitmproxyNormalizedRequest{}, fmt.Errorf("invalid native request path: %w", err)
	}
	headers, err := tnetHeaderPairs(raw["headers"])
	if err != nil {
		return mitmproxyNormalizedRequest{}, fmt.Errorf("invalid native request headers: %w", err)
	}
	content, err := tnetValueBytes(raw["content"])
	if err != nil {
		return mitmproxyNormalizedRequest{}, fmt.Errorf("invalid native request content: %w", err)
	}

	return mitmproxyNormalizedRequest{
		Method:  method,
		Scheme:  scheme,
		Host:    host,
		Port:    port,
		Path:    path,
		Headers: headers,
		Content: content,
	}, nil
}

// parseNativeResponse extracts the response fields needed from a native mitmproxy flow map.
func parseNativeResponse(raw any) (mitmproxyNormalizedResponse, error) {
	if raw == nil {
		return mitmproxyNormalizedResponse{}, nil
	}

	responseMap, ok := raw.(map[string]any)
	if !ok {
		return mitmproxyNormalizedResponse{}, fmt.Errorf("invalid native mitmproxy response")
	}

	statusCode, err := tnetValueInt(responseMap["status_code"])
	if err != nil {
		return mitmproxyNormalizedResponse{}, fmt.Errorf("invalid native response status code: %w", err)
	}
	headers, err := tnetHeaderPairs(responseMap["headers"])
	if err != nil {
		return mitmproxyNormalizedResponse{}, fmt.Errorf("invalid native response headers: %w", err)
	}
	content, err := tnetValueBytes(responseMap["content"])
	if err != nil {
		return mitmproxyNormalizedResponse{}, fmt.Errorf("invalid native response content: %w", err)
	}

	return mitmproxyNormalizedResponse{
		StatusCode: statusCode,
		Headers:    headers,
		Content:    content,
	}, nil
}

// tnetHeaderPairs converts native mitmproxy header tuples into the shared header representation.
func tnetHeaderPairs(raw any) ([][]string, error) {
	if raw == nil {
		return nil, nil
	}

	values, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("expected list, got %T", raw)
	}

	headers := make([][]string, 0, len(values))
	for _, value := range values {
		pair, ok := value.([]any)
		if !ok || len(pair) < 2 {
			continue
		}

		name, err := tnetValueString(pair[0])
		if err != nil || name == "" {
			continue
		}
		headerValue, err := tnetValueString(pair[1])
		if err != nil {
			continue
		}

		headers = append(headers, []string{name, headerValue})
	}

	return headers, nil
}

// tnetValueString converts a parsed tnetstring scalar into a Go string.
func tnetValueString(raw any) (string, error) {
	switch value := raw.(type) {
	case string:
		return value, nil
	case []byte:
		return string(value), nil
	default:
		return "", fmt.Errorf("expected string or bytes, got %T", raw)
	}
}

// tnetValueBytes converts a parsed tnetstring scalar into raw bytes.
func tnetValueBytes(raw any) ([]byte, error) {
	if raw == nil {
		return nil, nil
	}

	switch value := raw.(type) {
	case []byte:
		return value, nil
	case string:
		return []byte(value), nil
	default:
		return nil, fmt.Errorf("expected bytes or string, got %T", raw)
	}
}

// tnetValueInt converts a parsed tnetstring numeric value into a Go int.
func tnetValueInt(raw any) (int, error) {
	switch value := raw.(type) {
	case int:
		return value, nil
	case int64:
		return int(value), nil
	case float64:
		return int(value), nil
	default:
		return 0, fmt.Errorf("expected integer, got %T", raw)
	}
}

// readTnetstring reads one top-level tnetstring value with size sanity checks.
func readTnetstring(r *bufio.Reader, availableBytes int64, maxBodySize int64) (any, error) {
	firstByte, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	if firstByte < '0' || firstByte > '9' {
		return nil, fmt.Errorf("not a tnetstring: missing or invalid length prefix")
	}

	lengthPrefix := []byte{firstByte}
	for {
		b, err := r.ReadByte()
		if err != nil {
			if err == io.EOF {
				return nil, fmt.Errorf("not a tnetstring: missing or invalid length prefix")
			}
			return nil, err
		}
		if b == ':' {
			break
		}
		if b < '0' || b > '9' {
			return nil, fmt.Errorf("not a tnetstring: missing or invalid length prefix")
		}
		lengthPrefix = append(lengthPrefix, b)
	}

	if len(lengthPrefix) > 12 {
		return nil, fmt.Errorf("not a tnetstring: absurdly large length prefix")
	}

	length, err := strconv.Atoi(string(lengthPrefix))
	if err != nil {
		return nil, fmt.Errorf("not a tnetstring: missing or invalid length prefix")
	}
	if int64(length) > maxBodySize {
		return nil, ErrFileTooLarge
	}

	remainingAfterPrefix := availableBytes - int64(len(lengthPrefix)) - 1
	if remainingAfterPrefix < 0 || int64(length)+1 > remainingAfterPrefix {
		return nil, fmt.Errorf("not a tnetstring: invalid length prefix: %d", length)
	}

	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, fmt.Errorf("not a tnetstring: invalid length prefix: %d", length)
	}

	tag, err := r.ReadByte()
	if err != nil {
		if err == io.EOF {
			return nil, fmt.Errorf("not a tnetstring: invalid length prefix: %d", length)
		}
		return nil, err
	}

	return parseTnetstringValue(tag, body)
}

// parseTnetstringSegment decodes one nested tnetstring value from a byte slice.
func parseTnetstringSegment(data []byte) (any, int, error) {
	prefixEnd := -1
	for i, b := range data {
		if b == ':' {
			prefixEnd = i
			break
		}
		if b < '0' || b > '9' {
			return nil, 0, fmt.Errorf("not a tnetstring: missing or invalid length prefix")
		}
	}
	if prefixEnd == -1 {
		return nil, 0, fmt.Errorf("not a tnetstring: missing or invalid length prefix")
	}

	length, err := strconv.Atoi(string(data[:prefixEnd]))
	if err != nil {
		return nil, 0, fmt.Errorf("not a tnetstring: missing or invalid length prefix")
	}

	bodyStart := prefixEnd + 1
	bodyEnd := bodyStart + length
	if bodyEnd >= len(data) {
		return nil, 0, fmt.Errorf("not a tnetstring: invalid length prefix: %d", length)
	}

	value, err := parseTnetstringValue(data[bodyEnd], data[bodyStart:bodyEnd])
	if err != nil {
		return nil, 0, err
	}

	return value, bodyEnd + 1, nil
}

// parseTnetstringValue converts a tnetstring tag/body pair into native Go values.
func parseTnetstringValue(tag byte, body []byte) (any, error) {
	switch tag {
	case ',':
		return body, nil
	case ';':
		return string(body), nil
	case '#':
		value, err := strconv.Atoi(string(body))
		if err != nil {
			return nil, fmt.Errorf("not a tnetstring: invalid integer literal: %q", string(body))
		}
		return value, nil
	case '^':
		value, err := strconv.ParseFloat(string(body), 64)
		if err != nil {
			return nil, fmt.Errorf("not a tnetstring: invalid float literal: %q", string(body))
		}
		return value, nil
	case '!':
		switch string(body) {
		case "true":
			return true, nil
		case "false":
			return false, nil
		default:
			return nil, fmt.Errorf("not a tnetstring: invalid boolean literal: %q", string(body))
		}
	case '~':
		if len(body) != 0 {
			return nil, fmt.Errorf("not a tnetstring: invalid null literal: %q", string(body))
		}
		return nil, nil
	case ']':
		items := make([]any, 0)
		for offset := 0; offset < len(body); {
			item, size, err := parseTnetstringSegment(body[offset:])
			if err != nil {
				return nil, err
			}
			items = append(items, item)
			offset += size
		}
		return items, nil
	case '}':
		values := make(map[string]any)
		for offset := 0; offset < len(body); {
			keyRaw, size, err := parseTnetstringSegment(body[offset:])
			if err != nil {
				return nil, err
			}
			offset += size

			value, size, err := parseTnetstringSegment(body[offset:])
			if err != nil {
				return nil, err
			}
			offset += size

			key, err := tnetValueString(keyRaw)
			if err != nil {
				return nil, fmt.Errorf("not a tnetstring: invalid dictionary key: %w", err)
			}
			values[key] = value
		}
		return values, nil
	default:
		return nil, fmt.Errorf("unknown type tag: %d", tag)
	}
}
