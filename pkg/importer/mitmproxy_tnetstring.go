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
	lengthPrefix, err := readTnetstringLengthPrefix(r, firstByte)
	if err != nil {
		return nil, err
	}

	length, err := parseTnetstringLength(lengthPrefix, maxBodySize)
	if err != nil {
		return nil, err
	}
	if err := validateTnetstringLength(length, len(lengthPrefix), availableBytes); err != nil {
		return nil, err
	}

	body, err := readTnetstringBody(r, length)
	if err != nil {
		return nil, invalidTnetstringLength(length)
	}

	tag, err := readTnetstringTag(r, length)
	if err != nil {
		return nil, err
	}

	return parseTnetstringValue(tag, body)
}

func readTnetstringLengthPrefix(r *bufio.Reader, firstByte byte) ([]byte, error) {
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
			return lengthPrefix, nil
		}
		if b < '0' || b > '9' {
			return nil, fmt.Errorf("not a tnetstring: missing or invalid length prefix")
		}
		lengthPrefix = append(lengthPrefix, b)
	}
}

func parseTnetstringLength(lengthPrefix []byte, maxBodySize int64) (int, error) {
	if len(lengthPrefix) > 12 {
		return 0, fmt.Errorf("not a tnetstring: absurdly large length prefix")
	}

	length, err := strconv.Atoi(string(lengthPrefix))
	if err != nil {
		return 0, fmt.Errorf("not a tnetstring: missing or invalid length prefix")
	}
	if int64(length) > maxBodySize {
		return 0, ErrFileTooLarge
	}

	return length, nil
}

func validateTnetstringLength(length int, prefixLength int, availableBytes int64) error {
	remainingAfterPrefix := availableBytes - int64(prefixLength) - 1
	if remainingAfterPrefix < 0 || int64(length)+1 > remainingAfterPrefix {
		return invalidTnetstringLength(length)
	}

	return nil
}

func readTnetstringBody(r *bufio.Reader, length int) ([]byte, error) {
	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}

	return body, nil
}

func readTnetstringTag(r *bufio.Reader, length int) (byte, error) {
	tag, err := r.ReadByte()
	if err != nil {
		if err == io.EOF {
			return 0, invalidTnetstringLength(length)
		}
		return 0, err
	}

	return tag, nil
}

func invalidTnetstringLength(length int) error {
	return fmt.Errorf("not a tnetstring: invalid length prefix: %d", length)
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
	if value, handled, err := parseTnetstringScalar(tag, body); handled || err != nil {
		return value, err
	}

	switch tag {
	case ']':
		return parseTnetstringList(body)
	case '}':
		return parseTnetstringDict(body)
	default:
		return nil, fmt.Errorf("unknown type tag: %d", tag)
	}
}

func parseTnetstringScalar(tag byte, body []byte) (any, bool, error) {
	switch tag {
	case ',':
		return body, true, nil
	case ';':
		return string(body), true, nil
	case '#':
		value, err := strconv.Atoi(string(body))
		if err != nil {
			return nil, true, fmt.Errorf("not a tnetstring: invalid integer literal: %q", string(body))
		}
		return value, true, nil
	case '^':
		value, err := strconv.ParseFloat(string(body), 64)
		if err != nil {
			return nil, true, fmt.Errorf("not a tnetstring: invalid float literal: %q", string(body))
		}
		return value, true, nil
	case '!':
		return parseTnetstringBool(body)
	case '~':
		return parseTnetstringNull(body)
	default:
		return nil, false, nil
	}
}

func parseTnetstringBool(body []byte) (any, bool, error) {
	switch string(body) {
	case "true":
		return true, true, nil
	case "false":
		return false, true, nil
	default:
		return nil, true, fmt.Errorf("not a tnetstring: invalid boolean literal: %q", string(body))
	}
}

func parseTnetstringNull(body []byte) (any, bool, error) {
	if len(body) != 0 {
		return nil, true, fmt.Errorf("not a tnetstring: invalid null literal: %q", string(body))
	}

	return nil, true, nil
}

func parseTnetstringList(body []byte) ([]any, error) {
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
}

func parseTnetstringDict(body []byte) (map[string]any, error) {
	values := make(map[string]any)
	for offset := 0; offset < len(body); {
		keyRaw, value, nextOffset, err := parseTnetstringDictEntry(body, offset)
		if err != nil {
			return nil, err
		}

		key, err := tnetValueString(keyRaw)
		if err != nil {
			return nil, fmt.Errorf("not a tnetstring: invalid dictionary key: %w", err)
		}
		values[key] = value
		offset = nextOffset
	}

	return values, nil
}

func parseTnetstringDictEntry(body []byte, offset int) (any, any, int, error) {
	keyRaw, size, err := parseTnetstringSegment(body[offset:])
	if err != nil {
		return nil, nil, 0, err
	}
	offset += size

	value, size, err := parseTnetstringSegment(body[offset:])
	if err != nil {
		return nil, nil, 0, err
	}

	return keyRaw, value, offset + size, nil
}
