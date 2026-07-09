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

package crawl

import (
	"fmt"
	"strings"
)

// ParseHeader parses a single "Key: Value" string, validating that the name is
// an RFC 7230 token and the value contains no CR, LF, or NUL. Whitespace around
// the name and value is trimmed.
//
// Validation errors deliberately never include the header value (only the
// name), to avoid leaking secrets such as auth tokens carried in header values.
func ParseHeader(raw string) (name, value string, err error) {
	parts := strings.SplitN(raw, ":", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid header format (expected 'Key: Value')")
	}
	name = strings.TrimSpace(parts[0])
	value = strings.TrimSpace(parts[1])
	if name == "" {
		return "", "", fmt.Errorf("header has empty name")
	}
	if !isValidHeaderName(name) {
		return "", "", fmt.Errorf("header name contains invalid characters (RFC 7230): %q", name)
	}
	if strings.ContainsAny(value, "\r\n\x00") {
		return "", "", fmt.Errorf("header %q value contains invalid characters", name)
	}
	return name, value, nil
}

func isValidHeaderName(name string) bool {
	for i := 0; i < len(name); i++ {
		if !isTokenChar(name[i]) {
			return false
		}
	}
	return true
}

// isTokenChar reports whether c is a valid RFC 7230 tchar.
//
//nolint:gocyclo // character-class lookup table
func isTokenChar(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z':
		return true
	case c >= 'a' && c <= 'z':
		return true
	case c >= '0' && c <= '9':
		return true
	case c == '!' || c == '#' || c == '$' || c == '%' || c == '&' ||
		c == '\'' || c == '*' || c == '+' || c == '-' || c == '.' ||
		c == '^' || c == '_' || c == '`' || c == '|' || c == '~':
		return true
	default:
		return false
	}
}
