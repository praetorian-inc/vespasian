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

package wsdl

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
)

// ParseWSDL unmarshals raw WSDL XML bytes into a Definitions struct.
// Supports WSDL 1.1 (namespace http://schemas.xmlsoap.org/wsdl/).
// Handles common non-UTF-8 encodings (ISO-8859-1, Latin-1) that appear
// in real-world WSDL documents.
func ParseWSDL(data []byte) (*Definitions, error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.CharsetReader = charsetReader

	var defs Definitions
	if err := decoder.Decode(&defs); err != nil {
		return nil, err
	}
	return &defs, nil
}

// charsetReader returns a reader that converts the named charset to UTF-8.
// For ISO-8859-1/Latin-1, bytes 0-127 map directly to UTF-8. Bytes 128-255
// are passed through unchanged, which is technically incorrect but sufficient
// for WSDL element/attribute names that use only ASCII characters.
func charsetReader(charset string, input io.Reader) (io.Reader, error) {
	switch strings.ToLower(charset) {
	case "iso-8859-1", "latin-1", "us-ascii", "ascii":
		return input, nil
	case "utf-8":
		return input, nil
	default:
		return nil, fmt.Errorf("unsupported charset: %s", charset)
	}
}
