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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCharsetReader_SupportedCharsets(t *testing.T) {
	supported := []string{
		"iso-8859-1",
		"latin-1",
		"us-ascii",
		"ascii",
		"utf-8",
		// Also verify case-insensitivity via the strings.ToLower in the implementation.
		"ISO-8859-1",
		"Latin-1",
		"US-ASCII",
		"ASCII",
		"UTF-8",
	}

	for _, charset := range supported {
		t.Run(charset, func(t *testing.T) {
			input := strings.NewReader("hello")
			reader, err := charsetReader(charset, input)
			require.NoError(t, err, "charsetReader(%q) should not return an error", charset)
			assert.NotNil(t, reader, "charsetReader(%q) should return a non-nil reader", charset)
		})
	}
}

func TestCharsetReader_UnsupportedCharset(t *testing.T) {
	unsupported := []string{
		"windows-1252",
		"shift_jis",
		"euc-kr",
		"gb2312",
		"unknown",
	}

	for _, charset := range unsupported {
		t.Run(charset, func(t *testing.T) {
			input := strings.NewReader("hello")
			reader, err := charsetReader(charset, input)
			assert.Error(t, err, "charsetReader(%q) should return an error", charset)
			assert.Nil(t, reader, "charsetReader(%q) should return a nil reader", charset)
			assert.Contains(t, err.Error(), "unsupported charset")
		})
	}
}

func TestParseWSDL_ISO88591Encoding(t *testing.T) {
	wsdlXML := `<?xml version="1.0" encoding="ISO-8859-1"?>
<definitions name="TestService" xmlns="http://schemas.xmlsoap.org/wsdl/">
  <message name="Msg"><part name="p" type="xsd:string"/></message>
  <portType name="TestPortType">
    <operation name="GetUser">
      <input message="tns:Msg"/>
    </operation>
  </portType>
</definitions>`

	defs, err := ParseWSDL([]byte(wsdlXML))
	require.NoError(t, err, "ParseWSDL should handle ISO-8859-1 encoding declaration")
	assert.Equal(t, "TestService", defs.Name)
	require.Len(t, defs.Messages, 1)
	require.Len(t, defs.PortTypes, 1)
	assert.Equal(t, "GetUser", defs.PortTypes[0].Operations[0].Name)
}

func TestParseWSDL_UTF8Encoding(t *testing.T) {
	wsdlXML := `<?xml version="1.0" encoding="UTF-8"?>
<definitions name="UTF8Service" xmlns="http://schemas.xmlsoap.org/wsdl/">
  <message name="PingRequest"><part name="p" type="xsd:string"/></message>
  <portType name="UTF8PortType">
    <operation name="Ping">
      <input message="tns:PingRequest"/>
    </operation>
  </portType>
</definitions>`

	defs, err := ParseWSDL([]byte(wsdlXML))
	require.NoError(t, err, "ParseWSDL should handle UTF-8 encoding declaration")
	assert.Equal(t, "UTF8Service", defs.Name)
	require.Len(t, defs.Messages, 1)
	require.Len(t, defs.PortTypes, 1)
	assert.Equal(t, "Ping", defs.PortTypes[0].Operations[0].Name)
}
