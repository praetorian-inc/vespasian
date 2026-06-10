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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseHeader_Valid(t *testing.T) {
	name, value, err := ParseHeader("Authorization: Bearer tok")
	require.NoError(t, err)
	assert.Equal(t, "Authorization", name)
	assert.Equal(t, "Bearer tok", value)
}

func TestParseHeader_MissingColon(t *testing.T) {
	_, _, err := ParseHeader("no-colon-here")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid header format")
}

func TestParseHeader_EmptyName(t *testing.T) {
	_, _, err := ParseHeader(": value")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty name")
}

func TestParseHeader_InvalidNameChar(t *testing.T) {
	_, _, err := ParseHeader("Bad Name: value")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "RFC 7230")
}

func TestParseHeader_RejectsCRLF(t *testing.T) {
	_, _, err := ParseHeader("X-Smuggle: a\r\nSet-Cookie: pwn")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid characters")
}

func TestParseHeader_RejectsNUL(t *testing.T) {
	_, _, err := ParseHeader("X-Smuggle: a\x00b")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid characters")
}

func TestParseHeader_ErrorOmitsValue(t *testing.T) {
	_, _, err := ParseHeader("Authorization: Bearer\r\nleaked-token-value")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "leaked-token-value")
	assert.Contains(t, err.Error(), "Authorization")
}
