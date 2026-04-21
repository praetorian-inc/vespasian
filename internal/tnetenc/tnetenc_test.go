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

package tnetenc

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Byte-level assertions prevent the encoder-as-oracle problem: if the encoder
// ever drifts from the format spec, round-trip decoder tests won't catch it
// because they use the same encoder for both ends. These tests compare
// against hand-computed tnetstring bytes.

func TestEncode_PrimitiveBytes(t *testing.T) {
	tests := []struct {
		name string
		in   any
		want string
	}{
		{"nil", nil, "0:~"},
		{"empty bytes", []byte{}, "0:,"},
		{"short bytes", []byte("hi"), "2:hi,"},
		{"string encoded as bytes", "ok", "2:ok,"},
		{"bool true", true, "4:true!"},
		{"bool false", false, "5:false!"},
		{"int zero", 0, "1:0#"},
		{"int positive", 443, "3:443#"},
		{"int negative", -1, "2:-1#"},
		{"int64", int64(1_000_000), "7:1000000#"},
		{"float", 1.5, "3:1.5^"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, string(Encode(tt.in)))
		})
	}
}

func TestEncode_PercentInPayloadIsNotFormatDirective(t *testing.T) {
	// Regression test for QUAL-009: earlier revisions used fmt.Sprintf with
	// %s on []byte, so a payload like "%d" or "%s" was interpreted as a
	// format directive rather than literal bytes. Encode must preserve every
	// byte verbatim.
	tricky := []byte("POST %d %s %%EOF")
	got := Encode(tricky)
	assert.Equal(t, "16:POST %d %s %%EOF,", string(got))
}

func TestEncode_NullByteInPayload(t *testing.T) {
	// Arbitrary binary bodies (including NUL) must survive encoding intact.
	payload := []byte{0x00, 0xFF, 0x7F, 0x01}
	got := Encode(payload)
	// "4:" + 4 payload bytes + ","
	assert.Equal(t, 7, len(got))
	assert.Equal(t, "4:", string(got[:2]))
	assert.Equal(t, payload, got[2:6])
	assert.Equal(t, byte(','), got[6])
}

func TestEncode_EmptyList(t *testing.T) {
	assert.Equal(t, "0:]", string(Encode([]any{})))
}

func TestEncode_ListOfPrimitives(t *testing.T) {
	// Inner: "3:123#" (6) + "4:true!" (7) + "2:hi," (5) = 18 bytes.
	got := Encode([]any{int64(123), true, []byte("hi")})
	assert.Equal(t, "18:3:123#4:true!2:hi,]", string(got))
}

func TestEncode_EmptyDict(t *testing.T) {
	assert.Equal(t, "0:}", string(Encode(map[string]any{})))
}

func TestEncode_DictKeysSortedDeterministically(t *testing.T) {
	// Keys must emerge in alphabetical order so that fixture bytes are
	// reproducible across runs regardless of Go map iteration order.
	d := map[string]any{
		"z": []byte("last"),
		"a": []byte("first"),
		"m": []byte("middle"),
	}
	got := string(Encode(d))
	// Decoded key order should be a, m, z.
	aIdx := findSubstring(got, "1:a,")
	mIdx := findSubstring(got, "1:m,")
	zIdx := findSubstring(got, "1:z,")
	assert.True(t, aIdx < mIdx && mIdx < zIdx,
		"keys not emitted in sorted order: a@%d, m@%d, z@%d in %q", aIdx, mIdx, zIdx, got)
}

func TestEncode_UnsupportedTypePanics(t *testing.T) {
	assert.Panics(t, func() { Encode(uint32(42)) })
	assert.Panics(t, func() { Encode(complex(1.0, 2.0)) })
}

func findSubstring(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
