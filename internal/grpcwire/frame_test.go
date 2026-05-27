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

package grpcwire

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeFrame(compressed bool, payload []byte) []byte {
	out := make([]byte, FrameHeaderLen+len(payload))
	if compressed {
		out[0] = 1
	}
	binary.BigEndian.PutUint32(out[1:5], uint32(len(payload))) //nolint:gosec // G115: test payload sizes are bounded
	copy(out[FrameHeaderLen:], payload)
	return out
}

func TestParseFrame_Valid(t *testing.T) {
	payload := []byte{0x01, 0x02, 0x03, 0x04}
	b := makeFrame(false, payload)

	f, n, err := ParseFrame(b)
	require.NoError(t, err)
	assert.Equal(t, len(b), n)
	assert.False(t, f.Compressed)
	assert.Equal(t, payload, f.Message)
}

func TestParseFrame_CompressedFlag(t *testing.T) {
	b := makeFrame(true, []byte{0xAA})
	f, _, err := ParseFrame(b)
	require.NoError(t, err)
	assert.True(t, f.Compressed)
}

func TestParseFrame_EmptyPayload(t *testing.T) {
	b := makeFrame(false, nil)
	f, n, err := ParseFrame(b)
	require.NoError(t, err)
	assert.Equal(t, FrameHeaderLen, n)
	assert.Empty(t, f.Message)
}

func TestParseFrame_HeaderTruncated(t *testing.T) {
	for i := range FrameHeaderLen {
		_, _, err := ParseFrame(make([]byte, i))
		assert.Error(t, err, "expected error for %d-byte input", i)
	}
}

func TestParseFrame_BodyTruncated(t *testing.T) {
	b := []byte{0x00, 0x00, 0x00, 0x00, 0x0A, 0x01, 0x02, 0x03}
	_, _, err := ParseFrame(b)
	assert.Error(t, err)
}

func TestParseFrames_Multiple(t *testing.T) {
	b := append(makeFrame(false, []byte("first")), makeFrame(false, []byte("second"))...)
	frames, err := ParseFrames(b)
	require.NoError(t, err)
	require.Len(t, frames, 2)
	assert.Equal(t, []byte("first"), frames[0].Message)
	assert.Equal(t, []byte("second"), frames[1].Message)
}

func TestParseFrames_PartialThenError(t *testing.T) {
	b := append(makeFrame(false, []byte("ok")), 0x00, 0x00)
	frames, err := ParseFrames(b)
	assert.Error(t, err)
	require.Len(t, frames, 1)
	assert.Equal(t, []byte("ok"), frames[0].Message)
}

func TestParseFrames_Empty(t *testing.T) {
	frames, err := ParseFrames(nil)
	require.NoError(t, err)
	assert.Empty(t, frames)
}

func TestParseVarint(t *testing.T) {
	tests := []struct {
		name  string
		in    []byte
		want  uint64
		wantN int
	}{
		{"zero", []byte{0x00}, 0, 1},
		{"one byte", []byte{0x7F}, 127, 1},
		{"two bytes", []byte{0x80, 0x01}, 128, 2},
		{"three bytes leaves trailer", []byte{0xAC, 0x02, 0xFF}, 300, 2},
		{"max uint32", []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x0F}, 0xFFFFFFFF, 5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, n, err := ParseVarint(tt.in)
			require.NoError(t, err)
			assert.Equal(t, tt.want, v)
			assert.Equal(t, tt.wantN, n)
		})
	}
}

func TestParseVarint_Truncated(t *testing.T) {
	_, _, err := ParseVarint([]byte{0x80})
	assert.Error(t, err)
}

func TestParseVarint_Overflow(t *testing.T) {
	b := []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01}
	_, _, err := ParseVarint(b)
	assert.Error(t, err)
}

func TestParseTag(t *testing.T) {
	tests := []struct {
		name     string
		in       []byte
		wantNum  int
		wantWire WireType
	}{
		{"field 1 varint", []byte{0x08}, 1, WireVarint},
		{"field 1 length-delim", []byte{0x0A}, 1, WireLengthDelim},
		{"field 2 length-delim", []byte{0x12}, 2, WireLengthDelim},
		{"field 16 (2-byte tag)", []byte{0x80, 0x01}, 16, WireVarint},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tag, _, err := ParseTag(tt.in)
			require.NoError(t, err)
			assert.Equal(t, tt.wantNum, tag.FieldNumber)
			assert.Equal(t, tt.wantWire, tag.WireType)
		})
	}
}

func varint(v uint64) []byte {
	var out []byte
	for v >= 0x80 {
		out = append(out, byte(v)|0x80)
		v >>= 7
	}
	out = append(out, byte(v))
	return out
}

func tag(field int, wire WireType) []byte {
	return varint(uint64(field)<<3 | uint64(wire)) //nolint:gosec // G115: test field numbers are small positive
}

func TestWalkFields_VarintField(t *testing.T) {
	msg := append(tag(1, WireVarint), 0x96, 0x01)

	var saw []Tag
	var values [][]byte
	err := WalkFields(msg, func(tg Tag, v []byte) bool {
		saw = append(saw, tg)
		values = append(values, v)
		return true
	})
	require.NoError(t, err)
	require.Len(t, saw, 1)
	assert.Equal(t, 1, saw[0].FieldNumber)
	assert.Equal(t, WireVarint, saw[0].WireType)
	assert.Equal(t, []byte{0x96, 0x01}, values[0])
}

func TestWalkFields_LengthDelimField(t *testing.T) {
	payload := []byte("hello")
	msg := append(tag(2, WireLengthDelim), append(varint(uint64(len(payload))), payload...)...)

	var got []byte
	err := WalkFields(msg, func(tg Tag, v []byte) bool {
		assert.Equal(t, 2, tg.FieldNumber)
		got = v
		return true
	})
	require.NoError(t, err)
	assert.Equal(t, payload, got)
}

func TestWalkFields_Fixed64Field(t *testing.T) {
	val := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	msg := append(tag(3, Wire64Bit), val...)

	err := WalkFields(msg, func(tg Tag, v []byte) bool {
		assert.Equal(t, 3, tg.FieldNumber)
		assert.Equal(t, Wire64Bit, tg.WireType)
		assert.Equal(t, val, v)
		return true
	})
	require.NoError(t, err)
}

func TestWalkFields_Fixed32Field(t *testing.T) {
	val := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	msg := append(tag(4, Wire32Bit), val...)

	err := WalkFields(msg, func(tg Tag, v []byte) bool {
		assert.Equal(t, 4, tg.FieldNumber)
		assert.Equal(t, Wire32Bit, tg.WireType)
		assert.Equal(t, val, v)
		return true
	})
	require.NoError(t, err)
}

func TestWalkFields_MultipleFields(t *testing.T) {
	msg := append(tag(1, WireVarint), 42)
	msg = append(msg, tag(2, WireLengthDelim)...)
	msg = append(msg, append(varint(2), 'h', 'i')...)

	var fields []int
	err := WalkFields(msg, func(tg Tag, _ []byte) bool {
		fields = append(fields, tg.FieldNumber)
		return true
	})
	require.NoError(t, err)
	assert.Equal(t, []int{1, 2}, fields)
}

func TestWalkFields_StopEarly(t *testing.T) {
	msg := append(tag(1, WireVarint), 1)
	msg = append(msg, tag(2, WireVarint)...)
	msg = append(msg, 2)

	count := 0
	err := WalkFields(msg, func(tg Tag, _ []byte) bool {
		count++
		return false
	})
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestWalkFields_TruncatedLengthDelim(t *testing.T) {
	msg := append(tag(1, WireLengthDelim), append(varint(10), 0xAA, 0xBB)...)
	err := WalkFields(msg, func(Tag, []byte) bool { return true })
	assert.Error(t, err)
}

func TestWalkFields_UnsupportedWireType(t *testing.T) {
	msg := tag(1, WireStartGroup)
	err := WalkFields(msg, func(Tag, []byte) bool { return true })
	assert.Error(t, err)
}

func TestWalkFields_TruncatedFixed64(t *testing.T) {
	msg := append(tag(1, Wire64Bit), 0x01, 0x02)
	err := WalkFields(msg, func(Tag, []byte) bool { return true })
	assert.Error(t, err)
}

func TestWalkFields_TruncatedFixed32(t *testing.T) {
	msg := append(tag(1, Wire32Bit), 0x01)
	err := WalkFields(msg, func(Tag, []byte) bool { return true })
	assert.Error(t, err)
}

func TestWalkFields_EmptyMessage(t *testing.T) {
	called := false
	err := WalkFields(nil, func(Tag, []byte) bool {
		called = true
		return true
	})
	require.NoError(t, err)
	assert.False(t, called)
}
