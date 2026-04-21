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
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/vespasian/internal/tnetenc"
)

// encodeTnet is a thin test-local alias over the shared encoder to keep
// existing test call sites concise.
func encodeTnet(v any) []byte { return tnetenc.Encode(v) }

// decodeHelper decodes a single tnetstring element from s via the streaming
// decoder. Shared by primitive tests and error-path tests.
func decodeHelper(t *testing.T, s string) any {
	t.Helper()
	r := bufio.NewReader(strings.NewReader(s))
	v, err := decodeTnetstringStream(r, 0)
	require.NoError(t, err)
	return v
}

func TestTnetstring_PrimitiveTypes(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  any
	}{
		{"bytes", "5:hello,", []byte("hello")},
		{"empty bytes", "0:,", []byte{}},
		{"utf8 string", "5:world;", "world"},
		{"integer positive", "3:123#", int64(123)},
		{"integer negative", "4:-456#", int64(-456)},
		{"integer zero", "1:0#", int64(0)},
		{"float", "3:1.5^", 1.5},
		{"bool true", "4:true!", true},
		{"bool false", "5:false!", false},
		{"null", "0:~", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := decodeHelper(t, tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestTnetstring_StringTypeRoundTrip(t *testing.T) {
	// Cover the `;` (UTF-8 string) code path with literal byte input. The
	// shared encoder emits bytes (`,`) not strings (`;`), so without this
	// explicit test the string decoder path is only touched by the primitive
	// table.
	got := decodeHelper(t, "11:hello world;")
	assert.Equal(t, "hello world", got)
}

func TestTnetstring_List(t *testing.T) {
	// Inner: "3:123#" (6) + "4:true!" (7) + "2:hi," (5) = 18 bytes
	input := "18:3:123#4:true!2:hi,]"
	got := decodeHelper(t, input).([]any)

	require.Len(t, got, 3)
	assert.Equal(t, int64(123), got[0])
	assert.Equal(t, true, got[1])
	assert.Equal(t, []byte("hi"), got[2])
}

func TestTnetstring_EmptyList(t *testing.T) {
	got := decodeHelper(t, "0:]")
	assert.Nil(t, got) // parseTnetList returns nil slice for empty container
}

func TestTnetstring_Dict(t *testing.T) {
	input := string(encodeTnet(map[string]any{
		"method": []byte("GET"),
		"port":   int64(443),
	}))

	got := decodeHelper(t, input).(map[string]any)
	assert.Equal(t, []byte("GET"), got["method"])
	assert.Equal(t, int64(443), got["port"])
}

func TestTnetstring_NestedDict(t *testing.T) {
	input := string(encodeTnet(map[string]any{
		"request": map[string]any{
			"method": []byte("POST"),
			"headers": []any{
				[]any{[]byte("Content-Type"), []byte("application/json")},
			},
		},
	}))

	got := decodeHelper(t, input).(map[string]any)
	req := got["request"].(map[string]any)
	assert.Equal(t, []byte("POST"), req["method"])

	headers := req["headers"].([]any)
	require.Len(t, headers, 1)
	pair := headers[0].([]any)
	assert.Equal(t, []byte("Content-Type"), pair[0])
	assert.Equal(t, []byte("application/json"), pair[1])
}

func TestTnetstring_RoundTrip(t *testing.T) {
	original := map[string]any{
		"type":  []byte("http"),
		"id":    []byte("flow-1"),
		"port":  int64(8080),
		"tls":   true,
		"error": nil,
		"tags":  []any{[]byte("foo"), []byte("bar")},
	}
	encoded := encodeTnet(original)

	got := decodeHelper(t, string(encoded)).(map[string]any)
	assert.Equal(t, []byte("http"), got["type"])
	assert.Equal(t, []byte("flow-1"), got["id"])
	assert.Equal(t, int64(8080), got["port"])
	assert.Equal(t, true, got["tls"])
	assert.Nil(t, got["error"])
	assert.Equal(t, []any{[]byte("foo"), []byte("bar")}, got["tags"])
}

func TestTnetstring_InvalidInputs(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"non-digit prefix", "a:hello,"},
		{"missing colon", "5hello,"},
		{"empty length prefix", ":hello,"},
		{"truncated payload", "99:short,"},
		{"missing type byte", "5:hello"},
		{"unknown type byte", "5:hello?"},
		{"empty input", ""},
		{"prefix too long", "12345678901:xxx,"},
		{"invalid float payload", "3:abc^"},
		// Dict with a single int key and no value: payload "3:k#0" is "3:k#"
		// (int key "k") + "0" (start of the next element — truncated).
		{"dict int-keyed with truncated value", "5:3:k#0}"},
		// Dict with a single bytes key and no following value element.
		{"dict key without value", "6:3:abc,}"},
		// Outer list of payload-length 10; inner element claims 99 bytes
		// which is more than the 10-byte enclosing buffer holds.
		{"nested list element length > enclosing buffer", "10:99:short,]"},
		// Empty payload for the integer type is not a valid int.
		{"empty integer payload", "0:#"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := bufio.NewReader(strings.NewReader(tt.input))
			_, err := decodeTnetstringStream(r, 0)
			require.Error(t, err)
		})
	}
}

func TestTnetstring_InvalidBool(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("3:yes!"))
	_, err := decodeTnetstringStream(r, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid bool")
}

func TestTnetstring_InvalidInt(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("3:abc#"))
	_, err := decodeTnetstringStream(r, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse int")
}

func TestTnetstring_NonEmptyNull(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("3:abc~"))
	_, err := decodeTnetstringStream(r, 0)
	require.Error(t, err)
}

func TestTnetstring_LengthTooLarge(t *testing.T) {
	// Length above the per-element cap is rejected before allocating.
	input := fmt.Sprintf("%d:x,", maxTnetstringElement+1)
	r := bufio.NewReader(strings.NewReader(input))
	_, err := decodeTnetstringStream(r, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "per-element cap")
}

func TestTnetstring_IntegerDictKey(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(encodeTnet(int64(1)))
	buf.Write(encodeTnet([]byte("value")))
	dict := fmt.Sprintf("%d:%s}", buf.Len(), buf.String())

	r := bufio.NewReader(strings.NewReader(dict))
	_, err := decodeTnetstringStream(r, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported dict key")
}

// TestTnetstring_DepthLimitRejected constructs deeply nested dicts beyond
// maxTnetstringDepth and confirms the decoder returns ErrTnetstringDepth
// instead of exhausting the goroutine stack. Regression for SEC-BE-002.
func TestTnetstring_DepthLimitRejected(t *testing.T) {
	// Build nested lists 2x deeper than the cap.
	nest := 2 * maxTnetstringDepth
	var v any = []any{}
	for i := 0; i < nest; i++ {
		v = []any{v}
	}
	encoded := encodeTnet(v)

	r := bufio.NewReader(bytes.NewReader(encoded))
	_, err := decodeTnetstringStream(r, 0)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTnetstringDepth)
}

// TestTnetstring_NestedLengthBoundedByRemaining crafts a container whose
// child element's length prefix claims more bytes than the container holds,
// and asserts the decoder rejects the nested element rather than allocating
// the full claimed size. Regression for SEC-BE-001.
func TestTnetstring_NestedLengthBoundedByRemaining(t *testing.T) {
	// Outer list of length 10 containing an element that claims 999 bytes.
	input := "10:999:xxxxx,]"
	r := bufio.NewReader(strings.NewReader(input))
	_, err := decodeTnetstringStream(r, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds remaining buffer")
}

// TestTnetstring_ListElementCountCap_BelowCapAccepted sanity-checks that a
// list with fewer than maxTnetstringElements entries decodes successfully.
// Paired with _AboveCapRejected so both sides of the boundary are pinned.
func TestTnetstring_ListElementCountCap_BelowCapAccepted(t *testing.T) {
	const n = 100
	var body bytes.Buffer
	for i := 0; i < n; i++ {
		body.WriteString("0:,")
	}
	listEncoded := encodeWithLen(body.Bytes(), ']')

	r := bufio.NewReader(bytes.NewReader(listEncoded))
	got, err := decodeTnetstringStream(r, 0)
	require.NoError(t, err)
	require.Len(t, got.([]any), n)
}

// TestTnetstring_ListElementCountCap_AboveCapRejected exercises the cap-
// rejection code path by temporarily lowering maxTnetstringElements. Without
// this, deleting the cap from production would not fail any test.
//
// Regression test for round-2 TEST-R2-001: the original ListElementCountCap
// test claimed to cover cap rejection but its body only exercised the
// below-cap path, giving false confidence.
func TestTnetstring_ListElementCountCap_AboveCapRejected(t *testing.T) {
	const lowered = 10
	withTempCap(t, &maxTnetstringElements, lowered)

	// Emit enough elements to decisively cross the lowered cap.
	const elementCount = lowered + 5
	var body bytes.Buffer
	for i := 0; i < elementCount; i++ {
		body.WriteString("0:,") // minimal empty-bytes element, 3 bytes each
	}
	listEncoded := encodeWithLen(body.Bytes(), ']')

	r := bufio.NewReader(bytes.NewReader(listEncoded))
	_, err := decodeTnetstringStream(r, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list exceeds")
}

// TestTnetstring_DictElementCountCap_AboveCapRejected mirrors the list test
// for the dict path, which has its own check at a different line.
func TestTnetstring_DictElementCountCap_AboveCapRejected(t *testing.T) {
	const lowered = 3
	withTempCap(t, &maxTnetstringElements, lowered)

	// lowered+2 key/value pairs, decisively over the lowered cap.
	const pairCount = lowered + 2
	var body bytes.Buffer
	for i := 0; i < pairCount; i++ {
		fmt.Fprintf(&body, "1:%c,1:v,", 'a'+byte(i))
	}
	dictEncoded := encodeWithLen(body.Bytes(), '}')

	r := bufio.NewReader(bytes.NewReader(dictEncoded))
	_, err := decodeTnetstringStream(r, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dict exceeds")
}

// encodeWithLen is a tiny test helper for constructing raw container bytes
// without exercising the shared encoder (whose bug would otherwise be an
// oracle for the decoder).
func encodeWithLen(payload []byte, marker byte) []byte {
	prefix := fmt.Sprintf("%d:", len(payload))
	out := make([]byte, 0, len(prefix)+len(payload)+1)
	out = append(out, prefix...)
	out = append(out, payload...)
	out = append(out, marker)
	return out
}
