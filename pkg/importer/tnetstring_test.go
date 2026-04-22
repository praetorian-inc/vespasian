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
		// Explicit coverage: leading minus is structurally rejected by the
		// "non-digit prefix" case above, but pinning it separately ensures a
		// future refactor of the length-prefix reader that started tolerating
		// signed ints would surface here instead of passing silently.
		{"negative length", "-1:x,"},
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

// TestTnetstring_InvalidIntHugePayloadBounded is a regression test for the
// round-5 finding that the strconv.NumError wrapped into a %w error string
// re-embedded the full input payload, defeating payloadPreview. A 1 KB
// invalid-int payload must produce an error message bounded by the preview
// constant plus a small formatting overhead, not by the input size.
func TestTnetstring_InvalidIntHugePayloadBounded(t *testing.T) {
	const n = 1024
	payload := make([]byte, n)
	for i := range payload {
		payload[i] = 'a' // not a digit -> ParseInt fails
	}
	input := fmt.Sprintf("%d:%s#", n, payload)

	r := bufio.NewReader(strings.NewReader(input))
	_, err := decodeTnetstringStream(r, 0)
	require.Error(t, err)

	// Error message must embed the total length but NOT the full payload.
	msg := err.Error()
	assert.Contains(t, msg, "parse int")
	assert.Contains(t, msg, "bytes total")
	// Comfortable upper bound: preview (64) + format overhead (~80). A 1 KB
	// payload embed would blow past this.
	assert.Less(t, len(msg), 256,
		"error message not bounded by payloadPreview: got %d bytes", len(msg))
}

// TestTnetstring_DictHugeKeyErrorBounded verifies that a dict with a huge
// attacker-controlled key and no following value produces an error message
// bounded by payloadPreview rather than embedding the full key.
// Regression for round-5 SEC-BE-R5-002.
func TestTnetstring_DictHugeKeyErrorBounded(t *testing.T) {
	// Large bytes key followed by nothing → "dict key ... has no value".
	const keyLen = 4096
	key := make([]byte, keyLen)
	for i := range key {
		key[i] = 'k'
	}
	// Encode as a dict containing only the key element, with no value after.
	keyElement := fmt.Sprintf("%d:%s,", keyLen, key) // <len>:<payload>,
	dict := fmt.Sprintf("%d:%s}", len(keyElement), keyElement)

	r := bufio.NewReader(strings.NewReader(dict))
	_, err := decodeTnetstringStream(r, 0)
	require.Error(t, err)
	msg := err.Error()
	assert.Contains(t, msg, "has no value")
	assert.Contains(t, msg, "bytes total")
	assert.Less(t, len(msg), 256,
		"dict-key error not bounded: got %d bytes", len(msg))
}

// TestTnetstring_InvalidFloatHugePayloadBounded mirrors the int test for
// the float branch.
func TestTnetstring_InvalidFloatHugePayloadBounded(t *testing.T) {
	const n = 1024
	payload := make([]byte, n)
	for i := range payload {
		payload[i] = 'x' // not a float
	}
	input := fmt.Sprintf("%d:%s^", n, payload)

	r := bufio.NewReader(strings.NewReader(input))
	_, err := decodeTnetstringStream(r, 0)
	require.Error(t, err)
	msg := err.Error()
	assert.Contains(t, msg, "parse float")
	assert.Less(t, len(msg), 256)
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

// TestTnetstring_ElementAtCapAccepted and
// TestTnetstring_ElementAtCapPlusOneRejected together pin the exact per-
// element cap boundary. maxTnetstringElement is promoted to a var so
// withTempCap can lower it — without this, a refactor that flipped `>` to
// `>=` (or vice versa) in readLengthPrefix would silently pass because only
// the far-side rejection is currently exercised (by TestTnetstring_LengthTooLarge).
//
// Regression for review TEST-007.
func TestTnetstring_ElementAtCapAccepted(t *testing.T) {
	const lowered = 64
	withTempCap(t, &maxTnetstringElement, lowered)

	payload := strings.Repeat("x", lowered)
	input := fmt.Sprintf("%d:%s,", lowered, payload)
	r := bufio.NewReader(strings.NewReader(input))
	got, err := decodeTnetstringStream(r, 0)
	require.NoError(t, err)
	assert.Equal(t, []byte(payload), got)
}

func TestTnetstring_ElementAtCapPlusOneRejected(t *testing.T) {
	const lowered = 64
	withTempCap(t, &maxTnetstringElement, lowered)

	payload := strings.Repeat("x", lowered+1)
	input := fmt.Sprintf("%d:%s,", lowered+1, payload)
	r := bufio.NewReader(strings.NewReader(input))
	_, err := decodeTnetstringStream(r, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "per-element cap")
}

// TestTnetstring_DepthAtCapAccepted / _DepthAtCapPlusOneRejected pin the
// exact depth boundary. TestTnetstring_DepthLimitRejected already exercises
// depth=2*cap rejection; without these, a refactor flipping `>` to `>=` in
// decodeTnetstringStream/Inner would silently pass.
//
// Regression for review TEST-007.
func TestTnetstring_DepthAtCapAccepted(t *testing.T) {
	// The depth check is `depth > maxTnetstringDepth`, so depth=cap is
	// accepted and depth=cap+1 is rejected. The decoder starts at depth=0
	// and increments once per nested level, so a payload with physical
	// depth N reaches decoder depth N-1 at the innermost element. Therefore
	// to exercise decoder depth == maxTnetstringDepth we need a physical
	// depth of maxTnetstringDepth+1 — i.e. one innermost empty list wrapped
	// by maxTnetstringDepth outer lists.
	var v any = []any{}
	for i := 0; i < maxTnetstringDepth; i++ {
		v = []any{v}
	}
	encoded := encodeTnet(v)

	r := bufio.NewReader(bytes.NewReader(encoded))
	got, err := decodeTnetstringStream(r, 0)
	require.NoError(t, err, "decoder depth == maxTnetstringDepth must decode successfully")
	assert.NotNil(t, got)
}

func TestTnetstring_DepthAtCapPlusOneRejected(t *testing.T) {
	// One more wrapper than the at-cap test lifts decoder depth to
	// maxTnetstringDepth+1, which trips ErrTnetstringDepth.
	var v any = []any{}
	for i := 0; i < maxTnetstringDepth+1; i++ {
		v = []any{v}
	}
	encoded := encodeTnet(v)

	r := bufio.NewReader(bytes.NewReader(encoded))
	_, err := decodeTnetstringStream(r, 0)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTnetstringDepth)
}

// TestTnetstring_LengthPrefixAtDigitCap pins the exact digit-count boundary
// for the length prefix. maxLengthPrefixDigits=9 prevents strconv.Atoi
// overflow; the existing "prefix too long" case in TestTnetstring_InvalidInputs
// uses 11 digits, leaving a gap between 9 (accepted) and 10 (rejected).
//
// Regression for review TEST-006.
func TestTnetstring_LengthPrefixAtDigitCap(t *testing.T) {
	t.Run("9 digits accepted", func(t *testing.T) {
		// "000000000:<nothing>," = 9-digit length prefix of 0 followed by
		// empty-bytes payload. 9 digits is the inclusive cap.
		input := "000000000:,"
		r := bufio.NewReader(strings.NewReader(input))
		got, err := decodeTnetstringStream(r, 0)
		require.NoError(t, err)
		assert.Equal(t, []byte{}, got)
	})
	t.Run("10 digits rejected", func(t *testing.T) {
		// "0000000000:,": same semantics but one extra digit -> rejected
		// before even parsing the number.
		input := "0000000000:,"
		r := bufio.NewReader(strings.NewReader(input))
		_, err := decodeTnetstringStream(r, 0)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "length prefix exceeds")
	})
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
	listEncoded := buildElement(body.Bytes(), ']')

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
	listEncoded := buildElement(body.Bytes(), ']')

	r := bufio.NewReader(bytes.NewReader(listEncoded))
	_, err := decodeTnetstringStream(r, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list exceeds")
}

// TestTnetstring_DictElementCountCap_RepeatedKeysStillRejected verifies the
// cardinality cap counts pairs, not unique keys. An attacker who floods a
// dict payload with the SAME key would otherwise leave len(result) pinned at
// 1 while the loop consumes unbounded CPU parsing bogus pairs.
func TestTnetstring_DictElementCountCap_RepeatedKeysStillRejected(t *testing.T) {
	const lowered = 3
	withTempCap(t, &maxTnetstringElements, lowered)

	// Emit lowered+2 pairs all using the same key "a".
	const pairCount = lowered + 2
	var body bytes.Buffer
	for i := 0; i < pairCount; i++ {
		body.WriteString("1:a,1:v,")
	}
	dictEncoded := buildElement(body.Bytes(), '}')

	r := bufio.NewReader(bytes.NewReader(dictEncoded))
	_, err := decodeTnetstringStream(r, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dict exceeds")
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
	dictEncoded := buildElement(body.Bytes(), '}')

	r := bufio.NewReader(bytes.NewReader(dictEncoded))
	_, err := decodeTnetstringStream(r, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dict exceeds")
}
