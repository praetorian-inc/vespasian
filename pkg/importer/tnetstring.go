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
	"errors"
	"fmt"
	"io"
	"strconv"
)

// tnetstring implements the subset of the tnetstring serialization format
// used by mitmproxy to persist flow dumps.
//
// Format: <length>:<data><type>
//
// Type markers:
//
//	,  bytes
//	;  UTF-8 string
//	#  integer
//	^  float
//	!  boolean
//	~  null
//	]  list
//	}  dictionary
//
// Compound types (list, dictionary) contain nested tnetstring elements
// concatenated within the data section. Dictionaries store alternating
// key and value elements.
//
// Reference: https://tnetstrings.org/ and mitmproxy/io/tnetstring.py.

// Defense-in-depth limits. maxTnetstringElement caps any single element's
// payload size; it is deliberately much smaller than the stream-level
// maxImportSize cap so a malformed header with a huge length prefix cannot
// trigger a large allocation before io.ReadFull validates the bytes exist.
// maxTnetstringDepth bounds mutual recursion (dict→list→dict→...) to prevent
// stack exhaustion on crafted inputs. maxTnetstringElements caps how many
// items a single list or dict can hold, which bounds the pointer/interface
// overhead that compound types can amplify out of their payload byte count.
const (
	maxTnetstringElement  = 64 * 1024 * 1024 // 64 MB per-element allocation bound
	maxTnetstringDepth    = 64               // mitmproxy flow dicts nest ~4 levels in practice
	maxLengthPrefixDigits = 9                // digits(maxTnetstringElement) = 8; 9 leaves headroom
)

// maxTnetstringElements caps list/dict cardinality. Declared as a var (not a
// const) so tests can lower the cap and exercise the rejection path with a
// small crafted payload rather than allocating a million elements in-test.
// Production callers MUST treat this as read-only.
var maxTnetstringElements = 1 << 20 // 1M entries per list or dict

// ErrTnetstringDepth reports recursion beyond maxTnetstringDepth.
var ErrTnetstringDepth = errors.New("tnetstring: nesting depth exceeds limit")

// tnetType identifies a tnetstring element's data type via its trailing marker byte.
type tnetType byte

const (
	tnetBytes  tnetType = ','
	tnetString tnetType = ';'
	tnetInt    tnetType = '#'
	tnetFloat  tnetType = '^'
	tnetBool   tnetType = '!'
	tnetNull   tnetType = '~'
	tnetList   tnetType = ']'
	tnetDict   tnetType = '}'
)

// decodeTnetstringStream reads one tnetstring element from a streaming
// bufio.Reader (used at the top level of importNative). The element's length
// prefix is bounded only by the per-element cap, since the stream itself is
// already size-limited by importer-level limitedReader.
func decodeTnetstringStream(r *bufio.Reader, depth int) (any, error) {
	if depth > maxTnetstringDepth {
		return nil, ErrTnetstringDepth
	}

	length, err := readLengthPrefix(r, maxTnetstringElement)
	if err != nil {
		return nil, err
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("tnetstring: read payload (len=%d): %w", length, err)
	}

	typeByte, err := r.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("tnetstring: read type marker: %w", err)
	}

	return parseTnetPayload(tnetType(typeByte), payload, depth)
}

// decodeTnetstringInner reads one tnetstring element from a bounded
// bytes.Reader (used inside parseTnetList / parseTnetDict). The length prefix
// is additionally bounded by the remaining bytes in r, so a malformed element
// cannot claim more data than its enclosing container holds.
func decodeTnetstringInner(r *bytes.Reader, depth int) (any, error) {
	if depth > maxTnetstringDepth {
		return nil, ErrTnetstringDepth
	}

	length, err := readLengthPrefix(r, r.Len())
	if err != nil {
		return nil, err
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("tnetstring: read payload (len=%d): %w", length, err)
	}

	typeByte, err := r.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("tnetstring: read type marker: %w", err)
	}

	return parseTnetPayload(tnetType(typeByte), payload, depth)
}

// readLengthPrefix reads ASCII decimal digits terminated by ':' and validates
// the resulting length against two independent bounds:
//
//   - the global per-element ceiling (maxTnetstringElement), which prevents
//     a single allocation from consuming the whole import budget;
//   - a caller-supplied bound (maxLen), which for nested calls equals the
//     remaining bytes in the enclosing container — this stops a crafted
//     inner element from claiming more data than its parent holds.
//
// For the stream-level caller the two bounds coincide (`maxLen ==
// maxTnetstringElement`), making the second check redundant in that one
// code path; the duplication is intentional defense-in-depth.
func readLengthPrefix(r io.ByteReader, maxLen int) (int, error) {
	digits := make([]byte, 0, maxLengthPrefixDigits)
	for {
		b, err := r.ReadByte()
		if err != nil {
			return 0, fmt.Errorf("tnetstring: read length prefix: %w", err)
		}
		if b == ':' {
			break
		}
		if b < '0' || b > '9' {
			return 0, fmt.Errorf("tnetstring: invalid length prefix byte %q", b)
		}
		if len(digits) == maxLengthPrefixDigits {
			return 0, fmt.Errorf("tnetstring: length prefix exceeds %d digits", maxLengthPrefixDigits)
		}
		digits = append(digits, b)
	}
	if len(digits) == 0 {
		return 0, fmt.Errorf("tnetstring: empty length prefix")
	}
	length, err := strconv.Atoi(string(digits))
	if err != nil {
		return 0, fmt.Errorf("tnetstring: parse length %q: %w", digits, err)
	}
	if length < 0 || length > maxTnetstringElement {
		return 0, fmt.Errorf(
			"tnetstring: single element is %d bytes, exceeding the %d-byte per-element cap "+
				"(raise maxTnetstringElement if you are importing flows with response bodies larger than %d MB)",
			length, maxTnetstringElement, maxTnetstringElement/(1024*1024),
		)
	}
	if length > maxLen {
		return 0, fmt.Errorf("tnetstring: length %d exceeds remaining buffer %d", length, maxLen)
	}
	return length, nil
}

func parseTnetPayload(t tnetType, payload []byte, depth int) (any, error) {
	switch t {
	case tnetBytes:
		buf := make([]byte, len(payload))
		copy(buf, payload)
		return buf, nil
	case tnetString:
		return string(payload), nil
	case tnetInt:
		n, err := strconv.ParseInt(string(payload), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("tnetstring: parse int %s: %w", payloadPreview(payload), err)
		}
		return n, nil
	case tnetFloat:
		f, err := strconv.ParseFloat(string(payload), 64)
		if err != nil {
			return nil, fmt.Errorf("tnetstring: parse float %s: %w", payloadPreview(payload), err)
		}
		return f, nil
	case tnetBool:
		switch string(payload) {
		case "true":
			return true, nil
		case "false":
			return false, nil
		default:
			return nil, fmt.Errorf("tnetstring: invalid bool %s", payloadPreview(payload))
		}
	case tnetNull:
		if len(payload) != 0 {
			return nil, fmt.Errorf("tnetstring: null element has %d-byte payload", len(payload))
		}
		return nil, nil
	case tnetList:
		return parseTnetList(payload, depth+1)
	case tnetDict:
		return parseTnetDict(payload, depth+1)
	default:
		return nil, fmt.Errorf("tnetstring: unknown type marker %q", byte(t))
	}
}

func parseTnetList(payload []byte, depth int) ([]any, error) {
	var result []any
	r := bytes.NewReader(payload)
	for r.Len() > 0 {
		if len(result) >= maxTnetstringElements {
			return nil, fmt.Errorf("tnetstring: list exceeds %d elements", maxTnetstringElements)
		}
		val, err := decodeTnetstringInner(r, depth)
		if err != nil {
			return nil, fmt.Errorf("tnetstring: list element: %w", err)
		}
		result = append(result, val)
	}
	return result, nil
}

func parseTnetDict(payload []byte, depth int) (map[string]any, error) {
	result := map[string]any{}
	r := bytes.NewReader(payload)
	// pairsParsed counts every key/value pair parsed, not unique keys. This
	// bounds CPU even when an attacker floods the payload with repeated keys
	// (which would leave len(result) pinned at 1 and let the loop run free).
	var pairsParsed int
	for r.Len() > 0 {
		if pairsParsed >= maxTnetstringElements {
			return nil, fmt.Errorf("tnetstring: dict exceeds %d entries", maxTnetstringElements)
		}
		keyVal, err := decodeTnetstringInner(r, depth)
		if err != nil {
			return nil, fmt.Errorf("tnetstring: dict key: %w", err)
		}
		key, err := coerceDictKey(keyVal)
		if err != nil {
			return nil, err
		}
		if r.Len() == 0 {
			return nil, fmt.Errorf("tnetstring: dict key %q has no value", key)
		}
		valueVal, err := decodeTnetstringInner(r, depth)
		if err != nil {
			return nil, fmt.Errorf("tnetstring: dict value for key %q: %w", key, err)
		}
		result[key] = valueVal
		pairsParsed++
	}
	return result, nil
}

// coerceDictKey converts a decoded dict key (bytes or string) into a Go string.
// mitmproxy serializes keys as bytes with ASCII names; tolerate both forms.
func coerceDictKey(v any) (string, error) {
	switch k := v.(type) {
	case string:
		return k, nil
	case []byte:
		return string(k), nil
	default:
		return "", fmt.Errorf("tnetstring: unsupported dict key type %T", v)
	}
}

// maxPayloadPreview is the longest attacker-controlled byte slice we embed
// verbatim into an error string. Larger payloads are summarized as
// "<preview>... (N bytes total)" to keep log volume bounded.
const maxPayloadPreview = 64

// payloadPreview renders up to maxPayloadPreview bytes of payload for use in
// error messages. Longer payloads are truncated and annotated with the full
// length so operators still see the size without pasting 64 MB into the log.
func payloadPreview(payload []byte) string {
	if len(payload) <= maxPayloadPreview {
		return fmt.Sprintf("%q", payload)
	}
	return fmt.Sprintf("%q... (%d bytes total)", payload[:maxPayloadPreview], len(payload))
}
