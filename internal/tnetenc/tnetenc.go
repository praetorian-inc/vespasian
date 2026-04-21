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

// Package tnetenc is a minimal tnetstring encoder used only by tests and the
// fixture-generator utility. It mirrors the subset of the format that
// mitmproxy uses in HTTPFlow serialization so the importer's decoder can be
// round-trip tested and live-test fixtures can be regenerated from source.
//
// This is NOT a general-purpose tnetstring library. It lives under the
// module's internal/ tree so it is only available to vespasian packages
// (importer tests, the fixture generator under test/fixtures).
package tnetenc

import (
	"bytes"
	"fmt"
	"sort"
	"strconv"
)

// Encode serializes v using the tnetstring format.
//
// Supported types:
//   - nil              -> "0:~"
//   - []byte           -> "<len>:<data>,"        (binary payload, %-safe)
//   - string           -> "<len>:<data>,"        (encoded as bytes; mitmproxy
//     serializes all strings as bytes in flow state)
//   - bool             -> "4:true!" / "5:false!"
//   - int, int64       -> "<digits>:<int>#"
//   - float64          -> "<digits>:<float>^"
//   - []any            -> "<len>:<elements>]"    (sort-stable recursion)
//   - map[string]any   -> "<len>:<kv-pairs>}"    (keys sorted alphabetically
//     for deterministic golden-file output)
//
// Encoding is byte-safe for arbitrary []byte payloads including those that
// contain '%', NUL, or non-UTF8 bytes: the length-prefix/raw-payload format
// never interprets payload contents as formatting directives. This matters
// because earlier revisions used fmt.Sprintf("%d:%s,", len, x) on []byte,
// which broke silently for payloads containing '%'.
func Encode(v any) []byte {
	switch x := v.(type) {
	case nil:
		return []byte("0:~")
	case []byte:
		return encodeWithMarker(x, ',')
	case string:
		return encodeWithMarker([]byte(x), ',')
	case bool:
		if x {
			return []byte("4:true!")
		}
		return []byte("5:false!")
	case int:
		return encodeWithMarker([]byte(strconv.FormatInt(int64(x), 10)), '#')
	case int64:
		return encodeWithMarker([]byte(strconv.FormatInt(x, 10)), '#')
	case float64:
		return encodeWithMarker([]byte(strconv.FormatFloat(x, 'g', -1, 64)), '^')
	case []any:
		var buf bytes.Buffer
		for _, item := range x {
			buf.Write(Encode(item))
		}
		return encodeWithMarker(buf.Bytes(), ']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var buf bytes.Buffer
		for _, k := range keys {
			buf.Write(Encode([]byte(k)))
			buf.Write(Encode(x[k]))
		}
		return encodeWithMarker(buf.Bytes(), '}')
	default:
		panic(fmt.Sprintf("tnetenc: unsupported type %T", v))
	}
}

// encodeWithMarker builds "<len>:<payload><marker>" using byte concatenation
// rather than fmt.Sprintf so that payload bytes are never interpreted as
// format directives.
func encodeWithMarker(payload []byte, marker byte) []byte {
	lenStr := strconv.Itoa(len(payload))
	out := make([]byte, 0, len(lenStr)+1+len(payload)+1)
	out = append(out, lenStr...)
	out = append(out, ':')
	out = append(out, payload...)
	out = append(out, marker)
	return out
}
